// Copyright 2026 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package appsec

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/captcha"
)

const appSecTestClientIP = "192.0.2.20"

type appSecProviderTransport struct {
	base  http.RoundTripper
	calls atomic.Int64
}

func (t *appSecProviderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "challenges.cloudflare.com" {
		t.calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
			Request:    r,
		}, nil
	}

	return t.base.RoundTrip(r)
}

func TestAppSecCaptchaFlow(t *testing.T) {
	var action atomic.Value
	var appSecCalls atomic.Int64
	action.Store("captcha")
	appSecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		appSecCalls.Add(1)
		switch current := action.Load().(string); current {
		case "allow":
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"action":"`+current+`","http_status":403}`)
		}
	}))
	defer appSecServer.Close()

	cs, transport := newAppSecTestCrowdSec(t, appSecServer.URL)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	nextCalls := 0
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		nextCalls++
		_, err := io.WriteString(w, "upstream")
		return err
	})

	challengeRequest := appSecRequestWithClientIP(httptest.NewRequest(http.MethodGet, "http://example.com/protected?x=1", nil))
	challengeResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(challengeResponse, challengeRequest, next))
	assert.Equal(t, http.StatusOK, challengeResponse.Code)
	assert.Zero(t, nextCalls)
	assert.EqualValues(t, 1, appSecCalls.Load())
	pendingCookie := appSecCookieNamed(t, challengeResponse.Result(), captcha.CookieName)
	formAction := appSecChallengeFormAction(t, challengeResponse.Body.String())

	// Marked submissions are module-internal control requests. They must be
	// intercepted before AppSec sees their provider token and state cookie.
	action.Store("allow")
	submission := appSecRequestWithClientIP(httptest.NewRequest(
		http.MethodPost,
		"http://example.com"+formAction,
		strings.NewReader("cf-turnstile-response=valid-token"),
	))
	submission.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	submission.AddCookie(pendingCookie)
	solvedResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(solvedResponse, submission, next))
	assert.Equal(t, http.StatusSeeOther, solvedResponse.Code)
	assert.Equal(t, "/protected?x=1", solvedResponse.Header().Get("Location"))
	assert.Zero(t, nextCalls)
	assert.EqualValues(t, 1, transport.calls.Load())
	assert.EqualValues(t, 1, appSecCalls.Load())
	passedCookie := appSecCookieNamed(t, solvedResponse.Result(), captcha.CookieName)

	action.Store("captcha")
	bypassRequest := appSecRequestWithClientIP(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil))
	bypassRequest.AddCookie(passedCookie)
	bypassResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(bypassResponse, bypassRequest, next))
	assert.Equal(t, http.StatusOK, bypassResponse.Code)
	assert.Equal(t, "upstream", bypassResponse.Body.String())
	assert.Equal(t, 1, nextCalls)
	assert.EqualValues(t, 2, appSecCalls.Load())

	action.Store("ban")
	banRequest := appSecRequestWithClientIP(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil))
	banRequest.AddCookie(passedCookie)
	banResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(banResponse, banRequest, next))
	assert.Equal(t, http.StatusForbidden, banResponse.Code)
	assert.Equal(t, 1, nextCalls, "a solved CAPTCHA must never bypass an AppSec ban")
	assert.EqualValues(t, 3, appSecCalls.Load())
}

func TestAppSecCaptchaUnsafeMethodFallsBackToBan(t *testing.T) {
	var appSecCalls atomic.Int64
	appSecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		appSecCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"action":"captcha","http_status":403}`)
	}))
	defer appSecServer.Close()

	cs, transport := newAppSecTestCrowdSec(t, appSecServer.URL)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	nextCalls := 0
	r := appSecRequestWithClientIP(httptest.NewRequest(http.MethodPut, "http://example.com/protected", strings.NewReader("sensitive=body")))
	w := httptest.NewRecorder()

	require.NoError(t, handler.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalls++
		return nil
	})))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "cf-turnstile")
	assert.EqualValues(t, 1, appSecCalls.Load())
	assert.Zero(t, transport.calls.Load())
	assert.Zero(t, nextCalls)
}

func newAppSecTestCrowdSec(t *testing.T, appSecURL string) (*crowdsec.CrowdSec, *appSecProviderTransport) {
	t.Helper()
	cs := &crowdsec.CrowdSec{
		APIUrl:            appSecURL,
		APIKey:            "test-key",
		AppSecUrl:         appSecURL,
		CaptchaProvider:   "turnstile",
		CaptchaSiteKey:    "site-key",
		CaptchaSecretKey:  "provider-secret",
		CaptchaSigningKey: "01234567890123456789012345678901",
	}

	baseTransport := http.DefaultTransport
	transport := &appSecProviderTransport{base: baseTransport}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = baseTransport }()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	require.NoError(t, cs.Provision(ctx))
	return cs, transport
}

func appSecRequestWithClientIP(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, appSecTestClientIP)
	return r.WithContext(ctx)
}

func appSecCookieNamed(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}

func appSecChallengeFormAction(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(body)
	require.Len(t, match, 2)
	return html.UnescapeString(match[1])
}
