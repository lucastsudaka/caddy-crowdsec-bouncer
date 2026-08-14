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

package http

import (
	"context"
	"fmt"
	"html"
	"io"
	nethttp "net/http"
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

const testClientIP = "192.0.2.10"

type providerTransport struct {
	base  nethttp.RoundTripper
	calls atomic.Int64
}

func (t *providerTransport) RoundTrip(r *nethttp.Request) (*nethttp.Response, error) {
	if r.URL.Host == "challenges.cloudflare.com" {
		t.calls.Add(1)
		return &nethttp.Response{
			StatusCode: nethttp.StatusOK,
			Status:     "200 OK",
			Header:     make(nethttp.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
			Request:    r,
		}, nil
	}

	return t.base.RoundTrip(r)
}

func TestHandlerCaptchaFlow(t *testing.T) {
	var decisionType atomic.Value
	decisionType.Store("captcha")
	lapi := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))
		assert.Equal(t, testClientIP, r.URL.Query().Get("ip"))
		if typ := decisionType.Load().(string); typ != "" {
			_, _ = fmt.Fprintf(w, `[{"duration":"1h","id":1,"origin":"cscli","scenario":"test","scope":"Ip","type":%q,"value":%q}]`, typ, testClientIP)
			return
		}
		_, _ = io.WriteString(w, "null")
	}))
	defer lapi.Close()

	cs, transport := newHandlerTestCrowdSec(t, lapi.URL, true)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	nextCalls := 0
	next := caddyhttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) error {
		nextCalls++
		_, err := io.WriteString(w, "upstream")
		return err
	})

	challengeRequest := requestWithClientIP(httptest.NewRequest(nethttp.MethodGet, "http://example.com/protected?x=1", nil))
	challengeResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(challengeResponse, challengeRequest, next))
	assert.Equal(t, nethttp.StatusOK, challengeResponse.Code)
	assert.Contains(t, challengeResponse.Body.String(), "cf-turnstile")
	assert.Zero(t, nextCalls)
	pendingCookie := cookieNamed(t, challengeResponse.Result(), captcha.CookieName)
	formAction := challengeFormAction(t, challengeResponse.Body.String())

	submission := requestWithClientIP(httptest.NewRequest(
		nethttp.MethodPost,
		"http://example.com"+formAction,
		strings.NewReader("cf-turnstile-response=valid-token"),
	))
	submission.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	submission.AddCookie(pendingCookie)
	solvedResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(solvedResponse, submission, next))
	assert.Equal(t, nethttp.StatusSeeOther, solvedResponse.Code)
	assert.Equal(t, "/protected?x=1", solvedResponse.Header().Get("Location"))
	assert.Zero(t, nextCalls)
	assert.EqualValues(t, 1, transport.calls.Load())
	passedCookie := cookieNamed(t, solvedResponse.Result(), captcha.CookieName)

	bypassRequest := requestWithClientIP(httptest.NewRequest(nethttp.MethodGet, "http://example.com/protected?x=1", nil))
	bypassRequest.AddCookie(passedCookie)
	bypassResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(bypassResponse, bypassRequest, next))
	assert.Equal(t, nethttp.StatusOK, bypassResponse.Code)
	assert.Equal(t, "upstream", bypassResponse.Body.String())
	assert.Equal(t, 1, nextCalls)

	decisionType.Store("ban")
	banRequest := requestWithClientIP(httptest.NewRequest(nethttp.MethodGet, "http://example.com/protected", nil))
	banRequest.AddCookie(passedCookie)
	banResponse := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(banResponse, banRequest, next))
	assert.Equal(t, nethttp.StatusForbidden, banResponse.Code)
	assert.Equal(t, 1, nextCalls, "a solved CAPTCHA must never bypass a ban")
}

func TestHandlerRejectsUnsolicitedCaptchaSubmission(t *testing.T) {
	lapi := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = io.WriteString(w, "null")
	}))
	defer lapi.Close()

	cs, transport := newHandlerTestCrowdSec(t, lapi.URL, true)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	nextCalls := 0
	next := caddyhttp.HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error {
		nextCalls++
		return nil
	})

	r := requestWithClientIP(httptest.NewRequest(
		nethttp.MethodPost,
		"http://example.com/protected?__crowdsec_captcha=verify",
		strings.NewReader("cf-turnstile-response=valid-token"),
	))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	require.NoError(t, handler.ServeHTTP(w, r, next))
	assert.Equal(t, nethttp.StatusForbidden, w.Code)
	assert.Zero(t, nextCalls)
	assert.Zero(t, transport.calls.Load())
}

func TestHandlerCaptchaUnsafeMethodFallsBackToBan(t *testing.T) {
	lapi := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = fmt.Fprintf(w, `[{"duration":"1h","id":1,"origin":"cscli","scenario":"test","scope":"Ip","type":"captcha","value":%q}]`, testClientIP)
	}))
	defer lapi.Close()

	cs, transport := newHandlerTestCrowdSec(t, lapi.URL, true)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	nextCalls := 0
	next := caddyhttp.HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error {
		nextCalls++
		return nil
	})
	r := requestWithClientIP(httptest.NewRequest(nethttp.MethodPost, "http://example.com/protected", strings.NewReader("sensitive=body")))
	w := httptest.NewRecorder()

	require.NoError(t, handler.ServeHTTP(w, r, next))
	assert.Equal(t, nethttp.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "cf-turnstile")
	assert.Zero(t, nextCalls)
	assert.Zero(t, transport.calls.Load())
}

func TestHandlerDisabledCaptchaDoesNotReserveSubmissionMarker(t *testing.T) {
	lapi := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = io.WriteString(w, "null")
	}))
	defer lapi.Close()

	cs, _ := newHandlerTestCrowdSec(t, lapi.URL, false)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	nextCalls := 0
	next := caddyhttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) error {
		nextCalls++
		w.WriteHeader(nethttp.StatusNoContent)
		return nil
	})
	r := requestWithClientIP(httptest.NewRequest(
		nethttp.MethodPost,
		"http://example.com/protected?__crowdsec_captcha=verify",
		strings.NewReader("application=data"),
	))
	w := httptest.NewRecorder()

	require.NoError(t, handler.ServeHTTP(w, r, next))
	assert.Equal(t, nethttp.StatusNoContent, w.Code)
	assert.Equal(t, 1, nextCalls)
}

func TestHandlerCaptchaWithoutConfigurationFallsBackToBan(t *testing.T) {
	lapi := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = fmt.Fprintf(w, `[{"duration":"1h","id":1,"origin":"cscli","scenario":"test","scope":"Ip","type":"captcha","value":%q}]`, testClientIP)
	}))
	defer lapi.Close()

	cs, _ := newHandlerTestCrowdSec(t, lapi.URL, false)
	handler := &Handler{crowdsec: cs, logger: zaptest.NewLogger(t)}
	w := httptest.NewRecorder()
	r := requestWithClientIP(httptest.NewRequest(nethttp.MethodGet, "http://example.com/protected", nil))
	require.NoError(t, handler.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(nethttp.ResponseWriter, *nethttp.Request) error {
		t.Fatal("fallback must not call the next handler")
		return nil
	})))
	assert.Equal(t, nethttp.StatusForbidden, w.Code)
}

func newHandlerTestCrowdSec(t *testing.T, apiURL string, configureCaptcha bool) (*crowdsec.CrowdSec, *providerTransport) {
	t.Helper()
	streaming := false
	cs := &crowdsec.CrowdSec{
		APIUrl:          apiURL,
		APIKey:          "test-key",
		EnableStreaming: &streaming,
	}
	if configureCaptcha {
		cs.CaptchaProvider = "turnstile"
		cs.CaptchaSiteKey = "site-key"
		cs.CaptchaSecretKey = "provider-secret"
		cs.CaptchaSigningKey = "01234567890123456789012345678901"
	}

	baseTransport := nethttp.DefaultTransport
	transport := &providerTransport{base: baseTransport}
	nethttp.DefaultTransport = transport
	defer func() { nethttp.DefaultTransport = baseTransport }()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	require.NoError(t, cs.Provision(ctx))
	require.NoError(t, cs.Validate())
	return cs, transport
}

func requestWithClientIP(r *nethttp.Request) *nethttp.Request {
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, testClientIP)
	return r.WithContext(ctx)
}

func cookieNamed(t *testing.T, response *nethttp.Response, name string) *nethttp.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}

func challengeFormAction(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(body)
	require.Len(t, match, 2)
	return html.UnescapeString(match[1])
}
