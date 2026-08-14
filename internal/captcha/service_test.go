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

package captcha

import (
	"context"
	"crypto/tls"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testNow = time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC) //nolint:gochecknoglobals // immutable test fixture

type fakeClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type trackingResponseWriter struct {
	header http.Header
	wrote  bool
}

func (writer *trackingResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *trackingResponseWriter) Write(body []byte) (int, error) {
	writer.wrote = true
	return len(body), nil
}

func (writer *trackingResponseWriter) WriteHeader(int) { writer.wrote = true }

func newTestService(t *testing.T, provider Provider, clock Clock, options ...Option) *Service {
	t.Helper()
	options = append([]Option{WithClock(clock)}, options...)
	service, err := New(validConfig(provider), options...)
	require.NoError(t, err)
	return service
}

func requestInfo() RequestInfo {
	return RequestInfo{
		ClientIP: netip.MustParseAddr("192.0.2.42"),
		Binding:  "http:example.com:192.0.2.42",
	}
}

func challenge(t *testing.T, service *Service, rawURL string, secure bool) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, rawURL, nil)
	if secure {
		request.TLS = &tls.ConnectionState{}
	}
	recorder := httptest.NewRecorder()
	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	require.Equal(t, OutcomeChallenge, outcome)
	require.Equal(t, http.StatusOK, recorder.Code)
	cookies := recorder.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func submitRequest(t *testing.T, rawURL, responseField, token string, cookie *http.Cookie) *http.Request {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	action, ok := submissionURI(parsed.RequestURI())
	require.True(t, ok)
	parsed.RawPath = ""
	parsed.Path = action
	parsed.RawQuery = ""
	if actionURL, parseErr := url.ParseRequestURI(action); parseErr == nil {
		parsed.Path = actionURL.Path
		parsed.RawPath = actionURL.RawPath
		parsed.RawQuery = actionURL.RawQuery
	}
	form := make(url.Values, 1)
	form.Set(responseField, token)
	request := httptest.NewRequest(http.MethodPost, parsed.String(), strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	return request
}

func TestServiceDisabled(t *testing.T) {
	t.Parallel()

	service, err := New(Config{})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeUnavailable, outcome)
	assert.Empty(t, recorder.Header())
	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestChallengeResponse(t *testing.T) {
	t.Parallel()

	for _, provider := range []Provider{ProviderReCAPTCHA, ProviderHCaptcha, ProviderTurnstile} {
		provider := provider
		t.Run(string(provider), func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: testNow}
			service := newTestService(t, provider, clock)
			request := httptest.NewRequest(http.MethodGet, "https://EXAMPLE.com:8443/private?a=b", nil)
			request.TLS = &tls.ConnectionState{}
			recorder := httptest.NewRecorder()

			outcome, err := service.Handle(recorder, request, requestInfo())
			require.NoError(t, err)
			assert.Equal(t, OutcomeChallenge, outcome)
			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, "text/html; charset=utf-8", recorder.Header().Get("Content-Type"))
			assert.Equal(t, "no-store, private", recorder.Header().Get("Cache-Control"))
			assert.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", recorder.Header().Get("X-Frame-Options"))
			body := recorder.Body.String()
			csp := recorder.Header().Get("Content-Security-Policy")
			nonce := htmlAttribute(t, body, "nonce")
			assert.Contains(t, csp, "'nonce-"+nonce+"'")
			assert.Equal(t, 2, strings.Count(body, `nonce="`))
			assert.Contains(t, body, `data-callback="crowdsecCaptchaSolved"`)
			assert.Contains(t, body, "JavaScript is required")
			assert.NotContains(t, body, `<button`)
			assert.Contains(t, recorder.Body.String(), string(provider))
			assert.Contains(t, recorder.Body.String(), testSiteKey)
			assert.NotContains(t, recorder.Body.String(), testSecretKey)
			assert.NotContains(t, recorder.Body.String(), testSigningKey)
			assert.Contains(t, recorder.Body.String(), "__crowdsec_captcha=verify")
			if provider == ProviderTurnstile {
				assert.Contains(t, recorder.Body.String(), `data-action="crowdsec"`)
			}
			if provider == ProviderHCaptcha {
				assert.Contains(t, csp, "https://hcaptcha.com")
				assert.Contains(t, csp, "style-src 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com")
			}

			cookies := recorder.Result().Cookies()
			require.Len(t, cookies, 1)
			cookie := cookies[0]
			assert.Equal(t, CookieName, cookie.Name)
			assert.Empty(t, cookie.Domain)
			assert.Equal(t, "/", cookie.Path)
			assert.True(t, cookie.HttpOnly)
			assert.True(t, cookie.Secure)
			assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
			assert.Equal(t, testNow.Add(defaultPendingExpiration), cookie.Expires)
		})
	}
}

func htmlAttribute(t *testing.T, body, name string) string {
	t.Helper()
	marker := name + `="`
	_, value, found := strings.Cut(body, marker)
	require.True(t, found)
	value, _, found = strings.Cut(value, `"`)
	require.True(t, found)
	require.NotEmpty(t, value)
	return html.UnescapeString(value)
}

func TestChallengeNonceFailureFallsBackBeforeWriting(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		generator func() (string, error)
	}{
		{
			name: "entropy failure",
			generator: func() (string, error) {
				return "", errors.New("entropy unavailable")
			},
		},
		{
			name: "invalid nonce",
			generator: func() (string, error) {
				return "invalid nonce; script-src *", nil
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newTestService(
				t,
				ProviderTurnstile,
				&fakeClock{now: testNow},
				withNonceGenerator(test.generator),
			)
			writer := &trackingResponseWriter{}
			request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)

			outcome, err := service.Handle(writer, request, requestInfo())
			require.ErrorIs(t, err, ErrRenderChallenge)
			assert.Equal(t, OutcomeFallback, outcome)
			assert.False(t, writer.wrote)
			assert.Empty(t, writer.Header())
		})
	}
}

func TestManualTemplate(t *testing.T) {
	t.Parallel()

	config := validConfig(ProviderTurnstile)
	config.TemplatePath = filepath.Join("..", "..", "examples", "captcha-templates", "manual.html")
	service, err := New(
		config,
		WithClock(ClockFunc(func() time.Time { return testNow })),
		withNonceGenerator(func() (string, error) { return "MDEyMzQ1Njc4OWFiY2RlZg", nil }),
	)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
	assert.Contains(t, recorder.Body.String(), `<button type="submit">Continue</button>`)
	assert.NotContains(t, recorder.Body.String(), `data-callback=`)
	assert.Contains(t, recorder.Body.String(), `nonce="MDEyMzQ1Njc4OWFiY2RlZg"`)
	assert.Contains(t, recorder.Header().Get("Content-Security-Policy"), "'nonce-MDEyMzQ1Njc4OWFiY2RlZg'")
}

func TestHeadChallengeDoesNotWriteBody(t *testing.T) {
	t.Parallel()

	service := newTestService(t, ProviderTurnstile, &fakeClock{now: testNow})
	request := httptest.NewRequest(http.MethodHead, "https://example.com/private", nil)
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
	assert.NotEmpty(t, recorder.Header().Get("Set-Cookie"))
}

func TestUnsafeOriginalMethodFallsBackWithoutConsumingBody(t *testing.T) {
	t.Parallel()

	service := newTestService(t, ProviderTurnstile, &fakeClock{now: testNow})
	request := httptest.NewRequest(http.MethodPost, "https://example.com/private", strings.NewReader("application-body"))
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.ErrorIs(t, err, ErrUnsupportedMethod)
	assert.Equal(t, OutcomeFallback, outcome)
	remaining, err := io.ReadAll(request.Body)
	require.NoError(t, err)
	assert.Equal(t, "application-body", string(remaining))
	assert.Empty(t, recorder.Header())
	assert.Empty(t, recorder.Body.String())
}

func TestCustomTemplateEscapesValues(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/captcha.html"
	require.NoError(t, writeTestFile(path, []byte(`{{.Provider}}|{{.SiteKey}}|{{.FormAction}}|{{.WidgetClass}}|{{.ScriptURL}}|{{.Failed}}`)))
	config := validConfig(ProviderTurnstile)
	config.TemplatePath = path
	config.SiteKey = `<img src=x onerror=alert(1)>`
	service, err := New(config, WithClock(ClockFunc(func() time.Time { return testNow })))
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
	assert.NotContains(t, recorder.Body.String(), `<img`)
	assert.Contains(t, recorder.Body.String(), `&lt;img`)
}

func TestRenderedTemplateSizeIsBounded(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/captcha.html"
	source := strings.Repeat("{{.SiteKey}}", maximumRenderedHTMLBytes/maximumSiteKeyBytes+1)
	require.NoError(t, writeTestFile(path, []byte(source)))
	config := validConfig(ProviderTurnstile)
	config.TemplatePath = path
	config.SiteKey = strings.Repeat("s", maximumSiteKeyBytes)
	service, err := New(config, WithClock(ClockFunc(func() time.Time { return testNow })))
	require.NoError(t, err)
	w := &trackingResponseWriter{}
	request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)

	outcome, err := service.Handle(w, request, requestInfo())
	require.ErrorIs(t, err, ErrRenderChallenge)
	assert.Equal(t, OutcomeFallback, outcome)
	assert.False(t, w.wrote)
	assert.Empty(t, w.Header())
}

func TestSuccessfulSubmissionAndBypass(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	var capturedValues url.Values
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		capturedValues, err = url.ParseQuery(string(body))
		require.NoError(t, err)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
			Request:    request,
		}, nil
	})
	service := newTestService(t, ProviderHCaptcha, clock, WithRoundTripper(transport))
	const originalURI = "https://example.com/private?b=2&a=%2F+%20&b=1"
	pendingCookie := challenge(t, service, originalURI, true)
	request := submitRequest(t, originalURI, "h-captcha-response", "browser-token", pendingCookie)
	request.TLS = &tls.ConnectionState{}
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeSolved, outcome)
	assert.Equal(t, http.StatusSeeOther, recorder.Code)
	assert.Equal(t, "/private?b=2&a=%2F+%20&b=1", recorder.Header().Get("Location"))
	assert.Equal(t, testSecretKey, capturedValues.Get("secret"))
	assert.Equal(t, "browser-token", capturedValues.Get("response"))
	assert.Equal(t, requestInfo().ClientIP.String(), capturedValues.Get("remoteip"))
	assert.Equal(t, testSiteKey, capturedValues.Get("sitekey"))
	assert.NotContains(t, recorder.Body.String(), "browser-token")
	passedCookies := recorder.Result().Cookies()
	require.Len(t, passedCookies, 1)
	assert.Equal(t, testNow.Add(DefaultPassedExpiration), passedCookies[0].Expires)

	normalRequest := httptest.NewRequest(http.MethodGet, originalURI, nil)
	normalRequest.AddCookie(passedCookies[0])
	normalRecorder := httptest.NewRecorder()
	outcome, err = service.Handle(normalRecorder, normalRequest, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeBypass, outcome)
	assert.Equal(t, http.StatusOK, normalRecorder.Code)
	assert.Empty(t, normalRecorder.Header())
}

func TestProviderForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		provider      Provider
		responseField string
		wantSiteKey   bool
	}{
		{provider: ProviderReCAPTCHA, responseField: "g-recaptcha-response"},
		{provider: ProviderHCaptcha, responseField: "h-captcha-response", wantSiteKey: true},
		{provider: ProviderTurnstile, responseField: "cf-turnstile-response"},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.provider), func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: testNow}
			called := false
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				called = true
				assert.Equal(t, providerSpecs[test.provider].endpoint, request.URL.String())
				assert.Equal(t, http.MethodPost, request.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", request.Header.Get("Content-Type"))
				body, err := io.ReadAll(request.Body)
				require.NoError(t, err)
				values, err := url.ParseQuery(string(body))
				require.NoError(t, err)
				assert.Equal(t, testSecretKey, values.Get("secret"))
				assert.Equal(t, "proof", values.Get("response"))
				assert.Equal(t, "192.0.2.42", values.Get("remoteip"))
				if test.wantSiteKey {
					assert.Equal(t, testSiteKey, values.Get("sitekey"))
				} else {
					assert.NotContains(t, values, "sitekey")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
					Request:    request,
				}, nil
			})
			service := newTestService(t, test.provider, clock, WithRoundTripper(transport))
			pendingCookie := challenge(t, service, "https://example.com/private", false)
			request := submitRequest(t, "https://example.com/private", test.responseField, "proof", pendingCookie)
			recorder := httptest.NewRecorder()

			outcome, err := service.Handle(recorder, request, requestInfo())
			require.NoError(t, err)
			assert.Equal(t, OutcomeSolved, outcome)
			assert.True(t, called)
		})
	}
}

func TestProviderHostnamePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		provider    Provider
		hostname    *string
		wantOutcome Outcome
		wantErr     error
	}{
		{name: "recaptcha matching", provider: ProviderReCAPTCHA, hostname: stringPointer("EXAMPLE.com."), wantOutcome: OutcomeSolved},
		{name: "recaptcha missing", provider: ProviderReCAPTCHA, wantOutcome: OutcomeFallback, wantErr: ErrProviderUnavailable},
		{name: "recaptcha mismatched", provider: ProviderReCAPTCHA, hostname: stringPointer("other.example"), wantOutcome: OutcomeChallenge},
		{name: "turnstile matching", provider: ProviderTurnstile, hostname: stringPointer("example.com"), wantOutcome: OutcomeSolved},
		{name: "turnstile missing", provider: ProviderTurnstile, wantOutcome: OutcomeFallback, wantErr: ErrProviderUnavailable},
		{name: "turnstile mismatched", provider: ProviderTurnstile, hostname: stringPointer("other.example"), wantOutcome: OutcomeChallenge},
		{name: "hcaptcha missing", provider: ProviderHCaptcha, wantOutcome: OutcomeSolved},
		{name: "hcaptcha not provided", provider: ProviderHCaptcha, hostname: stringPointer("not-provided"), wantOutcome: OutcomeSolved},
		{name: "hcaptcha different browser hostname", provider: ProviderHCaptcha, hostname: stringPointer("other.example"), wantOutcome: OutcomeSolved},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: testNow}
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body := `{"success":true}`
				if test.hostname != nil {
					body = `{"success":true,"hostname":"` + *test.hostname + `","action":"crowdsec"}`
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    request,
				}, nil
			})
			service := newTestService(t, test.provider, clock, WithRoundTripper(transport))
			pendingCookie := challenge(t, service, "https://example.com/private", false)
			request := submitRequest(t, "https://example.com/private", providerSpecs[test.provider].responseField, "proof", pendingCookie)
			recorder := httptest.NewRecorder()

			outcome, err := service.Handle(recorder, request, requestInfo())
			assert.Equal(t, test.wantOutcome, outcome)
			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, test.wantErr)
			}
		})
	}
}

func stringPointer(value string) *string { return &value }

func TestPackagePrivateVerificationEndpointInjection(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/verify", request.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"hostname":"example.com","action":"crowdsec"}`)
	}))
	t.Cleanup(server.Close)
	service := newTestService(t, ProviderTurnstile, clock, withVerificationEndpoint(server.URL+"/verify"))
	pendingCookie := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeSolved, outcome)
}

func TestRejectedProofReChallenges(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":false,"error-codes":["invalid-input-response"]}`)),
			Request:    request,
		}, nil
	})
	service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
	pendingCookie := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "bad-proof", pendingCookie)
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "not accepted")
	assert.NotContains(t, recorder.Body.String(), `<button`)
	assert.Contains(t, recorder.Body.String(), `data-callback="crowdsecCaptchaSolved"`)
	assert.Equal(t, 2, strings.Count(recorder.Body.String(), `nonce="`))
	assert.NotContains(t, recorder.Body.String(), "bad-proof")
}

func TestProviderFailureCodesFailClosed(t *testing.T) {
	t.Parallel()

	for _, code := range []string{"invalid-input-secret", "bad-request", "internal-error", "sitekey-secret-mismatch", "future-provider-error"} {
		code := code
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"success":false,"error-codes":["` + code + `"]}`)),
					Request:    request,
				}, nil
			})
			service := newTestService(t, ProviderTurnstile, &fakeClock{now: testNow}, WithRoundTripper(transport))
			pending := challenge(t, service, "https://example.com/private", false)
			request := submitRequest(t, "https://example.com/private", service.spec.responseField, "proof", pending)
			outcome, err := service.Handle(httptest.NewRecorder(), request, requestInfo())
			assert.Equal(t, OutcomeFallback, outcome)
			assert.ErrorIs(t, err, ErrProviderUnavailable)
		})
	}
}

func TestTurnstileActionMustMatch(t *testing.T) {
	t.Parallel()

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"other"}`)),
			Request:    request,
		}, nil
	})
	service := newTestService(t, ProviderTurnstile, &fakeClock{now: testNow}, WithRoundTripper(transport))
	pending := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", service.spec.responseField, "proof", pending)
	recorder := httptest.NewRecorder()
	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
}

func TestTurnstileTokenLengthIsBounded(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not be called")
	})
	service := newTestService(t, ProviderTurnstile, &fakeClock{now: testNow}, WithRoundTripper(transport))
	pending := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", service.spec.responseField, strings.Repeat("x", 2049), pending)
	outcome, err := service.Handle(httptest.NewRecorder(), request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
	assert.Zero(t, calls.Load())
}

func TestInvalidSubmissionEnvelopeFallsBackWithoutWritingOrVerifying(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("provider should not be called")
		return nil, nil
	})
	service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
	pendingCookie := challenge(t, service, "https://example.com/private?a=b", false)

	tests := []struct {
		name    string
		request func() *http.Request
	}{
		{
			name: "wrong method",
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodGet, "https://example.com/private?__crowdsec_captcha=verify", nil)
				request.AddCookie(pendingCookie)
				return request
			},
		},
		{
			name: "wrong marker",
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodPost, "https://example.com/private?__crowdsec_captcha=nope", nil)
				request.AddCookie(pendingCookie)
				return request
			},
		},
		{
			name: "unsolicited submission without pending cookie",
			request: func() *http.Request {
				return submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &trackingResponseWriter{}
			outcome, err := service.Handle(writer, test.request(), requestInfo())
			assert.Equal(t, OutcomeFallback, outcome)
			assert.ErrorIs(t, err, ErrInvalidSubmission)
			assert.False(t, writer.wrote)
			assert.Empty(t, writer.Header())
		})
	}
}

func TestInvalidProofReChallengesWithoutProviderCall(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("provider should not be called")
		return nil, nil
	})
	service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
	pendingCookie := challenge(t, service, "https://example.com/private?a=b", false)

	tests := []struct {
		name    string
		request func() *http.Request
	}{
		{
			name: "wrong content type",
			request: func() *http.Request {
				request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
				request.Header.Set("Content-Type", "application/json")
				return request
			},
		},
		{
			name: "missing token",
			request: func() *http.Request {
				return submitRequest(t, "https://example.com/private", "wrong-response-field", "proof", pendingCookie)
			},
		},
		{
			name: "oversized body",
			request: func() *http.Request {
				body := strings.NewReader(strings.Repeat("x", maximumSubmissionBytes+1))
				request := httptest.NewRequest(http.MethodPost, "https://example.com/private?__crowdsec_captcha=verify", body)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(pendingCookie)
				return request
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			outcome, err := service.Handle(recorder, test.request(), requestInfo())
			require.NoError(t, err)
			assert.Equal(t, OutcomeChallenge, outcome)
			assert.Equal(t, http.StatusOK, recorder.Code)
		})
	}
}

func TestVerificationUnavailableFallsBackWithoutWriting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport roundTripFunc
	}{
		{
			name: "transport error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("browser-token provider-secret")
			},
		},
		{
			name: "nil response",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, nil
			},
		},
		{
			name: "nil response body",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Request: request}, nil
			},
		},
		{
			name: "non 2xx",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("secret")), Request: request}, nil
			},
		},
		{
			name: "malformed JSON",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("not-json")), Request: request}, nil
			},
		},
		{
			name: "missing success",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
			},
		},
		{
			name: "missing hostname",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":true}`)), Request: request}, nil
			},
		},
		{
			name: "empty hostname",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":true,"hostname":""}`)), Request: request}, nil
			},
		},
		{
			name: "oversized response",
			transport: func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maximumVerificationResponseBytes+1))),
					Request:    request,
				}, nil
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: testNow}
			service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(test.transport))
			pendingCookie := challenge(t, service, "https://example.com/private", false)
			request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "browser-token", pendingCookie)
			recorder := httptest.NewRecorder()

			outcome, err := service.Handle(recorder, request, requestInfo())
			assert.Equal(t, OutcomeFallback, outcome)
			assert.ErrorIs(t, err, ErrProviderUnavailable)
			assert.NotContains(t, err.Error(), "browser-token")
			assert.NotContains(t, err.Error(), testSecretKey)
			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Empty(t, recorder.Header())
			assert.Empty(t, recorder.Body.String())
		})
	}
}

func TestHostnameVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		hostname    string
		wantOutcome Outcome
		wantErr     error
	}{
		{name: "canonical match", hostname: "EXAMPLE.com.", wantOutcome: OutcomeSolved},
		{name: "mismatch", hostname: "other.example", wantOutcome: OutcomeChallenge},
		{name: "malformed", hostname: "https://example.com", wantOutcome: OutcomeFallback, wantErr: ErrProviderUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clock := &fakeClock{now: testNow}
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"` + test.hostname + `","action":"crowdsec"}`)),
					Request:    request,
				}, nil
			})
			service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
			pendingCookie := challenge(t, service, "https://example.com/private", false)
			request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
			recorder := httptest.NewRecorder()

			outcome, err := service.Handle(recorder, request, requestInfo())
			assert.Equal(t, test.wantOutcome, outcome)
			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, test.wantErr)
			}
		})
	}
}

func TestProviderTimeout(t *testing.T) {
	t.Parallel()

	config := validConfig(ProviderTurnstile)
	config.HTTPTimeout = 20 * time.Millisecond
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	clock := &fakeClock{now: testNow}
	service, err := New(config, WithClock(clock), WithRoundTripper(transport))
	require.NoError(t, err)
	pendingCookie := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	assert.Equal(t, OutcomeFallback, outcome)
	assert.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestProviderConcurrencyIsBounded(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	service := newTestService(t, ProviderTurnstile, &fakeClock{now: testNow}, WithRoundTripper(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
			Request:    request,
		}, nil
	})))
	for range maximumConcurrentChecks {
		service.verificationSlots <- struct{}{}
	}

	pending := challenge(t, service, "https://example.com/private", true)
	request := submitRequest(t, "https://example.com/private", service.spec.responseField, "valid-token", pending)
	recorder := httptest.NewRecorder()
	outcome, err := service.Handle(recorder, request, requestInfo())
	require.ErrorIs(t, err, ErrProviderUnavailable)
	assert.Equal(t, OutcomeFallback, outcome)
	assert.Zero(t, calls.Load())
}

func TestProviderRedirectIsNotFollowed(t *testing.T) {
	t.Parallel()

	var redirectTargetCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/verify":
			http.Redirect(w, request, "/target", http.StatusFound)
		case "/target":
			redirectTargetCalled.Store(true)
			_, _ = io.WriteString(w, `{"success":true,"hostname":"example.com","action":"crowdsec"}`)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	clock := &fakeClock{now: testNow}
	service := newTestService(t, ProviderTurnstile, clock, withVerificationEndpoint(server.URL+"/verify"))
	pendingCookie := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
	recorder := httptest.NewRecorder()

	outcome, err := service.Handle(recorder, request, requestInfo())
	assert.Equal(t, OutcomeFallback, outcome)
	assert.ErrorIs(t, err, ErrProviderUnavailable)
	assert.False(t, redirectTargetCalled.Load())
	assert.Empty(t, recorder.Body.String())
}

func TestCookieSecurityBindingAndExpiration(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
			Request:    request,
		}, nil
	})
	service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
	pendingCookie := challenge(t, service, "https://example.com/private", false)
	submit := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
	submitRecorder := httptest.NewRecorder()
	outcome, err := service.Handle(submitRecorder, submit, requestInfo())
	require.NoError(t, err)
	require.Equal(t, OutcomeSolved, outcome)
	passedCookie := submitRecorder.Result().Cookies()[0]

	tests := []struct {
		name   string
		mutate func(*http.Request, *RequestInfo, *http.Cookie)
	}{
		{name: "valid", mutate: func(*http.Request, *RequestInfo, *http.Cookie) {}},
		{name: "wrong host", mutate: func(request *http.Request, _ *RequestInfo, _ *http.Cookie) { request.Host = "other.example" }},
		{name: "wrong IP", mutate: func(_ *http.Request, info *RequestInfo, _ *http.Cookie) {
			info.ClientIP = netip.MustParseAddr("192.0.2.43")
		}},
		{name: "wrong binding", mutate: func(_ *http.Request, info *RequestInfo, _ *http.Cookie) { info.Binding = "other" }},
		{name: "tampered", mutate: func(_ *http.Request, _ *RequestInfo, cookie *http.Cookie) { cookie.Value += "x" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
			info := requestInfo()
			cookie := *passedCookie
			test.mutate(request, &info, &cookie)
			request.AddCookie(&cookie)
			recorder := httptest.NewRecorder()
			outcome, err := service.Handle(recorder, request, info)
			require.NoError(t, err)
			if test.name == "valid" {
				assert.Equal(t, OutcomeBypass, outcome)
			} else {
				assert.Equal(t, OutcomeChallenge, outcome)
			}
		})
	}

	clock.Advance(DefaultPassedExpiration + time.Second)
	expiredRequest := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	expiredRequest.AddCookie(passedCookie)
	expiredRecorder := httptest.NewRecorder()
	outcome, err = service.Handle(expiredRecorder, expiredRequest, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
}

func TestPassedCookieWorksAcrossInstancesSharingTheSigningKey(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.com","action":"crowdsec"}`)),
			Request:    request,
		}, nil
	})
	issuer := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
	pending := challenge(t, issuer, "https://example.com/private", true)
	submission := submitRequest(t, "https://example.com/private", issuer.spec.responseField, "proof", pending)
	solved := httptest.NewRecorder()
	outcome, err := issuer.Handle(solved, submission, requestInfo())
	require.NoError(t, err)
	require.Equal(t, OutcomeSolved, outcome)
	passed := solved.Result().Cookies()[0]

	sharedKeyInstance := newTestService(t, ProviderTurnstile, clock)
	request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	request.AddCookie(passed)
	outcome, err = sharedKeyInstance.Handle(httptest.NewRecorder(), request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeBypass, outcome)

	differentProfile := validConfig(ProviderTurnstile)
	differentProfile.SiteKey = "rotated-site-key"
	differentProfileInstance, err := New(differentProfile, WithClock(clock))
	require.NoError(t, err)
	request = httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	request.AddCookie(passed)
	outcome, err = differentProfileInstance.Handle(httptest.NewRecorder(), request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome, "clearance must be bound to the configured CAPTCHA profile")

	differentConfig := validConfig(ProviderTurnstile)
	differentConfig.SigningKey = "fedcba9876543210fedcba9876543210"
	differentKeyInstance, err := New(differentConfig, WithClock(clock))
	require.NoError(t, err)
	request = httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	request.AddCookie(passed)
	outcome, err = differentKeyInstance.Handle(httptest.NewRecorder(), request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
}

func TestDuplicateCookieNeverBypasses(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	service := newTestService(t, ProviderTurnstile, clock)
	request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: "one"})
	request.AddCookie(&http.Cookie{Name: CookieName, Value: "two"})
	recorder := httptest.NewRecorder()
	outcome, err := service.Handle(recorder, request, requestInfo())
	require.NoError(t, err)
	assert.Equal(t, OutcomeChallenge, outcome)
}

func TestSubmissionHelpersAndSafeRedirects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		rawURL       string
		isSubmission bool
		wantReturn   string
	}{
		{name: "normal", rawURL: "https://example.com/a?x=1", wantReturn: "/a?x=1"},
		{name: "valid marker", rawURL: "https://example.com/a?x=1&__crowdsec_captcha=verify", isSubmission: true, wantReturn: "/a?x=1&__crowdsec_captcha=verify"},
		{name: "malformed marker", rawURL: "https://example.com/a?__crowdsec_captcha=nope", isSubmission: true, wantReturn: "/a?__crowdsec_captcha=nope"},
		{name: "duplicate marker", rawURL: "https://example.com/a?__crowdsec_captcha=verify&__crowdsec_captcha=verify", isSubmission: true, wantReturn: "/a?__crowdsec_captcha=verify&__crowdsec_captcha=verify"},
		{name: "invalid query with marker", rawURL: "https://example.com/a?__crowdsec_captcha=verify;bad", isSubmission: true, wantReturn: "/a?__crowdsec_captcha=verify;bad"},
		{name: "encoded marker key", rawURL: "https://example.com/a?%5f%5fcrowdsec_captcha=verify", isSubmission: true, wantReturn: "/a?%5f%5fcrowdsec_captcha=verify"},
		{name: "marker text only in value", rawURL: "https://example.com/a?x=__crowdsec_captcha", wantReturn: "/a?x=__crowdsec_captcha"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.rawURL, nil)
			assert.Equal(t, test.isSubmission, IsSubmission(request))
			assert.Equal(t, test.wantReturn, safeReturnURI(request.URL))
		})
	}

	for _, raw := range []string{"", "https://evil.example", "//evil.example", "/\\evil", "/a\r\nLocation: https://evil.example"} {
		_, ok := validateReturnURI(raw)
		assert.False(t, ok, raw)
	}
	for _, raw := range []string{"/", "/private", "/private?a=b"} {
		got, ok := validateReturnURI(raw)
		assert.True(t, ok, raw)
		assert.Equal(t, raw, got)
	}
	assert.False(t, IsSubmission(nil))
}

func TestInvalidRequestContextFallsBack(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	service := newTestService(t, ProviderTurnstile, clock)
	missingHostRequest := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	missingHostRequest.Host = ""
	tests := []struct {
		name    string
		request *http.Request
		info    RequestInfo
	}{
		{name: "nil response writer handled below", request: httptest.NewRequest(http.MethodGet, "https://example.com", nil), info: requestInfo()},
		{name: "nil request", request: nil, info: requestInfo()},
		{name: "nil URL", request: &http.Request{Host: "example.com"}, info: requestInfo()},
		{name: "missing host", request: missingHostRequest, info: requestInfo()},
		{name: "invalid IP", request: httptest.NewRequest(http.MethodGet, "https://example.com", nil), info: RequestInfo{Binding: "binding"}},
		{name: "unspecified IP", request: httptest.NewRequest(http.MethodGet, "https://example.com", nil), info: RequestInfo{ClientIP: netip.IPv4Unspecified(), Binding: "binding"}},
		{name: "missing binding", request: httptest.NewRequest(http.MethodGet, "https://example.com", nil), info: RequestInfo{ClientIP: requestInfo().ClientIP}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var recorder http.ResponseWriter = httptest.NewRecorder()
			if test.name == "nil response writer handled below" {
				recorder = nil
			}
			outcome, err := service.Handle(recorder, test.request, test.info)
			assert.Equal(t, OutcomeFallback, outcome)
			assert.ErrorIs(t, err, ErrInvalidRequestContext)
		})
	}
}

func TestOutcomeString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "unavailable", OutcomeUnavailable.String())
	assert.Equal(t, "challenge", OutcomeChallenge.String())
	assert.Equal(t, "solved", OutcomeSolved.String())
	assert.Equal(t, "bypass", OutcomeBypass.String())
	assert.Equal(t, "fallback", OutcomeFallback.String())
	assert.Equal(t, "unknown", Outcome(255).String())
}

func TestConcurrentBypassValidation(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	service := newTestService(t, ProviderTurnstile, clock)
	claims := cookieClaims{
		Version: cookieVersion, State: cookieStatePassed, Host: "example.com", IP: requestInfo().ClientIP.String(),
		IssuedAt: testNow.Unix(), ExpiresAt: testNow.Add(time.Hour).Unix(), ReturnURI: "/", Binding: service.bindingTag(requestInfo().Binding),
	}
	value, err := service.signClaims(claims)
	require.NoError(t, err)
	cookie := &http.Cookie{Name: CookieName, Value: value}

	const goroutines = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(goroutines)
	for range goroutines {
		go func() {
			defer waitGroup.Done()
			request := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
			request.AddCookie(cookie)
			outcome, handleErr := service.Handle(httptest.NewRecorder(), request, requestInfo())
			assert.NoError(t, handleErr)
			assert.Equal(t, OutcomeBypass, outcome)
		}()
	}
	waitGroup.Wait()
}

func TestProviderRequestUsesCallerContext(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: testNow}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, context.Cause(request.Context())
	})
	service := newTestService(t, ProviderTurnstile, clock, WithRoundTripper(transport))
	pendingCookie := challenge(t, service, "https://example.com/private", false)
	request := submitRequest(t, "https://example.com/private", "cf-turnstile-response", "proof", pendingCookie)
	cancelledContext, cancel := context.WithCancelCause(request.Context())
	cancel(errors.New("cancelled by test"))
	request = request.WithContext(cancelledContext)

	outcome, err := service.Handle(httptest.NewRecorder(), request, requestInfo())
	assert.Equal(t, OutcomeFallback, outcome)
	assert.ErrorIs(t, err, ErrProviderUnavailable)
}
