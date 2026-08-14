package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
)

const maximumVerificationResponseBytes = 64 << 10

const turnstileAction = "crowdsec"

type providerSpec struct {
	endpoint          string
	scriptURL         string
	widgetClass       string
	responseField     string
	csp               string
	validateHost      bool
	expectedAction    string
	maximumTokenBytes int
}

var providerSpecs = map[Provider]providerSpec{ //nolint:gochecknoglobals // immutable provider registry
	ProviderReCAPTCHA: {
		endpoint:          "https://www.google.com/recaptcha/api/siteverify",
		scriptURL:         "https://www.google.com/recaptcha/api.js",
		widgetClass:       "g-recaptcha",
		responseField:     "g-recaptcha-response",
		maximumTokenBytes: 16 << 10,
		validateHost:      true,
		csp: "default-src 'none'; " +
			"script-src https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; " +
			"frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; " +
			"connect-src https://www.google.com/recaptcha/; " +
			"style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	},
	ProviderHCaptcha: {
		endpoint:          "https://api.hcaptcha.com/siteverify",
		scriptURL:         "https://js.hcaptcha.com/1/api.js",
		widgetClass:       "h-captcha",
		responseField:     "h-captcha-response",
		maximumTokenBytes: 16 << 10,
		csp: "default-src 'none'; " +
			"script-src https://js.hcaptcha.com https://hcaptcha.com https://*.hcaptcha.com; " +
			"frame-src https://hcaptcha.com https://*.hcaptcha.com; " +
			"connect-src https://hcaptcha.com https://*.hcaptcha.com; " +
			"style-src 'unsafe-inline' https://hcaptcha.com https://*.hcaptcha.com; " +
			"form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	},
	ProviderTurnstile: {
		endpoint:          "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		scriptURL:         "https://challenges.cloudflare.com/turnstile/v0/api.js",
		widgetClass:       "cf-turnstile",
		responseField:     "cf-turnstile-response",
		validateHost:      true,
		expectedAction:    turnstileAction,
		maximumTokenBytes: 2048,
		csp: "default-src 'none'; " +
			"script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; " +
			"connect-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; " +
			"form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	},
}

type verificationResult uint8

const (
	verificationRejected verificationResult = iota
	verificationAccepted
	verificationUnavailable
)

type verificationResponse struct {
	Success    *bool    `json:"success"`
	Hostname   *string  `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

// verificationLimiter bounds both total provider calls and the share that a
// single client can occupy. Its map contains only clients with calls in flight,
// so memory use is bounded by the global limit and no state must be shared
// across replicas.
type verificationLimiter struct {
	mu             sync.Mutex
	globalLimit    int
	perClientLimit int
	globalInFlight int
	clientInFlight map[netip.Addr]int
}

func newVerificationLimiter(globalLimit, perClientLimit int) *verificationLimiter {
	return &verificationLimiter{
		globalLimit:    globalLimit,
		perClientLimit: perClientLimit,
		clientInFlight: make(map[netip.Addr]int),
	}
}

func (limiter *verificationLimiter) acquire(clientIP netip.Addr) bool {
	clientIP = clientIP.Unmap()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if limiter.globalInFlight >= limiter.globalLimit || limiter.clientInFlight[clientIP] >= limiter.perClientLimit {
		return false
	}
	limiter.globalInFlight++
	limiter.clientInFlight[clientIP]++
	return true
}

func (limiter *verificationLimiter) release(clientIP netip.Addr) {
	clientIP = clientIP.Unmap()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if limiter.clientInFlight[clientIP] <= 1 {
		delete(limiter.clientInFlight, clientIP)
	} else {
		limiter.clientInFlight[clientIP]--
	}
	limiter.globalInFlight--
}

func (s *Service) verify(ctx context.Context, token, host string, clientIP netip.Addr) verificationResult {
	if ctx.Err() != nil || !s.verificationLimiter.acquire(clientIP) {
		return verificationUnavailable
	}
	defer s.verificationLimiter.release(clientIP)

	values := make(url.Values, 3)
	values.Set("secret", s.secretKey)
	values.Set("response", token)
	values.Set("remoteip", clientIP.String())
	if s.provider == ProviderHCaptcha {
		values.Set("sitekey", s.siteKey)
	}

	ctx, cancel := context.WithTimeout(ctx, s.httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.verificationEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return verificationUnavailable
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return verificationUnavailable
	}
	if resp == nil || resp.Body == nil {
		return verificationUnavailable
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return verificationUnavailable
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maximumVerificationResponseBytes+1))
	if err != nil || len(body) > maximumVerificationResponseBytes {
		return verificationUnavailable
	}

	var result verificationResponse
	if err := json.Unmarshal(body, &result); err != nil || result.Success == nil {
		return verificationUnavailable
	}
	if !*result.Success {
		return classifyVerificationFailure(result.ErrorCodes)
	}
	if !s.spec.validateHost {
		return verificationAccepted
	}
	if result.Hostname == nil || *result.Hostname == "" {
		return verificationUnavailable
	}

	verifiedHost, err := canonicalHost(*result.Hostname)
	if err != nil {
		return verificationUnavailable
	}
	if verifiedHost != host {
		return verificationRejected
	}
	if s.spec.expectedAction != "" && result.Action != s.spec.expectedAction {
		return verificationRejected
	}

	return verificationAccepted
}

func classifyVerificationFailure(errorCodes []string) verificationResult {
	if len(errorCodes) == 0 {
		return verificationRejected
	}

	for _, code := range errorCodes {
		switch code {
		case "invalid-input-response", "timeout-or-duplicate", "expired-input-response", "already-seen-response":
			// The browser proof is absent, invalid, expired, or already consumed.
			// Re-presenting the challenge is the provider-recommended recovery.
			continue
		case "missing-input-secret", "invalid-input-secret", "missing-input-response", "bad-request",
			"internal-error", "missing-remoteip", "invalid-remoteip", "not-using-dummy-passcode",
			"sitekey-secret-mismatch":
			return verificationUnavailable
		default:
			// Unknown provider failures must not become an authorization retry loop.
			return verificationUnavailable
		}
	}

	return verificationRejected
}

var errRedirectNotAllowed = errors.New("captcha: provider redirects are not allowed")
