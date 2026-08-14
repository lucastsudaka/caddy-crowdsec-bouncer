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
	"bytes"
	"errors"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	submissionQueryKey       = "__crowdsec_captcha"
	submissionQueryValue     = "verify"
	maximumSubmissionBytes   = 32 << 10
	maximumReturnURIBytes    = 2048
	maximumCanonicalHostByte = 255
	maximumConcurrentChecks  = 64
	captchaProfileVersion    = "v1"
)

var (
	// ErrInvalidRequestContext means Handle could not safely bind a proof to
	// the request. The caller should fail closed.
	ErrInvalidRequestContext = errors.New("captcha: invalid request context")
	// ErrInvalidSubmission means a marked request was not a valid response to
	// a pending challenge. The caller should fail closed without forwarding it.
	ErrInvalidSubmission = errors.New("captcha: invalid submission")
	// ErrUnsupportedMethod means a browser challenge cannot safely preserve the
	// semantics of the original request. The caller should apply its fallback.
	ErrUnsupportedMethod = errors.New("captcha: unsupported request method")
	// ErrProviderUnavailable means verification failed because the provider
	// was unreachable or returned an unusable response.
	ErrProviderUnavailable = errors.New("captcha: verification provider unavailable")
	// ErrRenderChallenge means the configured challenge could not be rendered.
	ErrRenderChallenge = errors.New("captcha: could not render challenge")
	// ErrWriteResponse means the client connection failed while writing a
	// response. The response may already have been committed.
	ErrWriteResponse = errors.New("captcha: could not write response")

	errCookieTooLarge = errors.New("captcha: cookie exceeds maximum size")
	errHTMLTooLarge   = errors.New("captcha: rendered HTML exceeds maximum size")
)

type boundedBuffer struct {
	bytes.Buffer
	maximum int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.maximum-b.Len() {
		return 0, errHTMLTooLarge
	}

	return b.Buffer.Write(p)
}

// Outcome describes what Service.Handle decided or wrote.
type Outcome uint8

const (
	// OutcomeUnavailable indicates that the service has an empty (disabled)
	// configuration and did not inspect or modify the response.
	OutcomeUnavailable Outcome = iota
	// OutcomeChallenge indicates that a challenge was written with status 200.
	// The caller must stop the handler chain and may record a captcha action.
	OutcomeChallenge
	// OutcomeSolved indicates that a submitted proof was accepted, a passed
	// cookie was issued, and a 303 redirect was written. The caller must stop
	// the handler chain and may record a bypass action.
	OutcomeSolved
	// OutcomeBypass indicates that the request carries a valid passed proof and
	// may continue through the rest of the handler chain.
	OutcomeBypass
	// OutcomeFallback indicates that captcha verification could not be
	// completed safely. The caller should apply a fail-closed remediation.
	OutcomeFallback
)

// String returns a stable diagnostic name for the outcome.
func (o Outcome) String() string {
	switch o {
	case OutcomeUnavailable:
		return "unavailable"
	case OutcomeChallenge:
		return "challenge"
	case OutcomeSolved:
		return "solved"
	case OutcomeBypass:
		return "bypass"
	case OutcomeFallback:
		return "fallback"
	default:
		return "unknown"
	}
}

// RequestInfo binds a captcha proof to a client and a caller-defined clearance
// domain. Binding must be stable and non-empty; callers may scope it to one
// decision or deliberately share it across related captcha decisions. It is
// stored in the cookie only as an HMAC.
type RequestInfo struct {
	ClientIP netip.Addr
	Binding  string
}

// HTTPClient is the subset of http.Client used for provider verification.
// Implementations must be safe for concurrent use.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Clock supplies time for cookie creation and validation.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

// Now implements Clock.
func (f ClockFunc) Now() time.Time { return f() }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type serviceOptions struct {
	httpClient           HTTPClient
	clock                Clock
	verificationEndpoint string
	nonceGenerator       func() (string, error)
}

// Option customizes Service construction. Production callers normally need
// no options; WithHTTPClient, WithRoundTripper, and WithClock primarily make
// tests hermetic. Provider endpoints remain fixed unless package-internal
// tests use the unexported endpoint option.
type Option func(*serviceOptions) error

// WithHTTPClient injects the client used for verification requests.
func WithHTTPClient(client HTTPClient) Option {
	return func(options *serviceOptions) error {
		if client == nil {
			return errors.New("captcha: HTTP client must not be nil")
		}
		options.httpClient = client
		return nil
	}
}

// WithRoundTripper injects an HTTP transport while retaining redirect
// rejection. The request timeout is still enforced by Service.
func WithRoundTripper(transport http.RoundTripper) Option {
	return func(options *serviceOptions) error {
		if transport == nil {
			return errors.New("captcha: HTTP transport must not be nil")
		}
		options.httpClient = newHTTPClient(transport)
		return nil
	}
}

// WithClock injects the clock used for signed-cookie timestamps.
func WithClock(clock Clock) Option {
	return func(options *serviceOptions) error {
		if clock == nil {
			return errors.New("captcha: clock must not be nil")
		}
		options.clock = clock
		return nil
	}
}

// withVerificationEndpoint is intentionally package-private: provider
// endpoints must not be part of user configuration. Tests may use this option
// to point at an httptest server without weakening the production allowlist.
func withVerificationEndpoint(endpoint string) Option {
	return func(options *serviceOptions) error {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return errors.New("captcha: invalid verification endpoint")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("captcha: invalid verification endpoint scheme")
		}
		options.verificationEndpoint = endpoint
		return nil
	}
}

// withNonceGenerator is intentionally package-private: production nonces are
// always generated with crypto/rand. Tests may inject deterministic values or
// failures without weakening the public API.
func withNonceGenerator(generator func() (string, error)) Option {
	return func(options *serviceOptions) error {
		if generator == nil {
			return errors.New("captcha: nonce generator must not be nil")
		}
		options.nonceGenerator = generator
		return nil
	}
}

// Service renders challenges, verifies provider tokens, and manages signed
// proof cookies. It is immutable after New and safe for concurrent use.
type Service struct {
	enabled              bool
	provider             Provider
	siteKey              string
	secretKey            string
	signingKey           []byte
	passedExpiration     time.Duration
	httpTimeout          time.Duration
	httpClient           HTTPClient
	clock                Clock
	verificationEndpoint string
	verificationSlots    chan struct{}
	nonceGenerator       func() (string, error)
	profileBinding       string
	template             *template.Template
	spec                 providerSpec
}

// New validates config and constructs a Service. An empty Config returns a
// disabled service whose Handle method reports OutcomeUnavailable.
func New(config Config, options ...Option) (*Service, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}

	serviceOptions := serviceOptions{
		httpClient:     newHTTPClient(http.DefaultTransport),
		clock:          systemClock{},
		nonceGenerator: generateScriptNonce,
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("captcha: option must not be nil")
		}
		if err := option(&serviceOptions); err != nil {
			return nil, err
		}
	}

	if !config.Configured() {
		return &Service{httpClient: serviceOptions.httpClient, clock: serviceOptions.clock}, nil
	}

	spec := providerSpecs[config.Provider]
	if serviceOptions.verificationEndpoint == "" {
		serviceOptions.verificationEndpoint = spec.endpoint
	}
	tmpl, err := loadTemplate(config.TemplatePath)
	if err != nil {
		return nil, err
	}

	return &Service{
		enabled:              true,
		provider:             config.Provider,
		siteKey:              config.SiteKey,
		secretKey:            config.SecretKey,
		signingKey:           append([]byte(nil), []byte(config.SigningKey)...),
		passedExpiration:     config.PassedExpiration,
		httpTimeout:          config.HTTPTimeout,
		httpClient:           serviceOptions.httpClient,
		clock:                serviceOptions.clock,
		verificationEndpoint: serviceOptions.verificationEndpoint,
		verificationSlots:    make(chan struct{}, maximumConcurrentChecks),
		nonceGenerator:       serviceOptions.nonceGenerator,
		profileBinding:       captchaProfileVersion + "\x00" + string(config.Provider) + "\x00" + config.SiteKey,
		template:             tmpl,
		spec:                 spec,
	}, nil
}

// Enabled reports whether the service has a complete CAPTCHA configuration.
func (s *Service) Enabled() bool {
	return s != nil && s.enabled
}

func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectNotAllowed
		},
	}
}

// IsSubmission reports whether the reserved captcha submission query key is
// present. It intentionally also reports malformed markers so callers can
// route them to Handle and prevent them from reaching body-consuming
// middleware or an upstream. Handle validates the marker value and method.
func IsSubmission(r *http.Request) bool {
	if r == nil {
		return false
	}
	present, _ := submissionMarker(r.URL)
	return present
}

// Handle evaluates a captcha request. The returned Outcome always determines
// whether the caller should continue, stop, or apply its fallback. Errors are
// deliberately sanitized and never contain credentials, tokens, cookies, or
// provider response bodies.
func (s *Service) Handle(w http.ResponseWriter, r *http.Request, info RequestInfo) (Outcome, error) {
	if s == nil || !s.enabled {
		return OutcomeUnavailable, nil
	}
	if w == nil || r == nil || r.URL == nil || !info.ClientIP.IsValid() || info.ClientIP.IsUnspecified() || info.ClientIP.Zone() != "" ||
		info.Binding == "" || len(info.Binding) > maximumBindingBytes {
		return OutcomeFallback, ErrInvalidRequestContext
	}
	info.ClientIP = info.ClientIP.Unmap()
	host, err := canonicalHost(r.Host)
	if err != nil {
		return OutcomeFallback, ErrInvalidRequestContext
	}

	claims, hasValidCookie := s.readClaims(r, host, info)
	markerPresent, validSubmissionMarker := submissionMarker(r.URL)
	if markerPresent {
		if r.Method != http.MethodPost || !validSubmissionMarker || !hasValidCookie || claims.State != cookieStatePending {
			closeRequestBody(r)
			return OutcomeFallback, ErrInvalidSubmission
		}

		token, ok := readSubmission(w, r, s.spec.responseField, s.spec.maximumTokenBytes)
		if !ok {
			return s.writeChallenge(w, r, host, info, claims.ReturnURI, true)
		}
		switch s.verify(r.Context(), token, host, info.ClientIP) {
		case verificationAccepted:
			return s.writePassedRedirect(w, r, host, info, claims.ReturnURI)
		case verificationRejected:
			return s.writeChallenge(w, r, host, info, claims.ReturnURI, true)
		case verificationUnavailable:
			return OutcomeFallback, ErrProviderUnavailable
		default:
			return OutcomeFallback, ErrProviderUnavailable
		}
	}

	if hasValidCookie && claims.State == cookieStatePassed {
		return OutcomeBypass, nil
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		closeRequestBody(r)
		return OutcomeFallback, ErrUnsupportedMethod
	}

	return s.writeChallenge(w, r, host, info, safeReturnURI(r.URL), false)
}

func (s *Service) writeChallenge(
	w http.ResponseWriter,
	r *http.Request,
	host string,
	info RequestInfo,
	returnURI string,
	failed bool,
) (Outcome, error) {
	returnURI, ok := validateReturnURI(returnURI)
	if !ok {
		returnURI = "/"
	}
	formAction, ok := submissionURI(returnURI)
	if !ok {
		return OutcomeFallback, ErrRenderChallenge
	}
	nonce, err := s.nonceGenerator()
	if err != nil {
		return OutcomeFallback, ErrRenderChallenge
	}
	csp, ok := contentSecurityPolicy(s.spec.csp, nonce)
	if !ok {
		return OutcomeFallback, ErrRenderChallenge
	}

	data := TemplateData{
		Provider:    s.provider,
		SiteKey:     s.siteKey,
		ScriptURL:   template.URL(s.spec.scriptURL), //nolint:gosec // URL is selected from the immutable provider registry
		WidgetClass: s.spec.widgetClass,
		Action:      s.spec.expectedAction,
		FormAction:  formAction,
		Nonce:       nonce,
		Failed:      failed,
	}
	body := boundedBuffer{maximum: maximumRenderedHTMLBytes}
	if err := s.template.Execute(&body, data); err != nil {
		return OutcomeFallback, ErrRenderChallenge
	}

	cookie, err := s.newCookie(r, cookieStatePending, host, info, returnURI)
	if err != nil {
		return OutcomeFallback, ErrRenderChallenge
	}
	setSecurityHeaders(w.Header(), csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return OutcomeChallenge, nil
	}
	if _, err := w.Write(body.Bytes()); err != nil {
		return OutcomeChallenge, ErrWriteResponse
	}
	return OutcomeChallenge, nil
}

func contentSecurityPolicy(base, nonce string) (string, bool) {
	if !validScriptNonce(nonce) {
		return "", false
	}

	const directive = "script-src "
	index := strings.Index(base, directive)
	if index < 0 {
		return "", false
	}
	index += len(directive)
	return base[:index] + "'nonce-" + nonce + "' " + base[index:], true
}

func validScriptNonce(nonce string) bool {
	if len(nonce) < 16 || len(nonce) > 128 {
		return false
	}
	for _, character := range nonce {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '+' && character != '/' && character != '=' {
			return false
		}
	}
	return true
}

func (s *Service) writePassedRedirect(
	w http.ResponseWriter,
	r *http.Request,
	host string,
	info RequestInfo,
	returnURI string,
) (Outcome, error) {
	returnURI, ok := validateReturnURI(returnURI)
	if !ok {
		return OutcomeFallback, ErrInvalidRequestContext
	}
	cookie, err := s.newCookie(r, cookieStatePassed, host, info, returnURI)
	if err != nil {
		return OutcomeFallback, ErrRenderChallenge
	}

	setSecurityHeaders(w.Header(), "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	http.SetCookie(w, cookie)
	http.Redirect(w, r, returnURI, http.StatusSeeOther)
	return OutcomeSolved, nil
}

func setSecurityHeaders(header http.Header, csp string) {
	header.Set("Cache-Control", "no-store, private")
	header.Set("Content-Security-Policy", csp)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func readSubmission(w http.ResponseWriter, r *http.Request, responseField string, maximumTokenLength int) (string, bool) {
	if r.Body == nil {
		return "", false
	}
	body := http.MaxBytesReader(w, r.Body, maximumSubmissionBytes)
	defer func() { _ = body.Close() }()

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return "", false
	}
	if r.ContentLength > maximumSubmissionBytes {
		return "", false
	}

	encoded, err := io.ReadAll(body)
	if err != nil {
		return "", false
	}
	values, err := url.ParseQuery(string(encoded))
	if err != nil {
		return "", false
	}
	tokens := values[responseField]
	if maximumTokenLength <= 0 || len(tokens) != 1 || tokens[0] == "" || len(tokens[0]) > maximumTokenLength {
		return "", false
	}
	return tokens[0], true
}

func closeRequestBody(r *http.Request) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
}

func submissionMarker(requestURL *url.URL) (present, valid bool) {
	if requestURL == nil {
		return false, false
	}
	query, err := url.ParseQuery(requestURL.RawQuery)
	values, present := query[submissionQueryKey]
	if !present {
		present = rawQueryContainsKey(requestURL.RawQuery, submissionQueryKey)
	}
	return present, err == nil && present && len(values) == 1 && values[0] == submissionQueryValue
}

func rawQueryContainsKey(rawQuery, wanted string) bool {
	for field := range strings.SplitSeq(rawQuery, "&") {
		rawKey, _, _ := strings.Cut(field, "=")
		key, err := url.QueryUnescape(rawKey)
		if err == nil && key == wanted {
			return true
		}
	}
	return false
}

func safeReturnURI(requestURL *url.URL) string {
	if requestURL == nil {
		return "/"
	}
	copyURL := *requestURL
	copyURL.Scheme = ""
	copyURL.Host = ""
	copyURL.User = nil
	copyURL.Fragment = ""
	if copyURL.Path == "" {
		copyURL.Path = "/"
	}
	uri := copyURL.RequestURI()
	if _, ok := validateReturnURI(uri); !ok {
		return "/"
	}
	return uri
}

func submissionURI(returnURI string) (string, bool) {
	returnURI, ok := validateReturnURI(returnURI)
	if !ok {
		return "", false
	}
	parsed, err := url.ParseRequestURI(returnURI)
	if err != nil {
		return "", false
	}
	if rawQueryContainsKey(parsed.RawQuery, submissionQueryKey) {
		return "", false
	}
	marker := url.QueryEscape(submissionQueryKey) + "=" + url.QueryEscape(submissionQueryValue)
	if parsed.RawQuery == "" {
		parsed.RawQuery = marker
	} else {
		parsed.RawQuery += "&" + marker
	}
	uri := parsed.RequestURI()
	_, ok = validateReturnURI(uri)
	return uri, ok
}

func validateReturnURI(raw string) (string, bool) {
	if raw == "" || len(raw) > maximumReturnURIBytes || raw[0] != '/' || strings.HasPrefix(raw, "//") ||
		strings.ContainsAny(raw, "\\\r\n") {
		return "", false
	}
	for _, character := range raw {
		if character < 0x20 || character == 0x7f {
			return "", false
		}
	}

	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return "", false
	}
	if strings.HasPrefix(parsed.Path, "//") || strings.ContainsAny(parsed.Path, "\\\r\n") {
		return "", false
	}
	return raw, true
}

func canonicalHost(raw string) (string, error) {
	if raw == "" || len(raw) > maximumCanonicalHostByte || raw != strings.TrimSpace(raw) ||
		strings.ContainsAny(raw, "/\\?#@\r\n\t") {
		return "", ErrInvalidRequestContext
	}

	host := raw
	if splitHost, port, err := net.SplitHostPort(raw); err == nil {
		if portNumber, err := strconv.ParseUint(port, 10, 16); err != nil || portNumber == 0 {
			return "", ErrInvalidRequestContext
		}
		host = splitHost
	} else if strings.HasPrefix(raw, "[") || strings.HasSuffix(raw, "]") {
		if len(raw) < 3 || raw[0] != '[' || raw[len(raw)-1] != ']' {
			return "", ErrInvalidRequestContext
		}
		host = raw[1 : len(raw)-1]
	} else if strings.Count(raw, ":") > 1 {
		host = raw
	} else if strings.Contains(raw, ":") {
		return "", ErrInvalidRequestContext
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", ErrInvalidRequestContext
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	}
	if len(host) > 253 {
		return "", ErrInvalidRequestContext
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidRequestContext
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidRequestContext
			}
		}
	}
	return host, nil
}
