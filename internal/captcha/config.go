package captcha

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultPassedExpiration is how long a successful captcha proof is valid
	// when Config.PassedExpiration is omitted.
	DefaultPassedExpiration = time.Hour

	// DefaultHTTPTimeout bounds a provider verification request when
	// Config.HTTPTimeout is omitted.
	DefaultHTTPTimeout = 5 * time.Second
	// MaximumPassedExpiration bounds stale browser clearances.
	MaximumPassedExpiration = 24 * time.Hour
	// MaximumHTTPTimeout prevents provider verification from tying up request
	// handlers for an unbounded period.
	MaximumHTTPTimeout = time.Minute

	defaultPendingExpiration = 10 * time.Minute
	minimumSigningKeyBytes   = 32
	maximumSigningKeyBytes   = 16384
	maximumSiteKeyBytes      = 4096
	maximumSecretKeyBytes    = 16384
	maximumTemplateBytes     = 1 << 20
	maximumRenderedHTMLBytes = 2 << 20
)

// Provider identifies a supported captcha provider.
type Provider string

const (
	// ProviderReCAPTCHA uses Google reCAPTCHA.
	ProviderReCAPTCHA Provider = "recaptcha"
	// ProviderHCaptcha uses hCaptcha.
	ProviderHCaptcha Provider = "hcaptcha"
	// ProviderTurnstile uses Cloudflare Turnstile.
	ProviderTurnstile Provider = "turnstile"
)

// Config contains captcha credentials and local security settings. Provider
// verification endpoints are deliberately not configurable here.
//
// An entirely empty Config disables captcha support. Once any field is set,
// Provider, SiteKey, SecretKey, and SigningKey are all required. SigningKey is
// independent from the provider secret and must contain at least 32 bytes.
type Config struct {
	Provider         Provider      `json:"provider,omitempty"`
	SiteKey          string        `json:"site_key,omitempty"`
	SecretKey        string        `json:"secret_key,omitempty"`
	SigningKey       string        `json:"signing_key,omitempty"`
	TemplatePath     string        `json:"template_path,omitempty"`
	PassedExpiration time.Duration `json:"passed_expiration,omitempty"`
	HTTPTimeout      time.Duration `json:"http_timeout,omitempty"`
}

// Configured reports whether at least one captcha setting was supplied.
func (c Config) Configured() bool {
	return c.Provider != "" ||
		c.SiteKey != "" ||
		c.SecretKey != "" ||
		c.SigningKey != "" ||
		c.TemplatePath != "" ||
		c.PassedExpiration != 0 ||
		c.HTTPTimeout != 0
}

// Validate validates Config without loading TemplatePath. New additionally
// reads and parses the configured template.
func (c Config) Validate() error {
	_, err := normalizeConfig(c)
	return err
}

func normalizeConfig(c Config) (Config, error) {
	if !c.Configured() {
		return c, nil
	}

	c.Provider = Provider(strings.ToLower(strings.TrimSpace(string(c.Provider))))
	if _, ok := providerSpecs[c.Provider]; !ok {
		return Config{}, fmt.Errorf("captcha: unsupported provider %q", c.Provider)
	}
	if c.SiteKey == "" {
		return Config{}, errors.New("captcha: site key is required")
	}
	if len(c.SiteKey) > maximumSiteKeyBytes {
		return Config{}, errors.New("captcha: site key is too long")
	}
	if c.SecretKey == "" {
		return Config{}, errors.New("captcha: secret key is required")
	}
	if len(c.SecretKey) > maximumSecretKeyBytes {
		return Config{}, errors.New("captcha: secret key is too long")
	}
	if len([]byte(c.SigningKey)) < minimumSigningKeyBytes {
		return Config{}, fmt.Errorf("captcha: signing key must contain at least %d bytes", minimumSigningKeyBytes)
	}
	if len([]byte(c.SigningKey)) > maximumSigningKeyBytes {
		return Config{}, errors.New("captcha: signing key is too long")
	}
	if c.SigningKey == c.SecretKey {
		return Config{}, errors.New("captcha: signing key must be independent from the provider secret")
	}
	if c.PassedExpiration < 0 {
		return Config{}, errors.New("captcha: passed expiration must be positive")
	}
	if c.PassedExpiration == 0 {
		c.PassedExpiration = DefaultPassedExpiration
	} else if c.PassedExpiration < time.Second {
		return Config{}, errors.New("captcha: passed expiration must be at least one second")
	} else if c.PassedExpiration > MaximumPassedExpiration {
		return Config{}, fmt.Errorf("captcha: passed expiration must not exceed %s", MaximumPassedExpiration)
	}
	if c.HTTPTimeout < 0 {
		return Config{}, errors.New("captcha: HTTP timeout must be positive")
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = DefaultHTTPTimeout
	} else if c.HTTPTimeout > MaximumHTTPTimeout {
		return Config{}, fmt.Errorf("captcha: HTTP timeout must not exceed %s", MaximumHTTPTimeout)
	}

	return c, nil
}
