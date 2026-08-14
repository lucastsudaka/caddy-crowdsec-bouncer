package captcha

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSiteKey    = "public-site-key"
	testSecretKey  = "provider-secret"
	testSigningKey = "0123456789abcdef0123456789abcdef"
)

func validConfig(provider Provider) Config {
	return Config{
		Provider:   provider,
		SiteKey:    testSiteKey,
		SecretKey:  testSecretKey,
		SigningKey: testSigningKey,
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     Config
		wantErr    string
		configured bool
	}{
		{name: "empty config disables captcha", config: Config{}, configured: false},
		{name: "recaptcha", config: validConfig(ProviderReCAPTCHA), configured: true},
		{name: "hcaptcha", config: validConfig(ProviderHCaptcha), configured: true},
		{name: "turnstile", config: validConfig(ProviderTurnstile), configured: true},
		{
			name: "provider is canonicalized",
			config: Config{
				Provider:   "  TURNSTILE ",
				SiteKey:    testSiteKey,
				SecretKey:  testSecretKey,
				SigningKey: testSigningKey,
			},
			configured: true,
		},
		{name: "unsupported provider", config: validConfig("friendlycaptcha"), wantErr: "unsupported provider", configured: true},
		{name: "missing provider", config: Config{SiteKey: testSiteKey}, wantErr: "unsupported provider", configured: true},
		{
			name:       "missing site key",
			config:     Config{Provider: ProviderTurnstile, SecretKey: testSecretKey, SigningKey: testSigningKey},
			wantErr:    "site key is required",
			configured: true,
		},
		{
			name: "site key too long",
			config: Config{
				Provider: ProviderTurnstile, SiteKey: strings.Repeat("s", maximumSiteKeyBytes+1),
				SecretKey: testSecretKey, SigningKey: testSigningKey,
			},
			wantErr:    "site key is too long",
			configured: true,
		},
		{
			name:       "missing provider secret",
			config:     Config{Provider: ProviderTurnstile, SiteKey: testSiteKey, SigningKey: testSigningKey},
			wantErr:    "secret key is required",
			configured: true,
		},
		{
			name: "provider secret too long",
			config: Config{
				Provider: ProviderTurnstile, SiteKey: testSiteKey,
				SecretKey: strings.Repeat("s", maximumSecretKeyBytes+1), SigningKey: testSigningKey,
			},
			wantErr:    "secret key is too long",
			configured: true,
		},
		{
			name:       "missing signing key",
			config:     Config{Provider: ProviderTurnstile, SiteKey: testSiteKey, SecretKey: testSecretKey},
			wantErr:    "at least 32 bytes",
			configured: true,
		},
		{
			name: "short signing key",
			config: Config{
				Provider: ProviderTurnstile, SiteKey: testSiteKey,
				SecretKey: testSecretKey, SigningKey: strings.Repeat("k", minimumSigningKeyBytes-1),
			},
			wantErr:    "at least 32 bytes",
			configured: true,
		},
		{
			name: "signing key too long",
			config: Config{
				Provider: ProviderTurnstile, SiteKey: testSiteKey,
				SecretKey: testSecretKey, SigningKey: strings.Repeat("k", maximumSigningKeyBytes+1),
			},
			wantErr:    "signing key is too long",
			configured: true,
		},
		{
			name: "signing key reuses provider secret",
			config: Config{
				Provider: ProviderTurnstile, SiteKey: testSiteKey,
				SecretKey: testSigningKey, SigningKey: testSigningKey,
			},
			wantErr:    "independent",
			configured: true,
		},
		{
			name: "negative expiration",
			config: func() Config {
				config := validConfig(ProviderTurnstile)
				config.PassedExpiration = -time.Second
				return config
			}(),
			wantErr:    "expiration must be positive",
			configured: true,
		},
		{
			name: "sub-second expiration",
			config: func() Config {
				config := validConfig(ProviderTurnstile)
				config.PassedExpiration = time.Millisecond
				return config
			}(),
			wantErr:    "at least one second",
			configured: true,
		},
		{
			name: "negative HTTP timeout",
			config: func() Config {
				config := validConfig(ProviderTurnstile)
				config.HTTPTimeout = -time.Second
				return config
			}(),
			wantErr:    "HTTP timeout must be positive",
			configured: true,
		},
		{
			name: "expiration above maximum",
			config: func() Config {
				config := validConfig(ProviderTurnstile)
				config.PassedExpiration = MaximumPassedExpiration + time.Second
				return config
			}(),
			wantErr:    "must not exceed",
			configured: true,
		},
		{
			name: "HTTP timeout above maximum",
			config: func() Config {
				config := validConfig(ProviderTurnstile)
				config.HTTPTimeout = MaximumHTTPTimeout + time.Second
				return config
			}(),
			wantErr:    "must not exceed",
			configured: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.configured, test.config.Configured())
			err := test.config.Validate()
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestNormalizeConfigDefaults(t *testing.T) {
	t.Parallel()

	config, err := normalizeConfig(validConfig(ProviderTurnstile))
	require.NoError(t, err)
	assert.Equal(t, DefaultPassedExpiration, config.PassedExpiration)
	assert.Equal(t, DefaultHTTPTimeout, config.HTTPTimeout)
}

func TestNewRejectsTemplateProblems(t *testing.T) {
	t.Parallel()

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		config := validConfig(ProviderTurnstile)
		config.TemplatePath = t.TempDir() + "/missing.html"
		_, err := New(config)
		require.ErrorContains(t, err, "open template")
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir() + "/captcha.html"
		require.NoError(t, writeTestFile(path, []byte("{{")))
		config := validConfig(ProviderTurnstile)
		config.TemplatePath = path
		_, err := New(config)
		require.ErrorContains(t, err, "parse template")
	})

	t.Run("too large", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir() + "/captcha.html"
		require.NoError(t, writeTestFile(path, []byte(strings.Repeat("x", maximumTemplateBytes+1))))
		config := validConfig(ProviderTurnstile)
		config.TemplatePath = path
		_, err := New(config)
		require.ErrorContains(t, err, "template exceeds")
	})
}

func writeTestFile(path string, contents []byte) error {
	return os.WriteFile(path, contents, 0o600)
}
