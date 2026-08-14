package crowdsec

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tv := true
	fv := false
	tests := []struct {
		name         string
		input        string
		env          map[string]string
		expected     *CrowdSec
		wantParseErr bool
	}{
		{
			name:         "fail/missing tokens",
			expected:     &CrowdSec{},
			input:        ``,
			wantParseErr: true,
		},
		{
			name:         "fail/not-crowdsec",
			expected:     &CrowdSec{},
			input:        `not-crowdsec`,
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-duration",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
					ticker_interval 30x
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/no-api-url",
			expected: &CrowdSec{},
			input: `
			crowdsec {
				api_url 
				api_key some_random_key
				ticker_interval 30x
			}`,
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-api-url",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://\x00/
					api_key some_random_key
					ticker_interval 30x
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-api-url-no-scheme",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url example.com
					api_key some_random_key
					ticker_interval 30x
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/missing-api-key",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key 
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/missing-ticker-interval",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key test-key
					ticker_interval
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-streaming",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key test-key
					ticker_interval 30s
					disable_streaming absolutely
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-streaming",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key test-key
					ticker_interval 30s
					disable_streaming
					enable_hard_fails yo
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/unknown-token",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
					unknown_token 42
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/enable-caddy-error-with-args",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_url http://127.0.0.1:8080
					api_key some_random_key
					enable_caddy_error true
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/missing-captcha-provider",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_key some_random_key
					captcha_provider
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-captcha-expiration",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_key some_random_key
					captcha_expiration forever
				}`,
			wantParseErr: true,
		},
		{
			name:     "fail/non-positive-captcha-timeout",
			expected: &CrowdSec{},
			input: `crowdsec {
					api_key some_random_key
					captcha_timeout 0s
				}`,
			wantParseErr: true,
		},
		{
			name: "ok/basic",
			expected: &CrowdSec{
				APIUrl:           "http://127.0.0.1:8080/",
				APIKey:           "some_random_key",
				TickerInterval:   "60s",
				EnableStreaming:  &tv,
				EnableHardFails:  &fv,
				EnableCaddyError: false,
			},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
				}`,
			wantParseErr: false,
		},
		{
			name: "ok/full",
			expected: &CrowdSec{
				APIUrl:              "http://127.0.0.1:8080/",
				APIKey:              "some_random_key",
				TickerInterval:      "33s",
				EnableStreaming:     &fv,
				EnableHardFails:     &tv,
				EnableCaddyError:    true,
				CaptchaProvider:     "turnstile",
				CaptchaSiteKey:      "site-key",
				CaptchaSecretKey:    "secret-key",
				CaptchaSigningKey:   "01234567890123456789012345678901",
				CaptchaTemplatePath: "/etc/caddy/captcha.html",
				CaptchaExpiration:   caddy.Duration(time.Hour),
				CaptchaTimeout:      caddy.Duration(3 * time.Second),
			},
			input: `crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
					ticker_interval 33s
					disable_streaming
					enable_hard_fails
					enable_caddy_error
					captcha_provider turnstile
					captcha_site_key site-key
					captcha_secret_key secret-key
					captcha_signing_key 01234567890123456789012345678901
					captcha_template_path /etc/caddy/captcha.html
					captcha_expiration 1h
					captcha_timeout 3s
				}`,
			wantParseErr: false,
		},
		{
			name: "ok/env-vars",
			expected: &CrowdSec{
				APIUrl:           "http://127.0.0.2:8080/",
				APIKey:           "env-test-key",
				TickerInterval:   "25s",
				EnableStreaming:  &tv,
				EnableHardFails:  &fv,
				EnableCaddyError: false,
			},
			env: map[string]string{
				"CROWDSEC_TEST_API_URL":         "http://127.0.0.2:8080/",
				"CROWDSEC_TEST_API_KEY":         "env-test-key",
				"CROWDSEC_TEST_TICKER_INTERVAL": "25s",
			},
			input: `crowdsec {
					api_url {$CROWDSEC_TEST_API_URL}
					api_key {$CROWDSEC_TEST_API_KEY}
					ticker_interval {$CROWDSEC_TEST_TICKER_INTERVAL}
				}`,
			wantParseErr: false,
		},
		{
			name: "ok/captcha-env-vars",
			expected: &CrowdSec{
				APIKey:            "env-test-key",
				TickerInterval:    "60s",
				EnableStreaming:   &tv,
				EnableHardFails:   &fv,
				CaptchaProvider:   "turnstile",
				CaptchaSiteKey:    "site-key",
				CaptchaSecretKey:  "provider-secret",
				CaptchaSigningKey: "01234567890123456789012345678901",
			},
			input: `crowdsec {
					api_key {$CROWDSEC_TEST_API_KEY}
					captcha_provider turnstile
					captcha_site_key {$CROWDSEC_TEST_CAPTCHA_SITE_KEY}
					captcha_secret_key {$CROWDSEC_TEST_CAPTCHA_SECRET_KEY}
					captcha_signing_key {$CROWDSEC_TEST_CAPTCHA_SIGNING_KEY}
				}`,
			env: map[string]string{
				"CROWDSEC_TEST_API_KEY":             "env-test-key",
				"CROWDSEC_TEST_CAPTCHA_SITE_KEY":    "site-key",
				"CROWDSEC_TEST_CAPTCHA_SECRET_KEY":  "provider-secret",
				"CROWDSEC_TEST_CAPTCHA_SIGNING_KEY": "01234567890123456789012345678901",
			},
			wantParseErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			dispenser := caddyfile.NewTestDispenser(tt.input)
			jsonApp, err := parseCrowdSec(dispenser, nil)
			if tt.wantParseErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			app, ok := jsonApp.(httpcaddyfile.App)
			require.True(t, ok)
			assert.Equal(t, "crowdsec", app.Name)

			var c CrowdSec
			err = json.Unmarshal(app.Value, &c)
			require.NoError(t, err)

			assert.Equal(t, tt.expected.APIUrl, c.APIUrl)
			assert.Equal(t, tt.expected.APIKey, c.APIKey)
			assert.Equal(t, tt.expected.TickerInterval, c.TickerInterval)
			assert.Equal(t, tt.expected.isStreamingEnabled(), c.isStreamingEnabled())
			assert.Equal(t, tt.expected.shouldFailHard(), c.shouldFailHard())
			assert.Equal(t, tt.expected.EnableCaddyError, c.EnableCaddyError)
			assert.Equal(t, tt.expected.CaptchaProvider, c.CaptchaProvider)
			assert.Equal(t, tt.expected.CaptchaSiteKey, c.CaptchaSiteKey)
			assert.Equal(t, tt.expected.CaptchaSecretKey, c.CaptchaSecretKey)
			assert.Equal(t, tt.expected.CaptchaSigningKey, c.CaptchaSigningKey)
			assert.Equal(t, tt.expected.CaptchaTemplatePath, c.CaptchaTemplatePath)
			assert.Equal(t, tt.expected.CaptchaExpiration, c.CaptchaExpiration)
			assert.Equal(t, tt.expected.CaptchaTimeout, c.CaptchaTimeout)
		})
	}
}
