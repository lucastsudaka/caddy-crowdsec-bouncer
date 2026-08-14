// Copyright 2020 Herman Slatman
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

package crowdsec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type fakeModule struct{}

func (m fakeModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crowdsec",
		New: func() caddy.Module { return new(fakeModule) },
	}
}

func init() {
	caddy.RegisterModule(fakeModule{}) // prevents module warning logs
}

func TestCrowdSecProvisions(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		env       map[string]string
		assertion func(tt assert.TestingT, c *CrowdSec)
		wantErr   bool
	}{
		{
			name: "ok",
			config: `{
				"api_url": "http://localhost:8080",
				"api_key": "test-key",
				"ticker_interval": "10s",
				"enable_streaming": false, 
				"enable_hard_fails": true
			}`,
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "http://localhost:8080", c.APIUrl)
				assert.Equal(tt, "test-key", c.APIKey)
				assert.Equal(tt, "10s", c.TickerInterval)
				assert.False(tt, c.isStreamingEnabled())
				assert.True(tt, c.shouldFailHard())
			},
			wantErr: false,
		},
		{
			name:   "defaults",
			config: `{}`,
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "http://127.0.0.1:8080/", c.APIUrl)
				assert.Equal(tt, "", c.APIKey)
				assert.Equal(tt, "60s", c.TickerInterval)
				assert.True(tt, c.isStreamingEnabled())
				assert.False(tt, c.shouldFailHard())
			},
			wantErr: false,
		},
		{
			name: "json-env-vars",
			config: `{
				"api_url": "{env.CROWDSEC_TEST_API_URL}",
				"api_key": "{env.CROWDSEC_TEST_API_KEY}",
				"ticker_interval": "{env.CROWDSEC_TEST_TICKER_INTERVAL}"
			}`,
			env: map[string]string{
				"CROWDSEC_TEST_API_URL":         "http://127.0.0.2:8080/",
				"CROWDSEC_TEST_API_KEY":         "env-test-key",
				"CROWDSEC_TEST_TICKER_INTERVAL": "25s",
			},
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "http://127.0.0.2:8080/", c.APIUrl)
				assert.Equal(tt, "env-test-key", c.APIKey)
				assert.Equal(tt, "25s", c.TickerInterval)
			},
			wantErr: false,
		},
		{
			name: "captcha-json-env-vars",
			config: `{
				"api_key": "test-key",
				"captcha_provider": "{env.CROWDSEC_TEST_CAPTCHA_PROVIDER}",
				"captcha_site_key": "{env.CROWDSEC_TEST_CAPTCHA_SITE_KEY}",
				"captcha_secret_key": "{env.CROWDSEC_TEST_CAPTCHA_SECRET_KEY}",
				"captcha_signing_key": "{env.CROWDSEC_TEST_CAPTCHA_SIGNING_KEY}"
			}`,
			env: map[string]string{
				"CROWDSEC_TEST_CAPTCHA_PROVIDER":    "TURNSTILE",
				"CROWDSEC_TEST_CAPTCHA_SITE_KEY":    "site-key",
				"CROWDSEC_TEST_CAPTCHA_SECRET_KEY":  "provider-secret",
				"CROWDSEC_TEST_CAPTCHA_SIGNING_KEY": "01234567890123456789012345678901",
			},
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "turnstile", c.CaptchaProvider)
				assert.Equal(tt, "site-key", c.CaptchaSiteKey)
				assert.Equal(tt, time.Hour, c.captchaExpiration())
				assert.Equal(tt, 5*time.Second, c.captchaTimeout())
				assert.NotNil(tt, c.captcha)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CrowdSec
			err := json.Unmarshal([]byte(tt.config), &c)
			require.NoError(t, err)

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
			err = c.Provision(ctx)
			require.NoError(t, err)

			if tt.assertion != nil {
				tt.assertion(t, &c)
			}
		})
	}
}

func TestCrowdSecValidates(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "ok",
			config: `{
				"api_url": "http://localhost:8080",
				"api_key": "test-key",
				"ticker_interval": "10s",
				"enable_streaming": false, 
				"enable_hard_fails": true
			}`,
			wantErr: false,
		},
		{
			name: "fail/missing-api-key",
			config: `{
				"api_url": "http://localhost:8080",
				"api_key": ""
			}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CrowdSec
			err := json.Unmarshal([]byte(tt.config), &c)
			require.NoError(t, err)

			ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
			err = c.Provision(ctx)
			require.NoError(t, err)

			err = c.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestCaptchaConfigValidation(t *testing.T) {
	valid := CrowdSec{
		CaptchaProvider:   "turnstile",
		CaptchaSiteKey:    "site-key",
		CaptchaSecretKey:  "provider-secret",
		CaptchaSigningKey: "01234567890123456789012345678901",
	}

	tests := []struct {
		name    string
		mutate  func(*CrowdSec)
		wantErr string
	}{
		{name: "disabled"},
		{
			name: "configured",
			mutate: func(c *CrowdSec) {
				*c = valid
			},
		},
		{
			name: "missing-provider",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaProvider = ""
			},
			wantErr: "captcha_provider must not be empty",
		},
		{
			name: "unsupported-provider",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaProvider = "other"
			},
			wantErr: "unsupported captcha provider",
		},
		{
			name: "short-signing-key",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaSigningKey = "too-short"
			},
			wantErr: "at least 32 bytes",
		},
		{
			name: "oversized-signing-key",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaSigningKey = strings.Repeat("k", 16385)
			},
			wantErr: "must not exceed 16384 bytes",
		},
		{
			name: "reused-provider-secret",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaSecretKey = c.CaptchaSigningKey
			},
			wantErr: "must be different",
		},
		{
			name: "negative-expiration",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaExpiration = caddy.Duration(-time.Second)
			},
			wantErr: "captcha_expiration must be positive",
		},
		{
			name: "negative-timeout",
			mutate: func(c *CrowdSec) {
				*c = valid
				c.CaptchaTimeout = caddy.Duration(-time.Second)
			},
			wantErr: "captcha_timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CrowdSec
			if tt.mutate != nil {
				tt.mutate(&c)
			}

			err := c.validateCaptchaConfig()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}

	assert.Equal(t, time.Hour, valid.captchaExpiration())
	assert.Equal(t, 5*time.Second, valid.captchaTimeout())
}

func TestHandleCaptchaBeforeProvisionIsUnavailable(t *testing.T) {
	for _, c := range []*CrowdSec{nil, {}} {
		outcome, err := c.HandleCaptcha(nil, nil, netip.Addr{})
		require.NoError(t, err)
		assert.Equal(t, CaptchaOutcomeUnavailable, outcome)
	}
}

func TestCrowdSecProvisionRejectsIncompleteCaptchaConfig(t *testing.T) {
	t.Run("partial values", func(t *testing.T) {
		c := CrowdSec{
			APIKey:          "test-key",
			CaptchaProvider: "turnstile",
		}

		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := c.Provision(ctx)
		require.ErrorContains(t, err, "captcha_site_key must not be empty")
		require.Nil(t, c.core)
		require.NoError(t, c.Cleanup())
		require.NoError(t, c.Stop())
	})

	t.Run("all environment placeholders missing", func(t *testing.T) {
		for _, name := range []string{
			"CROWDSEC_MISSING_CAPTCHA_PROVIDER",
			"CROWDSEC_MISSING_CAPTCHA_SITE_KEY",
			"CROWDSEC_MISSING_CAPTCHA_SECRET_KEY",
			"CROWDSEC_MISSING_CAPTCHA_SIGNING_KEY",
		} {
			t.Setenv(name, "")
		}
		c := CrowdSec{
			APIKey:            "test-key",
			CaptchaProvider:   "{env.CROWDSEC_MISSING_CAPTCHA_PROVIDER}",
			CaptchaSiteKey:    "{env.CROWDSEC_MISSING_CAPTCHA_SITE_KEY}",
			CaptchaSecretKey:  "{env.CROWDSEC_MISSING_CAPTCHA_SECRET_KEY}",
			CaptchaSigningKey: "{env.CROWDSEC_MISSING_CAPTCHA_SIGNING_KEY}",
		}

		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := c.Provision(ctx)
		require.ErrorContains(t, err, "resolved to empty values")
		require.Nil(t, c.core)
		require.NoError(t, c.Cleanup())
		require.NoError(t, c.Stop())
	})

	t.Run("template load failure", func(t *testing.T) {
		c := CrowdSec{
			APIKey:              "test-key",
			CaptchaProvider:     "turnstile",
			CaptchaSiteKey:      "site-key",
			CaptchaSecretKey:    "provider-secret",
			CaptchaSigningKey:   "01234567890123456789012345678901",
			CaptchaTemplatePath: filepath.Join(t.TempDir(), "missing.html"),
		}

		ctx, _ := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := c.Provision(ctx)
		require.ErrorContains(t, err, "open template")
		require.Nil(t, c.core)
		require.NoError(t, c.Cleanup())
		require.NoError(t, c.Stop())
	})
}

func TestCrowdSecLifecycleWithoutProvisionedCore(t *testing.T) {
	c := &CrowdSec{}

	require.ErrorContains(t, c.Start(), "core instance not available")
	require.NoError(t, c.Stop())
	require.NoError(t, c.Cleanup())
}

func TestCrowdSecStreamingBouncerRuntime(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent()) // ignore current ones; they're deep in the Caddy stack
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount += 1
		w.WriteHeader(200) // just accept any request
		w.Write(nil)       // nolint
	}))
	defer srv.Close()

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": "test-key"
	}`, srv.URL) // set test server URL as API URL

	var c CrowdSec
	err := json.Unmarshal([]byte(config), &c)
	require.NoError(t, err)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	err = c.Provision(caddyCtx)
	require.NoError(t, err)
	require.True(t, c.isStreamingEnabled())

	err = c.Validate()
	require.NoError(t, err)

	err = c.Start()
	require.NoError(t, err)

	wg := &sync.WaitGroup{}
	wg.Go(func() {

		// wait a little bit of time to let the go-cs-bouncer do _some_ work,
		// before it properly returns; seems to hang otherwise on b.wg.Wait().
		time.Sleep(100 * time.Millisecond)

		// simulate request coming in and stopping the server from another goroutine
		allowed, decision, err := c.IsAllowed(t.Context(), netip.MustParseAddr("127.0.0.1"))
		assert.NoError(t, err)
		assert.Nil(t, decision)
		assert.True(t, allowed)

		err = c.Stop()
		require.NoError(t, err)

		err = c.Cleanup()
		require.NoError(t, err)
	})

	// wait for the stop and cleanup process
	wg.Wait()

	// expect a single request to have been performed
	assert.Equal(t, 1, requestCount)
}

func TestCrowdSecliveBouncerRuntime(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent()) // ignore current ones; they're deep in the Caddy stack
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount += 1
		w.WriteHeader(200) // just accept any request
		w.Write(nil)       // nolint
	}))
	defer srv.Close()

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": "test-key",
		"enable_streaming": false
	}`, srv.URL) // set test server URL as API URL

	var c CrowdSec
	err := json.Unmarshal([]byte(config), &c)
	require.NoError(t, err)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	err = c.Provision(caddyCtx)
	require.NoError(t, err)
	require.False(t, c.isStreamingEnabled())

	err = c.Validate()
	require.NoError(t, err)

	err = c.Start()
	require.NoError(t, err)

	// simulate a lookup
	allowed, decision, err := c.IsAllowed(t.Context(), netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)
	assert.Nil(t, decision)
	assert.True(t, allowed)

	err = c.Stop()
	require.NoError(t, err)

	err = c.Cleanup()
	require.NoError(t, err)

	// expect a single request to have been performed
	assert.Equal(t, 1, requestCount)
}

type fakeDockerProxyModule struct{}

func (m fakeDockerProxyModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "docker_proxy", // fake github.com/lucaslorentz/caddy-docker-proxy/v2
		New: func() caddy.Module { return new(fakeModule) },
	}
}

func TestModuleLogsLowDockerProxyEventThrottleInterval(t *testing.T) {
	caddy.RegisterModule(fakeDockerProxyModule{})

	t.Run("ok/streaming", func(t *testing.T) {
		t.Setenv("CADDY_DOCKER_EVENT_THROTTLE_INTERVAL", "3s")

		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		assert.Equal(t, 0, logs.Len())
	})

	t.Run("ok/live", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		v := false
		c := &CrowdSec{logger: logger, EnableStreaming: &v}

		err := c.checkModules()
		require.NoError(t, err)

		assert.Equal(t, 0, logs.Len())
	})

	t.Run("warn-too-low", func(t *testing.T) {
		t.Setenv("CADDY_DOCKER_EVENT_THROTTLE_INTERVAL", "1s")

		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "using docker_proxy module with a low event throttle interval (<2s) can result in errors; see https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61", logs.All()[0].Message)
	})

	t.Run("warn-not-set", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "using docker_proxy module with a low event throttle interval (<2s) can result in errors; see https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61", logs.All()[0].Message)
	})

	t.Run("warn-invalid-duration", func(t *testing.T) {
		t.Setenv("CADDY_DOCKER_EVENT_THROTTLE_INTERVAL", "1x")

		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "using docker_proxy module with a low event throttle interval (<2s) can result in errors; see https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61", logs.All()[0].Message)
	})
}
