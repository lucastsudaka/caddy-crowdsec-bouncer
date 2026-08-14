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

package crowdsec

import (
	"net/http"
	"net/netip"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/captcha"
)

// CaptchaOutcome reports how a CAPTCHA request was handled.
type CaptchaOutcome = captcha.Outcome

const (
	CaptchaOutcomeUnavailable = captcha.OutcomeUnavailable
	CaptchaOutcomeChallenge   = captcha.OutcomeChallenge
	CaptchaOutcomeSolved      = captcha.OutcomeSolved
	CaptchaOutcomeBypass      = captcha.OutcomeBypass
	CaptchaOutcomeFallback    = captcha.OutcomeFallback

	captchaBinding = "crowdsec"
)

// IsCaptchaSubmission reports whether r carries the reserved CAPTCHA marker
// while CAPTCHA support is enabled. With an empty CAPTCHA configuration the
// marker has no special meaning, preserving the module's legacy behavior.
func (c *CrowdSec) IsCaptchaSubmission(r *http.Request) bool {
	return c != nil && c.captcha != nil && c.captcha.Enabled() && captcha.IsSubmission(r)
}

// HandleCaptcha evaluates a CAPTCHA decision or submission for the client.
// Proofs are intentionally shared by HTTP remediation components for the same
// host, IP, and configured CAPTCHA profile. Every component must still
// evaluate higher-priority ban actions on the redirected request.
func (c *CrowdSec) HandleCaptcha(w http.ResponseWriter, r *http.Request, ip netip.Addr) (CaptchaOutcome, error) {
	if c == nil || c.captcha == nil {
		return CaptchaOutcomeUnavailable, nil
	}
	return c.captcha.Handle(w, r, captcha.RequestInfo{
		ClientIP: ip,
		Binding:  captchaBinding,
	})
}

func (c *CrowdSec) captchaConfig() captcha.Config {
	if !c.captchaConfigured() {
		return captcha.Config{}
	}

	return captcha.Config{
		Provider:         captcha.Provider(c.CaptchaProvider),
		SiteKey:          c.CaptchaSiteKey,
		SecretKey:        c.CaptchaSecretKey,
		SigningKey:       c.CaptchaSigningKey,
		TemplatePath:     c.CaptchaTemplatePath,
		PassedExpiration: c.captchaExpiration(),
		HTTPTimeout:      c.captchaTimeout(),
	}
}
