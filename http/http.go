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

package http

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/appsec" // always include AppSec module when HTTP is added
	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/servername"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("crowdsec", parseCaddyfileHandlerDirective)
}

// Handler matches request IPs to CrowdSec decisions to (dis)allow access.
type Handler struct {
	logger   *zap.Logger
	crowdsec *crowdsec.CrowdSec
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crowdsec",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the CrowdSec handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	crowdsecAppIface, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}
	h.crowdsec = crowdsecAppIface.(*crowdsec.CrowdSec)

	h.logger = ctx.Logger(h)

	return nil
}

// Validate ensures the app's configuration is valid.
func (h *Handler) Validate() error {
	if h.crowdsec == nil {
		return errors.New("crowdsec app not available")
	}

	return nil
}

// Cleanup cleans up resources when the module is being stopped.
func (h *Handler) Cleanup() error {
	if h.logger == nil {
		return nil
	}

	_ = h.logger.Sync()

	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var (
		ctx    = r.Context()
		ip     netip.Addr
		server = servername.FromContext(ctx)
		module = "http"
	)

	ctx, ip = httputils.EnsureIP(ctx)
	ctx = h.crowdsec.IncrementProcessedRequests(ctx, server, module, ip.Is6())
	r = r.WithContext(ctx)

	isAllowed, decision, err := h.crowdsec.IsAllowed(ctx, ip)
	if err != nil {
		return err // TODO: return error here? Or just log it and continue serving
	}

	// TODO: if the IP is allowed, should we (temporarily) put it in an explicit allowlist for quicker check?

	if !isAllowed {
		typ := "ban"
		value := ip.String()
		duration := ""
		origin := "unknown"
		if decision != nil {
			if decision.Type != nil {
				typ = *decision.Type
			}
			if decision.Value != nil {
				value = *decision.Value
			}
			if decision.Duration != nil {
				duration = *decision.Duration
			}
			if decision.Origin != nil {
				origin = *decision.Origin
			}
		}
		typ = strings.ToLower(strings.TrimSpace(typ))

		if typ == "captcha" {
			handled, err := h.handleCaptcha(w, r, ip, server, origin)
			if err != nil || handled {
				return err
			}
		} else {
			remediation := httputils.FallbackRemediation(typ)
			if err := httputils.WriteResponse(w, h.logger, typ, value, duration, 0, h.crowdsec.EnableCaddyError); err != nil {
				h.crowdsec.IncrementBlockedRequests(server, origin, remediation, ip.Is6())
				return err
			}

			h.crowdsec.IncrementBlockedRequests(server, origin, remediation, ip.Is6())
			return nil
		}
	}

	// A marked submission must never reach an upstream, even if the decision
	// expired between rendering and submitting the challenge.
	if h.crowdsec.IsCaptchaSubmission(r) {
		handled, err := h.handleCaptcha(w, r, ip, server, "crowdsec")
		if err != nil || handled {
			return err
		}
	}

	// Continue down the handler stack
	if err := next.ServeHTTP(w, r); err != nil {
		return err
	}

	return nil
}

func (h *Handler) handleCaptcha(w http.ResponseWriter, r *http.Request, ip netip.Addr, server, origin string) (bool, error) {
	outcome, err := h.crowdsec.HandleCaptcha(w, r, ip)
	switch outcome {
	case crowdsec.CaptchaOutcomeChallenge:
		h.logger.Debug("serving CAPTCHA challenge", zap.String("ip", ip.String()), zap.String("origin", origin))
		h.crowdsec.IncrementBlockedRequests(server, origin, "captcha", ip.Is6())
		return true, err
	case crowdsec.CaptchaOutcomeSolved:
		h.logger.Debug("CAPTCHA proof accepted", zap.String("ip", ip.String()), zap.String("origin", origin))
		return true, err
	case crowdsec.CaptchaOutcomeBypass:
		return false, err
	case crowdsec.CaptchaOutcomeUnavailable, crowdsec.CaptchaOutcomeFallback:
		if err != nil {
			h.logger.Debug("CAPTCHA verification failed; applying ban fallback", zap.Error(err))
		}
	default:
		h.logger.Warn("CAPTCHA returned an unknown outcome; applying ban fallback", zap.String("outcome", outcome.String()))
	}

	writeErr := httputils.WriteResponse(w, h.logger, "captcha", ip.String(), "", 0, h.crowdsec.EnableCaddyError)
	h.crowdsec.IncrementBlockedRequests(server, origin, "ban", ip.Is6())
	return true, writeErr
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// parseCaddyfileHandlerDirective parses the `crowdsec` Caddyfile directive
func parseCaddyfileHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
