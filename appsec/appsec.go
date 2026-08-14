// Copyright 2024 Herman Slatman
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

package appsec

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

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/core"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/servername"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("appsec", parseCaddyfileHandlerDirective)
}

// Handler checks the CrowdSec AppSec component decided whether
// an HTTP request is blocked or not.
type Handler struct {
	logger   *zap.Logger
	crowdsec *crowdsec.CrowdSec
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.appsec",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the CrowdSec AppSec handler.
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

	_ = h.logger.Sync() // nolint

	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var (
		ctx    = r.Context()
		ip     netip.Addr
		server = servername.FromContext(ctx)
		module = "appsec"
	)

	ctx, ip = httputils.EnsureIP(ctx)
	ctx = h.crowdsec.IncrementProcessedRequests(ctx, server, module, ip.Is6())

	r = r.WithContext(ctx)

	// CAPTCHA submissions are internal control requests. Validate them before
	// AppSec so provider tokens and signed state cookies are never forwarded to
	// the AppSec endpoint. The resulting redirect is checked normally again.
	if h.crowdsec.IsCaptchaSubmission(r) {
		handled, err := h.handleCaptcha(w, r, ip, server, module, 0)
		if err != nil || handled {
			return err
		}
	}

	if err := h.crowdsec.CheckRequest(ctx, r); err != nil {
		a := &core.AppSecError{}
		if !errors.As(err, &a) {
			return err
		}

		switch {
		case strings.EqualFold(strings.TrimSpace(a.Action), "captcha"):
			handled, err := h.handleCaptcha(w, r, ip, server, module, a.StatusCode)
			if err != nil || handled {
				return err
			}
		case a.Action == "allow":
			// nothing to do
			h.crowdsec.IncrementBlockedRequests(server, module, "bypass", ip.Is6()) // TODO: properly set the action that was performed
		case a.Action == "log":
			h.logger.Info("appsec rule triggered", zap.String("ip", ip.String()), zap.String("action", a.Action))
			h.crowdsec.IncrementBlockedRequests(server, module, "log", ip.Is6()) // TODO: properly set the action that was performed
		default:
			if err := httputils.WriteResponse(w, h.logger, a.Action, ip.String(), a.Duration, a.StatusCode, h.crowdsec.EnableCaddyError); err != nil {
				h.crowdsec.IncrementBlockedRequests(server, module, a.Action, ip.Is6()) // TODO: properly set the action that was performed
				return err
			}

			h.crowdsec.IncrementBlockedRequests(server, module, a.Action, ip.Is6()) // TODO: properly set the action that was performed
			return nil
		}
	}

	// Continue down the handler stack
	if err := next.ServeHTTP(w, r); err != nil {
		return err
	}

	return nil
}

func (h *Handler) handleCaptcha(
	w http.ResponseWriter,
	r *http.Request,
	ip netip.Addr,
	server string,
	origin string,
	statusCode int,
) (bool, error) {
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

	writeErr := httputils.WriteResponse(w, h.logger, "captcha", ip.String(), "", statusCode, h.crowdsec.EnableCaddyError)
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
)
