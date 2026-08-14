package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"
)

const (
	// CookieName is the host-only cookie managed by Service.
	CookieName = "crowdsec_captcha"

	// Version 2 replaces the encoded return URI with an opaque pending-only tag.
	cookieVersion       = 2
	maximumCookieBytes  = 4096
	maximumBindingBytes = 512
	allowedClockSkew    = time.Minute
)

type cookieState string

const (
	cookieStatePending cookieState = "pending"
	cookieStatePassed  cookieState = "passed"
)

type cookieClaims struct {
	Version   int         `json:"v"`
	State     cookieState `json:"s"`
	Host      string      `json:"h"`
	IP        string      `json:"ip"`
	IssuedAt  int64       `json:"iat"`
	ExpiresAt int64       `json:"exp"`
	Binding   string      `json:"b"`
	ReturnTag string      `json:"rt,omitempty"`
}

func (s *Service) newCookie(
	r *http.Request,
	state cookieState,
	host string,
	info RequestInfo,
	pendingReturnURI string,
) (*http.Cookie, error) {
	now := s.clock.Now().UTC()
	lifetime := defaultPendingExpiration
	if state == cookieStatePassed {
		lifetime = s.passedExpiration
	}
	expires := now.Add(lifetime)

	claims := cookieClaims{
		Version:   cookieVersion,
		State:     state,
		Host:      host,
		IP:        info.ClientIP.String(),
		IssuedAt:  now.Unix(),
		ExpiresAt: expires.Unix(),
		Binding:   s.bindingTag(info.Binding),
	}
	if state == cookieStatePending {
		claims.ReturnTag = s.returnURITag(pendingReturnURI)
	}
	value, err := s.signClaims(claims)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	}, nil
}

func (s *Service) signClaims(claims cookieClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte(encodedPayload))
	encodedMAC := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	value := encodedPayload + "." + encodedMAC
	if len(value) > maximumCookieBytes {
		return "", errCookieTooLarge
	}

	return value, nil
}

func (s *Service) readClaims(r *http.Request, host string, info RequestInfo) (cookieClaims, bool) {
	var value string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == CookieName {
			value = cookie.Value
			count++
		}
	}
	if count != 1 || len(value) == 0 || len(value) > maximumCookieBytes {
		return cookieClaims{}, false
	}

	claims, ok := s.verifyClaims(value)
	if !ok || claims.Version != cookieVersion || claims.Host != host {
		return cookieClaims{}, false
	}
	claimIP, err := netip.ParseAddr(claims.IP)
	if err != nil || claimIP != info.ClientIP {
		return cookieClaims{}, false
	}
	if subtle.ConstantTimeCompare([]byte(claims.Binding), []byte(s.bindingTag(info.Binding))) != 1 {
		return cookieClaims{}, false
	}
	now := s.clock.Now().UTC()
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if issuedAt.After(now.Add(allowedClockSkew)) || !expiresAt.After(now) || expiresAt.Before(issuedAt) {
		return cookieClaims{}, false
	}

	var maximumLifetime time.Duration
	switch claims.State {
	case cookieStatePending:
		if !validReturnTag(claims.ReturnTag) {
			return cookieClaims{}, false
		}
		maximumLifetime = defaultPendingExpiration
	case cookieStatePassed:
		if claims.ReturnTag != "" {
			return cookieClaims{}, false
		}
		maximumLifetime = s.passedExpiration
	default:
		return cookieClaims{}, false
	}
	if expiresAt.Sub(issuedAt) > maximumLifetime+allowedClockSkew {
		return cookieClaims{}, false
	}

	return claims, true
}

func (s *Service) verifyClaims(value string) (cookieClaims, bool) {
	dot := -1
	for i := range value {
		if value[i] == '.' {
			if dot != -1 {
				return cookieClaims{}, false
			}
			dot = i
		}
	}
	if dot <= 0 || dot == len(value)-1 {
		return cookieClaims{}, false
	}

	encodedPayload, encodedMAC := value[:dot], value[dot+1:]
	providedMAC, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return cookieClaims{}, false
	}
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte(encodedPayload))
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return cookieClaims{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return cookieClaims{}, false
	}
	var claims cookieClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return cookieClaims{}, false
	}

	return claims, true
}

func (s *Service) bindingTag(binding string) string {
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte("crowdsec-captcha-binding\x00"))
	_, _ = mac.Write([]byte(s.profileBinding))
	_, _ = mac.Write([]byte("\x00"))
	_, _ = mac.Write([]byte(binding))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) returnURITag(returnURI string) string {
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte("crowdsec-captcha-return-uri\x00"))
	_, _ = mac.Write([]byte(returnURI))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validReturnTag(tag string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(tag)
	return err == nil && len(decoded) == sha256.Size
}
