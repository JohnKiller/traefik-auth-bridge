// Package authbridge provides an authorization portal bridge for Traefik.
package traefik_auth_bridge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains the middleware configuration exposed through Traefik.
type Config struct {
	CookieName                 string `json:"cookieName,omitempty"`
	CookieTTL                  int    `json:"cookieTTL,omitempty"`
	ServiceID                  string `json:"serviceID,omitempty"`
	MasterKeyFile              string `json:"masterKeyFile,omitempty"`
	AuthorizationURL           string `json:"authorizationURL,omitempty"`
	ReturnURLParameter         string `json:"returnURLParameter,omitempty"`
	CallbackPath               string `json:"callbackPath,omitempty"`
	AuthorizationCodeParameter string `json:"authorizationCodeParameter,omitempty"`
	RedeemURL                  string `json:"redeemURL,omitempty"`
	RedeemCodeParameter        string `json:"redeemCodeParameter,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CookieName:                 "__Host-traefik-auth",
		CookieTTL:                  3600,
		ReturnURLParameter:         "rd",
		CallbackPath:               "/_auth/callback",
		AuthorizationCodeParameter: "code",
		RedeemCodeParameter:        "code",
	}
}

// CookieAuth checks a request cookie before invoking the next handler.
type CookieAuth struct {
	next                       http.Handler
	cookieName                 string
	cookieTTL                  int
	serviceID                  string
	signingKey                 []byte
	authorizationURL           *url.URL
	returnURLParameter         string
	callbackPath               string
	authorizationCodeParameter string
	redeemURL                  string
	redeemCodeParameter        string
	httpClient                 *http.Client
}

// New creates the middleware.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if config.CookieName == "" {
		return nil, fmt.Errorf("cookieName is required")
	}
	if config.AuthorizationURL == "" {
		return nil, fmt.Errorf("authorizationURL is required")
	}
	if config.ReturnURLParameter == "" {
		return nil, fmt.Errorf("returnURLParameter is required")
	}
	if config.CallbackPath == "" || config.CallbackPath[0] != '/' {
		return nil, fmt.Errorf("callbackPath must start with /")
	}
	if config.RedeemURL == "" {
		return nil, fmt.Errorf("redeemURL is required")
	}
	if config.AuthorizationCodeParameter == "" {
		return nil, fmt.Errorf("authorizationCodeParameter is required")
	}
	if config.RedeemCodeParameter == "" {
		return nil, fmt.Errorf("redeemCodeParameter is required")
	}
	if config.CookieTTL <= 0 {
		return nil, fmt.Errorf("cookieTTL must be greater than zero")
	}
	if config.ServiceID == "" {
		return nil, fmt.Errorf("serviceID is required")
	}
	if config.MasterKeyFile == "" {
		return nil, fmt.Errorf("masterKeyFile is required")
	}
	masterKey, err := os.ReadFile(config.MasterKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("master key must contain at least 32 bytes")
	}
	keyDerivation := hmac.New(sha256.New, masterKey)
	keyDerivation.Write([]byte("traefik-cookie-auth:key:v1:" + config.ServiceID))
	signingKey := keyDerivation.Sum(nil)

	authorizationURL, err := url.Parse(config.AuthorizationURL)
	if err != nil || authorizationURL.Scheme == "" || authorizationURL.Host == "" {
		return nil, fmt.Errorf("authorizationURL must be an absolute URL")
	}

	return &CookieAuth{
		next:                       next,
		cookieName:                 config.CookieName,
		cookieTTL:                  config.CookieTTL,
		serviceID:                  config.ServiceID,
		signingKey:                 signingKey,
		authorizationURL:           authorizationURL,
		returnURLParameter:         config.ReturnURLParameter,
		callbackPath:               config.CallbackPath,
		authorizationCodeParameter: config.AuthorizationCodeParameter,
		redeemURL:                  config.RedeemURL,
		redeemCodeParameter:        config.RedeemCodeParameter,
		httpClient:                 &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// ServeHTTP allows authenticated requests and redirects all others to login.
func (m *CookieAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path == m.callbackPath {
		m.handleCallback(rw, req)
		return
	}

	cookie, err := req.Cookie(m.cookieName)
	if err == nil && m.validCookie(cookie.Value, time.Now()) {
		m.next.ServeHTTP(rw, req)
		return
	}

	originalScheme := "http"
	if req.TLS != nil {
		originalScheme = "https"
	}
	originalURL := originalScheme + "://" + req.Host + req.URL.RequestURI()

	redirectURL := *m.authorizationURL
	query := redirectURL.Query()
	query.Set(m.returnURLParameter, originalURL)
	redirectURL.RawQuery = query.Encode()

	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}

func (m *CookieAuth) validCookie(value string, now time.Time) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || expiresAt <= now.Unix() {
		return false
	}
	suppliedMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expectedMAC := m.cookieMAC(parts[1])
	return hmac.Equal(suppliedMAC, expectedMAC)
}

func (m *CookieAuth) cookieMAC(expiresAt string) []byte {
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte("traefik-cookie-auth:cookie:v1:" + m.serviceID + ":" + expiresAt))
	return mac.Sum(nil)
}

func (m *CookieAuth) newCookieValue(expiresAt int64) string {
	expires := strconv.FormatInt(expiresAt, 10)
	return "v1." + expires + "." + base64.RawURLEncoding.EncodeToString(m.cookieMAC(expires))
}

func (m *CookieAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get(m.authorizationCodeParameter)
	if code == "" {
		http.Error(rw, "missing authorization code", http.StatusUnauthorized)
		return
	}

	form := url.Values{}
	form.Set(m.redeemCodeParameter, code)
	redeemRequest, err := http.NewRequestWithContext(req.Context(), http.MethodPost, m.redeemURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(rw, "authorization service unavailable", http.StatusBadGateway)
		return
	}
	redeemRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := m.httpClient.Do(redeemRequest)
	if err != nil {
		http.Error(rw, "authorization service unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, response.Body)
		http.Error(rw, "invalid or expired authorization code", http.StatusUnauthorized)
		return
	}

	var grant struct {
		Active bool   `json:"active"`
		RD     string `json:"rd"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&grant); err != nil || !grant.Active {
		http.Error(rw, "invalid authorization response", http.StatusBadGateway)
		return
	}
	parsed, err := url.Parse(grant.RD)
	if err != nil || parsed.Scheme != "https" || parsed.Host != req.Host {
		http.Error(rw, "invalid redirect destination", http.StatusUnauthorized)
		return
	}

	expiresAt := time.Now().Add(time.Duration(m.cookieTTL) * time.Second)
	http.SetCookie(rw, &http.Cookie{
		Name:     m.cookieName,
		Value:    m.newCookieValue(expiresAt.Unix()),
		Path:     "/",
		MaxAge:   m.cookieTTL,
		Expires:  expiresAt.UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, grant.RD, http.StatusSeeOther)
}
