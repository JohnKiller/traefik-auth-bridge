// Package authbridge provides an authorization portal bridge for Traefik.
package traefik_auth_bridge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
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
	SessionCookie              bool   `json:"sessionCookie,omitempty"`
	MasterKey                  string `json:"masterKey,omitempty"`
	MasterKeyFile              string `json:"masterKeyFile,omitempty"`
	AuthorizationURL           string `json:"authorizationURL,omitempty"`
	ReturnURLParameter         string `json:"returnURLParameter,omitempty"`
	StateParameter             string `json:"stateParameter,omitempty"`
	StateCookieName            string `json:"stateCookieName,omitempty"`
	StateTTL                   int    `json:"stateTTL,omitempty"`
	ProtectedPath              string `json:"protectedPath,omitempty"`
	CallbackPath               string `json:"callbackPath,omitempty"`
	AuthorizationCodeParameter string `json:"authorizationCodeParameter,omitempty"`
	RedeemURL                  string `json:"redeemURL,omitempty"`
	RedeemCodeParameter        string `json:"redeemCodeParameter,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CookieName:                 "__Host-traefik-auth",
		CookieTTL:                  86400,
		SessionCookie:              true,
		ReturnURLParameter:         "rd",
		StateParameter:             "state",
		StateCookieName:            "__Host-traefik-auth-state",
		StateTTL:                   300,
		ProtectedPath:              "/",
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
	sessionCookie              bool
	signingKey                 []byte
	authorizationURL           *url.URL
	returnURLParameter         string
	stateParameter             string
	stateCookieName            string
	stateTTL                   int
	protectedPath              string
	protectedPathPrefix        string
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
	if config.StateParameter == "" {
		return nil, fmt.Errorf("stateParameter is required")
	}
	if config.StateCookieName == "" {
		return nil, fmt.Errorf("stateCookieName is required")
	}
	if config.StateTTL <= 0 {
		return nil, fmt.Errorf("stateTTL must be greater than zero")
	}
	if config.ProtectedPath == "" || config.ProtectedPath[0] != '/' {
		return nil, fmt.Errorf("protectedPath must start with /")
	}
	if config.CallbackPath == "" || config.CallbackPath[0] != '/' {
		return nil, fmt.Errorf("callbackPath must start with /")
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
	if config.MasterKey == "" && config.MasterKeyFile == "" {
		return nil, fmt.Errorf("one of masterKey or masterKeyFile is required")
	}
	if config.MasterKey != "" && config.MasterKeyFile != "" {
		return nil, fmt.Errorf("masterKey and masterKeyFile are mutually exclusive")
	}

	masterKey := []byte(config.MasterKey)
	if config.MasterKeyFile != "" {
		var err error
		masterKey, err = os.ReadFile(config.MasterKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read master key: %w", err)
		}
	}
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("master key must contain at least 32 bytes")
	}
	keyDerivation := hmac.New(sha256.New, masterKey)
	keyDerivation.Write([]byte("traefik-cookie-auth:key:v3"))
	signingKey := keyDerivation.Sum(nil)

	authorizationURL, err := url.Parse(config.AuthorizationURL)
	if err != nil || authorizationURL.Scheme == "" || authorizationURL.Host == "" {
		return nil, fmt.Errorf("authorizationURL must be an absolute URL")
	}
	redeemURL := config.RedeemURL
	if redeemURL == "" {
		redeemURL = config.AuthorizationURL
	}
	protectedPath := strings.TrimRight(config.ProtectedPath, "/")
	if protectedPath == "" {
		protectedPath = "/"
	}
	protectedPathPrefix := protectedPath
	if protectedPath != "/" {
		protectedPathPrefix += "/"
	}

	return &CookieAuth{
		next:                       next,
		cookieName:                 config.CookieName,
		cookieTTL:                  config.CookieTTL,
		sessionCookie:              config.SessionCookie,
		signingKey:                 signingKey,
		authorizationURL:           authorizationURL,
		returnURLParameter:         config.ReturnURLParameter,
		stateParameter:             config.StateParameter,
		stateCookieName:            config.StateCookieName,
		stateTTL:                   config.StateTTL,
		protectedPath:              protectedPath,
		protectedPathPrefix:        protectedPathPrefix,
		callbackPath:               config.CallbackPath,
		authorizationCodeParameter: config.AuthorizationCodeParameter,
		redeemURL:                  redeemURL,
		redeemCodeParameter:        config.RedeemCodeParameter,
		httpClient:                 &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// ServeHTTP allows authenticated requests and redirects all others to login.
func (m *CookieAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Reserve the entire namespace, including on unprotected routes.
	for name := range req.Header {
		// CGI backends can map hyphens, underscores and dots to the same name.
		normalized := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(name), "_", "-"), ".", "-")
		if strings.HasPrefix(normalized, "x-auth-") {
			delete(req.Header, name)
		}
	}
	hostname, err := canonicalHostname(req.Host)
	if err != nil {
		http.Error(rw, "invalid request host", http.StatusBadRequest)
		return
	}

	if req.URL.Path == m.callbackPath {
		if m.hasValidSession(req, hostname, time.Now()) {
			m.handleAuthenticatedCallback(rw, req)
			return
		}
		m.handleCallback(rw, req, hostname)
		return
	}
	if m.protectedPath != "/" && req.URL.Path != m.protectedPath && !strings.HasPrefix(req.URL.Path, m.protectedPathPrefix) {
		m.next.ServeHTTP(rw, req)
		return
	}

	if claims, valid := m.sessionClaims(req, hostname, time.Now()); valid {
		for name, value := range claims {
			encoded, _ := json.Marshal(value)
			req.Header.Set(claimHeaderName(name), string(encoded))
		}
		m.next.ServeHTTP(rw, req)
		return
	}

	originalScheme := "http"
	if req.TLS != nil {
		originalScheme = "https"
	}
	originalURL := originalScheme + "://" + req.Host + req.URL.RequestURI()
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(rw, "unable to start authorization", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	redirectURL := *m.authorizationURL
	query := redirectURL.Query()
	query.Set(m.returnURLParameter, originalURL)
	query.Set(m.stateParameter, state)
	redirectURL.RawQuery = query.Encode()

	http.SetCookie(rw, &http.Cookie{
		Name:     m.stateCookieNameFor(state),
		Value:    state,
		Path:     "/",
		MaxAge:   m.stateTTL,
		Expires:  time.Now().Add(time.Duration(m.stateTTL) * time.Second).UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}

func (m *CookieAuth) hasValidSession(req *http.Request, hostname string, now time.Time) bool {
	_, valid := m.sessionClaims(req, hostname, now)
	return valid
}

func (m *CookieAuth) sessionClaims(req *http.Request, hostname string, now time.Time) (map[string]json.RawMessage, bool) {
	cookie, err := req.Cookie(m.cookieName)
	if err != nil {
		return nil, false
	}
	return m.decodeCookie(cookie.Value, hostname, now)
}

func (m *CookieAuth) validCookie(value, hostname string, now time.Time) bool {
	_, valid := m.decodeCookie(value, hostname, now)
	return valid
}

func (m *CookieAuth) decodeCookie(value, hostname string, now time.Time) (map[string]json.RawMessage, bool) {
	parts := strings.Split(value, ".")
	if len(value) > 3800 || len(parts) != 4 || parts[0] != "v3" {
		return nil, false
	}
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || expiresAt <= now.Unix() {
		return nil, false
	}
	suppliedMAC, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, false
	}
	if !hmac.Equal(suppliedMAC, m.cookieMAC(hostname, parts[1], parts[2])) {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || claims == nil || !validClaims(claims) {
		return nil, false
	}
	return claims, true
}

// JSON keys must map unambiguously to case-insensitive HTTP header names.
func claimHeaderName(name string) string {
	return "X-Auth-" + strings.ReplaceAll(name, "_", "-")
}

func validClaims(claims map[string]json.RawMessage) bool {
	seen := make(map[string]bool)
	for name := range claims {
		lower := strings.ToLower(claimHeaderName(name))
		if name == "" || seen[lower] {
			return false
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
		seen[lower] = true
	}
	return true
}

func (m *CookieAuth) cookieMAC(hostname, expiresAt, payload string) []byte {
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte("traefik-cookie-auth:cookie:v3:" + hostname + ":" + expiresAt + ":" + payload))
	return mac.Sum(nil)
}

func (m *CookieAuth) newCookieValue(hostname string, expiresAt int64, claims ...map[string]json.RawMessage) string {
	expires := strconv.FormatInt(expiresAt, 10)
	data := []byte("{}")
	if len(claims) > 0 {
		data, _ = json.Marshal(claims[0])
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	return "v3." + expires + "." + payload + "." + base64.RawURLEncoding.EncodeToString(m.cookieMAC(hostname, expires, payload))
}

func (m *CookieAuth) handleCallback(rw http.ResponseWriter, req *http.Request, hostname string) {
	code := req.URL.Query().Get(m.authorizationCodeParameter)
	if code == "" {
		http.Error(rw, "missing authorization code", http.StatusUnauthorized)
		return
	}
	callbackState := req.URL.Query().Get(m.stateParameter)
	if callbackState == "" {
		http.Error(rw, "invalid authorization state", http.StatusUnauthorized)
		return
	}
	stateCookieName := m.stateCookieNameFor(callbackState)
	stateCookie, err := req.Cookie(stateCookieName)
	if err != nil || !hmac.Equal([]byte(callbackState), []byte(stateCookie.Value)) {
		if err == nil {
			m.clearStateCookie(rw, stateCookieName)
		}
		http.Error(rw, "invalid authorization state", http.StatusUnauthorized)
		return
	}
	m.clearStateCookie(rw, stateCookieName)

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
		State  string `json:"state"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	var claims map[string]json.RawMessage
	if err != nil || len(body) > 8192 || json.Unmarshal(body, &grant) != nil || !grant.Active || json.Unmarshal(body, &claims) != nil {
		http.Error(rw, "invalid authorization response", http.StatusBadGateway)
		return
	}
	if !hmac.Equal([]byte(grant.State), []byte(callbackState)) {
		http.Error(rw, "authorization state mismatch", http.StatusUnauthorized)
		return
	}
	parsed, err := url.Parse(grant.RD)
	if err != nil || parsed.Scheme != "https" || parsed.Host != req.Host {
		http.Error(rw, "invalid redirect destination", http.StatusUnauthorized)
		return
	}

	delete(claims, "active")
	delete(claims, "rd")
	delete(claims, "state")
	if !validClaims(claims) {
		http.Error(rw, "invalid authorization claims", http.StatusBadGateway)
		return
	}
	cookie := m.newSessionCookie(hostname, time.Now(), claims)
	if len(cookie.Value) > 3800 || len(cookie.String()) > 4096 {
		http.Error(rw, "authorization claims exceed cookie size limit", http.StatusBadGateway)
		return
	}
	http.SetCookie(rw, cookie)
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, grant.RD, http.StatusSeeOther)
}

func (m *CookieAuth) newSessionCookie(hostname string, now time.Time, claims ...map[string]json.RawMessage) *http.Cookie {
	expiresAt := now.Add(time.Duration(m.cookieTTL) * time.Second)
	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    m.newCookieValue(hostname, expiresAt.Unix(), claims...),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if !m.sessionCookie {
		cookie.MaxAge = m.cookieTTL
		cookie.Expires = expiresAt.UTC()
	}
	return cookie
}

func canonicalHostname(authority string) (string, error) {
	if authority == "" {
		return "", fmt.Errorf("host is empty")
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.Host != authority || parsed.User != nil {
		return "", fmt.Errorf("host is malformed")
	}
	hostname := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if hostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}
	return hostname, nil
}

func (m *CookieAuth) handleAuthenticatedCallback(rw http.ResponseWriter, req *http.Request) {
	callbackState := req.URL.Query().Get(m.stateParameter)
	if callbackState != "" {
		stateCookieName := m.stateCookieNameFor(callbackState)
		stateCookie, err := req.Cookie(stateCookieName)
		if err == nil && hmac.Equal([]byte(callbackState), []byte(stateCookie.Value)) {
			m.clearStateCookie(rw, stateCookieName)
		}
	}
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, m.protectedPath, http.StatusSeeOther)
}

func (m *CookieAuth) stateCookieNameFor(state string) string {
	digest := sha256.Sum256([]byte(state))
	return m.stateCookieName + "-" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func (m *CookieAuth) clearStateCookie(rw http.ResponseWriter, name string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
