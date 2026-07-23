package traefik_auth_bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSignedCookie(t *testing.T) {
	middleware := &CookieAuth{
		signingKey: []byte("01234567890123456789012345678901"),
	}

	value := middleware.newCookieValue("service.example.org", time.Now().Add(time.Hour).Unix())
	if !middleware.validCookie(value, "service.example.org", time.Now()) {
		t.Fatal("newly created cookie was rejected")
	}
	if middleware.validCookie(value+"A", "service.example.org", time.Now()) {
		t.Fatal("tampered cookie was accepted")
	}

	expired := middleware.newCookieValue("service.example.org", time.Now().Add(-time.Second).Unix())
	if middleware.validCookie(expired, "service.example.org", time.Now()) {
		t.Fatal("expired cookie was accepted")
	}
}

func TestHostnameIsolation(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	middleware := &CookieAuth{signingKey: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	value := middleware.newCookieValue("first.example.org", expires)

	if middleware.validCookie(value, "second.example.org", time.Now()) {
		t.Fatal("cookie from another hostname was accepted")
	}
}

func TestSigningKeyIsolation(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	first := &CookieAuth{signingKey: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	second := &CookieAuth{signingKey: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}
	value := first.newCookieValue("service.example.org", expires)

	if second.validCookie(value, "service.example.org", time.Now()) {
		t.Fatal("cookie signed by another middleware key was accepted")
	}
}

func TestLegacyCookieIsRejected(t *testing.T) {
	middleware := &CookieAuth{signingKey: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	if middleware.validCookie("v1.4102444800.invalid", "service.example.org", time.Now()) {
		t.Fatal("legacy v1 cookie was accepted")
	}
}

func TestCanonicalHostname(t *testing.T) {
	for authority, want := range map[string]string{
		"Service.Example.Org":      "service.example.org",
		"service.example.org.":     "service.example.org",
		"service.example.org:8443": "service.example.org",
		"[2001:db8::1]:443":        "2001:db8::1",
	} {
		got, err := canonicalHostname(authority)
		if err != nil {
			t.Errorf("canonicalHostname(%q): %v", authority, err)
		} else if got != want {
			t.Errorf("canonicalHostname(%q)=%q, want %q", authority, got, want)
		}
	}

	for _, authority := range []string{"", "user@example.org", "example.org/path", "example.org:invalid"} {
		if _, err := canonicalHostname(authority); err == nil {
			t.Errorf("canonicalHostname(%q) unexpectedly succeeded", authority)
		}
	}
}

func TestAuthorizationRedirectUsesConfiguredParameter(t *testing.T) {
	keyFile, err := os.CreateTemp(t.TempDir(), "master-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyFile.Write([]byte("01234567890123456789012345678901")); err != nil {
		t.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatal(err)
	}

	config := CreateConfig()
	config.MasterKeyFile = keyFile.Name()
	config.AuthorizationURL = "https://login.example.net/authorize?prompt=login"
	config.ReturnURLParameter = "return_to"
	config.RedeemURL = "https://login.example.net/redeem"

	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must not be called")
	}), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://service.example.org/private?q=1", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", response.Code)
	}
	location := response.Header().Get("Location")
	if !strings.Contains(location, "return_to=https%3A%2F%2Fservice.example.org%2Fprivate%3Fq%3D1") {
		t.Fatalf("configured return parameter missing from %q", location)
	}
	if !strings.Contains(location, "prompt=login") {
		t.Fatalf("existing authorization URL query was not preserved: %q", location)
	}
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	state := parsedLocation.Query().Get("state")
	if state == "" {
		t.Fatal("authorization redirect does not contain state")
	}
	var stateCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == handler.(*CookieAuth).stateCookieNameFor(state) {
			stateCookie = cookie
		}
	}
	if stateCookie == nil || stateCookie.Value != state {
		t.Fatal("state cookie does not match redirect state")
	}
	if stateCookie.MaxAge != 300 {
		t.Fatalf("state cookie MaxAge=%d, want 300", stateCookie.MaxAge)
	}
}

func TestInvalidRequestHostIsRejected(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"

	upstreamCalled := false
	handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalled = true
	}), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://service.example.org/", nil)
	request.Host = ""
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || upstreamCalled {
		t.Fatalf("status=%d upstreamCalled=%v", response.Code, upstreamCalled)
	}
	if response.Header().Get("Location") != "" || len(response.Result().Cookies()) != 0 {
		t.Fatal("invalid host produced a redirect or cookie")
	}
}

func TestSessionCookieIsBoundToCanonicalRequestHostname(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"

	upstreamCalls := 0
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusNoContent)
	}), config, "test")
	if err != nil {
		t.Fatal(err)
	}
	middleware := handler.(*CookieAuth)
	value := middleware.newCookieValue("service.example.org", time.Now().Add(time.Hour).Unix())

	sameHostRequest := httptest.NewRequest(http.MethodGet, "https://service.example.org/", nil)
	sameHostRequest.Host = "SERVICE.EXAMPLE.ORG.:8443"
	sameHostRequest.AddCookie(&http.Cookie{Name: config.CookieName, Value: value})
	sameHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(sameHostResponse, sameHostRequest)
	if sameHostResponse.Code != http.StatusNoContent {
		t.Fatalf("canonical equivalent host returned %d, want 204", sameHostResponse.Code)
	}

	otherHostRequest := httptest.NewRequest(http.MethodGet, "https://other.example.org/", nil)
	otherHostRequest.AddCookie(&http.Cookie{Name: config.CookieName, Value: value})
	otherHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherHostResponse, otherHostRequest)
	if otherHostResponse.Code != http.StatusFound {
		t.Fatalf("different host returned %d, want 302", otherHostResponse.Code)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream called %d times, want 1", upstreamCalls)
	}
}

func TestInlineMasterKey(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = "https://login.example.net/redeem"

	if _, err := New(context.Background(), http.NotFoundHandler(), config, "test"); err != nil {
		t.Fatalf("inline master key was rejected: %v", err)
	}
}

func TestRedeemURLDefaultsToAuthorizationURL(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize?prompt=login"

	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := handler.(*CookieAuth).redeemURL; got != config.AuthorizationURL {
		t.Fatalf("redeemURL=%q, want %q", got, config.AuthorizationURL)
	}
}

func TestMasterKeySourcesAreMutuallyExclusive(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.MasterKeyFile = "/run/secrets/master-key"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = "https://login.example.net/redeem"

	if _, err := New(context.Background(), http.NotFoundHandler(), config, "test"); err == nil {
		t.Fatal("configuration with both master key sources was accepted")
	}
}

func TestProtectedPathOnlyAuthenticatesConfiguredSubtree(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = "https://login.example.net/redeem"
	config.ProtectedPath = "/admin"

	upstreamCalls := 0
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusNoContent)
	}), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/admin", "/admin?test=1", "/admin/users"} {
		request := httptest.NewRequest(http.MethodGet, "https://service.example.org"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusFound {
			t.Errorf("%s returned %d, want 302", path, response.Code)
		}
	}

	for _, path := range []string{"/", "/administrator", "/favicon.ico"} {
		request := httptest.NewRequest(http.MethodGet, "https://service.example.org"+path, nil)
		request.AddCookie(&http.Cookie{Name: config.CookieName, Value: "invalid"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s returned %d, want 204", path, response.Code)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Errorf("%s created cookies outside the protected path", path)
		}
	}

	if upstreamCalls != 3 {
		t.Fatalf("upstream called %d times, want 3", upstreamCalls)
	}
}

func TestProtectedPathValidationAndNormalization(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = "https://login.example.net/redeem"
	config.ProtectedPath = "admin"
	if _, err := New(context.Background(), http.NotFoundHandler(), config, "test"); err == nil {
		t.Fatal("protectedPath without a leading slash was accepted")
	}

	config.ProtectedPath = "/admin///"
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}
	middleware := handler.(*CookieAuth)
	if middleware.protectedPath != "/admin" || middleware.protectedPathPrefix != "/admin/" {
		t.Fatalf("protected path normalized to %q with prefix %q", middleware.protectedPath, middleware.protectedPathPrefix)
	}
}

func TestCallbackRedeemsStateAndCreatesSession(t *testing.T) {
	redeemServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Error(err)
		}
		if req.Form.Get("code") != "one-time-code" {
			t.Errorf("unexpected code: %q", req.Form.Get("code"))
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"active":true,"rd":"https://service.example.org/private","state":"browser-state"}`))
	}))
	defer redeemServer.Close()

	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = redeemServer.URL
	config.ProtectedPath = "/private"
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://service.example.org/_auth/callback?code=one-time-code&state=browser-state", nil)
	stateCookieName := handler.(*CookieAuth).stateCookieNameFor("browser-state")
	request.AddCookie(&http.Cookie{Name: stateCookieName, Value: "browser-state"})
	otherStateCookieName := handler.(*CookieAuth).stateCookieNameFor("other-browser-state")
	request.AddCookie(&http.Cookie{Name: otherStateCookieName, Value: "other-browser-state"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", response.Code, response.Body.String())
	}
	var sessionCreated, stateCleared, otherStateCleared bool
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == config.CookieName && strings.HasPrefix(cookie.Value, "v2.") {
			sessionCreated = true
		}
		if cookie.Name == stateCookieName && cookie.MaxAge < 0 {
			stateCleared = true
		}
		if cookie.Name == otherStateCookieName && cookie.MaxAge < 0 {
			otherStateCleared = true
		}
	}
	if !sessionCreated || !stateCleared || otherStateCleared {
		t.Fatalf("sessionCreated=%v stateCleared=%v otherStateCleared=%v", sessionCreated, stateCleared, otherStateCleared)
	}
}

func TestAuthenticatedCallbackIgnoresInvalidState(t *testing.T) {
	redeemCalled := false
	redeemServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redeemCalled = true
	}))
	defer redeemServer.Close()

	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = redeemServer.URL
	config.ProtectedPath = "/private"
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}
	middleware := handler.(*CookieAuth)

	request := httptest.NewRequest(http.MethodGet, "https://service.example.org/_auth/callback?code=stale-code&state=invalid-state", nil)
	request.AddCookie(&http.Cookie{Name: config.CookieName, Value: middleware.newCookieValue("service.example.org", time.Now().Add(time.Hour).Unix())})
	unrelatedStateCookieName := middleware.stateCookieNameFor("other-browser-state")
	request.AddCookie(&http.Cookie{Name: unrelatedStateCookieName, Value: "other-browser-state"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != config.ProtectedPath || redeemCalled {
		t.Fatalf("status=%d location=%q redeemCalled=%v", response.Code, response.Header().Get("Location"), redeemCalled)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == unrelatedStateCookieName && cookie.MaxAge < 0 {
			t.Fatal("authenticated callback cleared an unrelated state cookie")
		}
	}
}

func TestCallbackRejectsBrowserStateMismatchBeforeRedeem(t *testing.T) {
	redeemCalled := false
	redeemServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redeemCalled = true
	}))
	defer redeemServer.Close()

	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = redeemServer.URL
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://service.example.org/_auth/callback?code=one-time-code&state=attacker-state", nil)
	validStateCookieName := handler.(*CookieAuth).stateCookieNameFor("browser-state")
	request.AddCookie(&http.Cookie{Name: validStateCookieName, Value: "browser-state"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || redeemCalled {
		t.Fatalf("status=%d redeemCalled=%v", response.Code, redeemCalled)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == validStateCookieName && cookie.MaxAge < 0 {
			t.Fatal("mismatched callback cleared an unrelated state cookie")
		}
	}
}

func TestConcurrentAuthorizationRequestsUseDifferentStateCookies(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = "https://login.example.net/redeem"

	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	stateCookies := make(map[string]string)
	for _, path := range []string{"/private", "/favicon.ico"} {
		request := httptest.NewRequest(http.MethodGet, "https://service.example.org"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		cookies := response.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("%s produced %d cookies, want 1", path, len(cookies))
		}
		stateCookies[cookies[0].Name] = cookies[0].Value
	}

	if len(stateCookies) != 2 {
		t.Fatalf("concurrent requests produced %d distinct state cookies, want 2", len(stateCookies))
	}
	for name, state := range stateCookies {
		if name != handler.(*CookieAuth).stateCookieNameFor(state) {
			t.Fatalf("cookie %q does not match its state", name)
		}
	}
}

func TestCallbackRejectsLegacyStateCookie(t *testing.T) {
	config := CreateConfig()
	config.MasterKey = "01234567890123456789012345678901"
	config.AuthorizationURL = "https://login.example.net/authorize"
	config.RedeemURL = "https://login.example.net/redeem"
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://service.example.org/_auth/callback?code=one-time-code&state=browser-state", nil)
	request.AddCookie(&http.Cookie{Name: config.StateCookieName, Value: "browser-state"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("legacy state cookie returned status %d, want 401", response.Code)
	}
}
