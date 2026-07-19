package traefik_auth_bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSignedCookie(t *testing.T) {
	middleware := &CookieAuth{
		serviceID:  "service-a",
		signingKey: []byte("01234567890123456789012345678901"),
	}

	value := middleware.newCookieValue(time.Now().Add(time.Hour).Unix())
	if !middleware.validCookie(value, time.Now()) {
		t.Fatal("newly created cookie was rejected")
	}
	if middleware.validCookie(value+"A", time.Now()) {
		t.Fatal("tampered cookie was accepted")
	}

	expired := middleware.newCookieValue(time.Now().Add(-time.Second).Unix())
	if middleware.validCookie(expired, time.Now()) {
		t.Fatal("expired cookie was accepted")
	}
}

func TestServiceKeyIsolation(t *testing.T) {
	expires := time.Now().Add(time.Hour).Unix()
	first := &CookieAuth{serviceID: "service-a", signingKey: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}
	second := &CookieAuth{serviceID: "service-b", signingKey: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")}

	if second.validCookie(first.newCookieValue(expires), time.Now()) {
		t.Fatal("cookie from another service was accepted")
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
	config.ServiceID = "service-a"
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
}
