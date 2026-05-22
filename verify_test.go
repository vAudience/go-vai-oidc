package vaioidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test constants — no magic strings.
const (
	testRealm        = "test-realm"
	testClientID     = "test-client"
	testCallback     = "/cb"
	testKID          = "test-kid-1"
	testIssuerPath   = "/realms/" + testRealm
	jwksAlgRS256     = "RS256"
	jwksUse          = "sig"
	jwksKty          = "RSA"
	jwksHeaderType   = "JWT"
	wellKnownPath    = "/.well-known/openid-configuration"
	jwksRoutePath    = "/protocol/openid-connect/certs"
	testSub          = "user-sub-abc"
	testEmail        = "alice@example.com"
	testName         = "Alice Example"
	testExtraClaim   = "preferred_username"
	testExtraValue   = "alice"
	verifyTestTokenTTL = 5 * time.Minute
)

// newTestKeycloak boots an httptest server that serves OIDC discovery +
// a single-key JWKS using a fresh RSA-2048 key. The returned signer is
// used to mint test ID tokens.
func newTestKeycloak(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc(testIssuerPath+wellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL + testIssuerPath
		fmt.Fprintf(w, validDiscoveryDocTemplate, base, base, base, base, base, base)
	})

	mux.HandleFunc(testIssuerPath+jwksRoutePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc(key))
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, key
}

func jwksDoc(key *rsa.PrivateKey) map[string]any {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eb := make([]byte, 4)
	binary.BigEndian.PutUint32(eb, uint32(key.E))
	// strip leading zero bytes
	i := 0
	for i < len(eb)-1 && eb[i] == 0 {
		i++
	}
	e := base64.RawURLEncoding.EncodeToString(eb[i:])
	return map[string]any{
		"keys": []map[string]any{{
			"kty": jwksKty,
			"use": jwksUse,
			"alg": jwksAlgRS256,
			"kid": testKID,
			"n":   n,
			"e":   e,
		}},
	}
}

// signRS256 mints a compact JWS with the test signing key.
// `tamper` set to true mutates the signature so verification fails.
func signRS256(t *testing.T, key *rsa.PrivateKey, header, payload map[string]any, tamper bool) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 5, h[:]) // crypto.SHA256 == 5
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if tamper {
		sig[0] ^= 0xFF
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func tokenHeader() map[string]any {
	return map[string]any{
		"alg": jwksAlgRS256,
		"typ": jwksHeaderType,
		"kid": testKID,
	}
}

func tokenPayload(issuer, audience, sub string, exp time.Time, extra map[string]any) map[string]any {
	p := map[string]any{
		"iss": issuer,
		"aud": audience,
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func newTestAuth(t *testing.T, srv *httptest.Server) *Auth {
	t.Helper()
	sessionSecret := base64.StdEncoding.EncodeToString(bytes32())
	cfg := Config{
		KeycloakURL:    srv.URL,
		Realm:          testRealm,
		ClientID:       testClientID,
		ClientSecret:   "irrelevant",
		CallbackURL:    srv.URL + testCallback,
		SessionSecret:  sessionSecret,
		ExtraClaims:    []string{testExtraClaim},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		InsecureCookie: true,
	}
	a, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func bytes32() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func TestVerifyIDToken_HappyPath(t *testing.T) {
	srv, key := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	issuer := srv.URL + testIssuerPath
	token := signRS256(t, key, tokenHeader(),
		tokenPayload(issuer, testClientID, testSub, time.Now().Add(verifyTestTokenTTL),
			map[string]any{"email": testEmail, "name": testName, testExtraClaim: testExtraValue}),
		false)

	user, err := a.VerifyIDToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Sub != testSub {
		t.Errorf("Sub: got %q, want %q", user.Sub, testSub)
	}
	if user.Email != testEmail {
		t.Errorf("Email: got %q, want %q", user.Email, testEmail)
	}
	if user.Name != testName {
		t.Errorf("Name: got %q, want %q", user.Name, testName)
	}
	if user.Claims[testExtraClaim] != testExtraValue {
		t.Errorf("extra claim %s: got %q, want %q", testExtraClaim, user.Claims[testExtraClaim], testExtraValue)
	}
}

func TestVerifyIDToken_EmptyToken(t *testing.T) {
	srv, _ := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	_, err := a.VerifyIDToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, ErrTokenVerification) {
		t.Errorf("expected ErrTokenVerification, got %v", err)
	}
}

func TestVerifyIDToken_TamperedSignature(t *testing.T) {
	srv, key := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	issuer := srv.URL + testIssuerPath
	token := signRS256(t, key, tokenHeader(),
		tokenPayload(issuer, testClientID, testSub, time.Now().Add(verifyTestTokenTTL), nil),
		true) // tamper

	_, err := a.VerifyIDToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if !errors.Is(err, ErrTokenVerification) {
		t.Errorf("expected ErrTokenVerification, got %v", err)
	}
}

func TestVerifyIDToken_Expired(t *testing.T) {
	srv, key := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	issuer := srv.URL + testIssuerPath
	token := signRS256(t, key, tokenHeader(),
		tokenPayload(issuer, testClientID, testSub, time.Now().Add(-1*time.Minute), nil), // expired
		false)

	_, err := a.VerifyIDToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !errors.Is(err, ErrTokenVerification) {
		t.Errorf("expected ErrTokenVerification, got %v", err)
	}
}

func TestVerifyIDToken_WrongAudience(t *testing.T) {
	srv, key := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	issuer := srv.URL + testIssuerPath
	token := signRS256(t, key, tokenHeader(),
		tokenPayload(issuer, "some-other-client", testSub, time.Now().Add(verifyTestTokenTTL), nil),
		false)

	_, err := a.VerifyIDToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if !errors.Is(err, ErrTokenVerification) {
		t.Errorf("expected ErrTokenVerification, got %v", err)
	}
}

func TestVerifyIDToken_WrongIssuer(t *testing.T) {
	srv, key := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	token := signRS256(t, key, tokenHeader(),
		tokenPayload("https://evil.example.com/realms/test", testClientID, testSub,
			time.Now().Add(verifyTestTokenTTL), nil),
		false)

	_, err := a.VerifyIDToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
	if !errors.Is(err, ErrTokenVerification) {
		t.Errorf("expected ErrTokenVerification, got %v", err)
	}
}

func TestVerifyIDToken_MalformedToken(t *testing.T) {
	srv, _ := newTestKeycloak(t)
	a := newTestAuth(t, srv)

	_, err := a.VerifyIDToken(context.Background(), "not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
	if !errors.Is(err, ErrTokenVerification) {
		t.Errorf("expected ErrTokenVerification, got %v", err)
	}
}

// guard import usage so a future refactor doesn't drop math/big or strings silently.
var _ = big.NewInt
var _ = strings.HasPrefix
