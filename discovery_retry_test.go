package vaioidc

// discovery_retry_test.go — jittered discovery retry (v0.8.0) unit tests.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// isDiscoveryRetryable
// =============================================================================

func TestIsDiscoveryRetryable_classifier(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context deadline", context.DeadlineExceeded, true},
		{"connection refused", errors.New("dial tcp 10.0.0.1:8080: connect: connection refused"), true},
		{"no such host", errors.New("Get \"http://keycloak/realm\": dial tcp: lookup keycloak: no such host"), true},
		{"i/o timeout", errors.New("Get \"http://keycloak/.well-known/openid-configuration\": net/http: TLS handshake timeout: i/o timeout"), true},
		{"EOF", errors.New("Get \"http://keycloak/realm\": EOF"), true},
		{"connection reset", errors.New("read tcp: connection reset by peer"), true},
		{"network unreachable", errors.New("dial tcp: network is unreachable"), true},
		{"500", errors.New("oidc: 500 Internal Server Error: realm error"), true},
		{"502", errors.New("oidc: 502 Bad Gateway"), true},
		{"503", errors.New("oidc: 503 Service Unavailable"), true},
		{"504", errors.New("oidc: 504 Gateway Timeout"), true},
		{"408", errors.New("oidc: 408 Request Timeout"), true},
		{"429", errors.New("oidc: 429 Too Many Requests"), true},
		// Permanent — must NOT retry.
		{"401", errors.New("oidc: 401 Unauthorized"), false},
		{"403", errors.New("oidc: 403 Forbidden"), false},
		{"404", errors.New("oidc: 404 Not Found"), false},
		{"400", errors.New("oidc: 400 Bad Request"), false},
		{"json parse", errors.New("oidc: failed to unmarshal discovery document: invalid character '}'"), false},
		{"random", errors.New("something else entirely"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDiscoveryRetryable(tc.err); got != tc.want {
				t.Errorf("isDiscoveryRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// =============================================================================
// discoverWithRetry — end-to-end against an in-process httptest server
// =============================================================================
//
// We do NOT instantiate the full go-oidc client (that does a real
// keychain + signing-key fetch). The tests exercise the retry loop
// logic by intercepting at the HTTP layer: the test server can
// return 503s for N calls then a valid discovery doc, and we assert
// the retry policy matches expectations.

const validDiscoveryDocTemplate = `{
  "issuer": "%s",
  "authorization_endpoint": "%s/protocol/openid-connect/auth",
  "token_endpoint": "%s/protocol/openid-connect/token",
  "userinfo_endpoint": "%s/protocol/openid-connect/userinfo",
  "jwks_uri": "%s/protocol/openid-connect/certs",
  "end_session_endpoint": "%s/protocol/openid-connect/logout",
  "id_token_signing_alg_values_supported": ["RS256"]
}`

// makeFlakyKeycloakServer returns an httptest.Server whose discovery
// endpoint returns `failCount` 503s, then valid 200 responses.
// keycloakURL inside the discovery document points back at the
// server itself so go-oidc accepts the issuer match.
func makeFlakyKeycloakServer(t *testing.T, failCount int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		if calls.Load() <= failCount {
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		// Derive the public URL from the server itself.
		base := fmt.Sprintf("http://%s/realms/test", r.Host)
		_, _ = fmt.Fprintf(w, validDiscoveryDocTemplate, base, base, base, base, base, base)
	}))
	return srv, &calls
}

// makeGenericIssuerServer returns an httptest.Server that serves a valid
// OIDC discovery document at the ROOT issuer (no Keycloak "/realms/..."
// path segment), modeling a generic provider such as Google, Okta, or
// Dex. Used to prove Config.IssuerURL discovery works against a
// non-Keycloak-shaped issuer.
func makeGenericIssuerServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		base := fmt.Sprintf("http://%s", r.Host) // issuer == server root, no /realms/
		_, _ = fmt.Fprintf(w, validDiscoveryDocTemplate, base, base, base, base, base, base)
	}))
	return srv
}

// TestDiscoverWithRetry_genericIssuerNoRealmPath proves discovery succeeds
// against a generic (non-Keycloak) issuer — the server root is passed as
// the discoveryURL exactly as Config.IssuerURL resolves for Google/Okta/Dex,
// with no "/realms/<realm>" composition.
func TestDiscoverWithRetry_genericIssuerNoRealmPath(t *testing.T) {
	srv := makeGenericIssuerServer(t)
	defer srv.Close()

	prov, err := discoverWithRetry(context.Background(), discardLogger(), 30*time.Second,
		srv.URL, "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	if err != nil {
		t.Fatalf("expected generic-issuer discovery to succeed, got: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil provider for generic issuer")
	}
}

func TestDiscoverWithRetry_succeedsAfterTransientFailures(t *testing.T) {
	srv, calls := makeFlakyKeycloakServer(t, 2) // 2 503s then 200
	defer srv.Close()

	prov, err := discoverWithRetry(context.Background(), discardLogger(), 30*time.Second,
		srv.URL+"/realms/test", "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if prov == nil {
		t.Fatal("expected non-nil provider")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("expected exactly 3 HTTP calls (2 fails + 1 success), got %d", got)
	}
}

func TestDiscoverWithRetry_zeroBudgetIsSingleShot(t *testing.T) {
	// 503 on first attempt; with budget=0 we should NOT retry.
	srv, calls := makeFlakyKeycloakServer(t, 1)
	defer srv.Close()

	_, err := discoverWithRetry(context.Background(), discardLogger(), 0,
		srv.URL+"/realms/test", "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error with zero budget + first-call-fails")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 call (no retry), got %d", got)
	}
}

func TestDiscoverWithRetry_negativeBudgetIsSingleShot(t *testing.T) {
	// applyDefaults() coerces 0 → DiscoveryRetryBudgetDefault, but
	// callers can pass -1 directly to discoverWithRetry for explicit
	// opt-out. This test exercises that path.
	srv, calls := makeFlakyKeycloakServer(t, 1)
	defer srv.Close()

	_, err := discoverWithRetry(context.Background(), discardLogger(), -1,
		srv.URL+"/realms/test", "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error with negative budget + first-call-fails")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 call, got %d", got)
	}
}

func TestDiscoverWithRetry_budgetExhaustionReturnsLastErr(t *testing.T) {
	// Server always 503s; budget=2s. We should burn ~2s of retries
	// and return the underlying 503 error (wrapped with
	// ErrDiscoveryFailed by discover()).
	srv, calls := makeFlakyKeycloakServer(t, 1000)
	defer srv.Close()

	start := time.Now()
	_, err := discoverWithRetry(context.Background(), discardLogger(), 2*time.Second,
		srv.URL+"/realms/test", "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error after budget exhaustion")
	}
	// Should have made multiple attempts within 2s.
	if got := calls.Load(); got < 2 {
		t.Errorf("expected >=2 attempts within 2s budget, got %d", got)
	}
	// Should have stayed reasonably close to the budget.
	if elapsed > 4*time.Second {
		t.Errorf("retry loop ran for %v, expected <~3s", elapsed)
	}
}

func TestDiscoverWithRetry_permanentErrorShortCircuits(t *testing.T) {
	// Server returns 401 immediately. With a 30s budget the helper
	// MUST NOT retry; the error class is permanent.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := discoverWithRetry(context.Background(), discardLogger(), 30*time.Second,
		srv.URL+"/realms/test", "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("permanent 401 must NOT retry; got %d calls", got)
	}
}

func TestDiscoverWithRetry_parentContextCancel(t *testing.T) {
	srv, calls := makeFlakyKeycloakServer(t, 1000) // always 503
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := discoverWithRetry(ctx, discardLogger(), 30*time.Second,
		srv.URL+"/realms/test", "client-id", "secret",
		srv.URL+"/cb", "", []string{"openid"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on context cancel")
	}
	if elapsed > 2*time.Second {
		t.Errorf("parent cancel should stop retry quickly; elapsed %v", elapsed)
	}
	if got := calls.Load(); got < 1 {
		t.Errorf("expected at least one call before cancel, got %d", got)
	}
}

// discardLogger returns a slog.Logger backed by a no-op handler so
// the retry helper's WARN/INFO lines don't pollute test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
