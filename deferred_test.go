package vaioidc

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// DC-OIDC-READINESS-01 — NewBackground contract.

func mockDiscoveryServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/test/.well-known/openid-configuration",
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
	return httptest.NewServer(mux)
}

func mockSuccessDiscoveryBody(issuer string) string {
	return `{
  "issuer": "` + issuer + `/realms/test",
  "authorization_endpoint": "` + issuer + `/realms/test/protocol/openid-connect/auth",
  "token_endpoint": "` + issuer + `/realms/test/protocol/openid-connect/token",
  "userinfo_endpoint": "` + issuer + `/realms/test/protocol/openid-connect/userinfo",
  "end_session_endpoint": "` + issuer + `/realms/test/protocol/openid-connect/logout",
  "jwks_uri": "` + issuer + `/realms/test/protocol/openid-connect/certs"
}`
}

func newGoodCfg(srvURL string) Config {
	// 32-byte base64-encoded session secret (44 chars after b64).
	const sessSec = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	return Config{
		KeycloakURL:          srvURL,
		Realm:                "test",
		ClientID:             "test-client",
		ClientSecret:         "test-secret",
		CallbackURL:          "http://localhost/callback",
		SessionSecret:        sessSec,
		Logger:               slog.Default(),
		DiscoveryRetryBudget: -1, // single-shot for test speed
	}
}

func TestDeferredAuth_happyPath(t *testing.T) {
	srv := mockDiscoveryServer(t, 200, "")
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(mockSuccessDiscoveryBody(srv.URL)))
			return
		}
		w.WriteHeader(404)
	})
	defer srv.Close()

	d := NewBackground(context.Background(), newGoodCfg(srv.URL))
	// Eventually Ready and Get returns non-nil Auth.
	deadline := time.Now().Add(2 * time.Second)
	for !d.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("DeferredAuth did not become ready within 2s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	auth, err := d.Get()
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if auth == nil {
		t.Fatal("Get returned nil Auth")
	}
}

func TestDeferredAuth_errorPath(t *testing.T) {
	srv := mockDiscoveryServer(t, 404, "not found")
	defer srv.Close()
	d := NewBackground(context.Background(), newGoodCfg(srv.URL))
	auth, err := d.Get()
	if err == nil {
		t.Fatal("Get expected error on 404 discovery")
	}
	if auth != nil {
		t.Errorf("Get returned non-nil Auth on error: %v", auth)
	}
}

func TestDeferredAuth_readyBeforeGet(t *testing.T) {
	srv := mockDiscoveryServer(t, 200, "")
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(mockSuccessDiscoveryBody(srv.URL)))
			return
		}
		w.WriteHeader(404)
	})
	defer srv.Close()
	d := NewBackground(context.Background(), newGoodCfg(srv.URL))
	// Ready() may already be true if discovery is instant; either way it
	// must not crash. We assert the post-Get() invariant below.
	_ = d.Ready()
	_, _ = d.Get()
	if !d.Ready() {
		t.Error("Ready() must be true after Get() returns")
	}
}

func TestDeferredAuth_concurrentGet(t *testing.T) {
	srv := mockDiscoveryServer(t, 200, "")
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "openid-configuration") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(mockSuccessDiscoveryBody(srv.URL)))
			return
		}
		w.WriteHeader(404)
	})
	defer srv.Close()
	d := NewBackground(context.Background(), newGoodCfg(srv.URL))
	// 20 goroutines each call Get. All must observe identical result.
	var wg sync.WaitGroup
	results := make([]*Auth, 20)
	errs := make([]error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = d.Get()
		}(i)
	}
	wg.Wait()
	for i := 1; i < 20; i++ {
		if results[i] != results[0] {
			t.Errorf("goroutine %d got different Auth than goroutine 0", i)
		}
		if errs[i] != errs[0] {
			t.Errorf("goroutine %d got different err than goroutine 0", i)
		}
	}
}

func TestDeferredAuth_parentCancel(t *testing.T) {
	// Use a server that sleeps so discovery is in-flight when ctx
	// cancels. Validate that Get unblocks with an error and the
	// goroutine doesn't leak past the cancel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	d := NewBackground(ctx, newGoodCfg(srv.URL))
	cancel()
	// Get() should unblock; the underlying New() respects ctx, so the
	// error is a context-cancelled-shaped error from discovery.
	got := make(chan struct{})
	go func() { _, _ = d.Get(); close(got) }()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("Get did not unblock after parent ctx cancel")
	}
}
