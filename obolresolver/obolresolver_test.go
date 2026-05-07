package obolresolver

// obolresolver_test.go — DC-AUTH-05 Phase A unit tests.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaioidc "github.com/vAudience/go-vai-oidc"
)

func TestNew_NilBaseURL_ReturnsNil(t *testing.T) {
	r := New(Config{Client: http.DefaultClient})
	if r != nil {
		t.Errorf("New with empty BaseURL should return nil")
	}
}

func TestNew_NilClient_ReturnsErrorResolver(t *testing.T) {
	r := New(Config{BaseURL: "http://x"})
	if r == nil {
		t.Fatal("expected non-nil resolver even with nil Client")
	}
	_, err := r(context.Background(), &vaioidc.User{Sub: "x"})
	if err == nil || !strings.Contains(err.Error(), "Config.Client is nil") {
		t.Errorf("expected nil-client error, got %v", err)
	}
}

func TestNew_HappyPath_FirstMembershipPicked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/v1/identity/ensure") {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req IdentityEnsureRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Sub != "user-uuid-1" {
			t.Errorf("sub = %q", req.Sub)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
  "data": {
    "user_id": "user-uuid-1",
    "memberships": [
      {"org_id": "org-alpha", "org_name": "Alpha", "role": "owner"},
      {"org_id": "org-beta",  "org_name": "Beta",  "role": "member"}
    ]
  },
  "error": null,
  "meta": {}
}`)
	}))
	defer srv.Close()

	r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
	user := &vaioidc.User{Sub: "user-uuid-1", Email: "u@example.com", Name: "User One"}
	out, err := r(context.Background(), user)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if out == nil {
		t.Fatal("resolver returned nil user")
	}
	if out.OrgID != "org-alpha" {
		t.Errorf("OrgID = %q, want org-alpha (first membership)", out.OrgID)
	}
}

func TestNew_EmptyMemberships_RejectsByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"user_id":"x","memberships":[]},"error":null}`)
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
	out, err := r(context.Background(), &vaioidc.User{Sub: "x"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != nil {
		t.Errorf("empty memberships should yield (nil, nil) per spec §5.5; got non-nil user")
	}
}

func TestNew_EmptyMemberships_AllowsWhenFlagSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"user_id":"x","memberships":[]},"error":null}`)
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Client: srv.Client(), AllowEmptyMembership: true})
	out, err := r(context.Background(), &vaioidc.User{Sub: "x"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("AllowEmptyMembership=true should pass user through")
	}
	if out.OrgID != "" {
		t.Errorf("OrgID should be empty when memberships empty + allow flag set; got %q", out.OrgID)
	}
}

func TestNew_ServerError_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		_, _ = io.WriteString(w, `{"error":{"code":"OBL_DOWN","message":"db unavailable"}}`)
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
	_, err := r(context.Background(), &vaioidc.User{Sub: "x"})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("expected error mentioning 503, got %v", err)
	}
}

func TestNew_ObolErrorEnvelope_PropagatesAsErr(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 200 status but error in envelope (rare but possible).
		_, _ = io.WriteString(w, `{"data":null,"error":{"code":"OBL_BAD","message":"validation failed"}}`)
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
	_, err := r(context.Background(), &vaioidc.User{Sub: "x"})
	if err == nil || !strings.Contains(err.Error(), "OBL_BAD") {
		t.Errorf("expected envelope-error propagation, got %v", err)
	}
}

func TestNew_NilUser_Errors(t *testing.T) {
	r := New(Config{BaseURL: "http://x", Client: http.DefaultClient})
	_, err := r(context.Background(), nil)
	if err == nil {
		t.Error("expected error on nil user")
	}
}

// stubFailingClient errors on every Do call — exercises the
// transport-error path.
type stubFailingClient struct{ err error }

func (c *stubFailingClient) Do(*http.Request) (*http.Response, error) { return nil, c.err }

func TestNew_TransportError(t *testing.T) {
	r := New(Config{BaseURL: "http://example", Client: &stubFailingClient{err: errors.New("conn refused")}})
	_, err := r(context.Background(), &vaioidc.User{Sub: "x"})
	if err == nil || !strings.Contains(err.Error(), "conn refused") {
		t.Errorf("expected transport-err propagation, got %v", err)
	}
}

func TestNew_RequestShape(t *testing.T) {
	// Verify Content-Type, Accept, and body shape are exactly what
	// obol's HandleIdentityEnsure expects.
	var captured *http.Request
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		capturedBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"data":{"user_id":"u","memberships":[{"org_id":"o"}]},"error":null}`)
	}))
	defer srv.Close()
	r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
	if _, err := r(context.Background(), &vaioidc.User{Sub: "s", Email: "e@x", Name: "N"}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got := captured.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := captured.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
	var req IdentityEnsureRequest
	if err := json.Unmarshal(capturedBody, &req); err != nil {
		t.Fatalf("body parse: %v (raw: %s)", err, capturedBody)
	}
	if req.Sub != "s" || req.Email != "e@x" || req.Name != "N" {
		t.Errorf("body fields wrong: %+v", req)
	}
}
