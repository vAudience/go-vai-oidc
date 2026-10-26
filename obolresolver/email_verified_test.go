package obolresolver

// email_verified_test.go — v0.36.0 (obol#497, obol ADR-502): the session's
// verified bit reaches obol's /identity/ensure.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	vaioidc "github.com/vAudience/go-vai-oidc"
)

// TestEnsureBodyCarriesEmailVerified pins the wire half of obol ADR-502.
//
// ⚠️ obol >= 3.498.0 auto-accepts pending org invitations at ensure ONLY on an
// explicit `"email_verified": true`. An invitation is a grant keyed on the
// ADDRESS, so the value must be exactly the IdP token's claim: true only for a
// verified user, and an explicit false (never absent, never true) otherwise —
// the test reads the RAW body so a defaulted or dropped key is caught.
func TestEnsureBodyCarriesEmailVerified(t *testing.T) {
	cases := []struct {
		name string
		user *vaioidc.User
		want bool
	}{
		{"verified", &vaioidc.User{Sub: "s", Email: "a@example.com", EmailVerified: true}, true},
		{"unverified", &vaioidc.User{Sub: "s", Email: "a@example.com", EmailVerified: false}, false},
		{"zero value (pre-v0.24.0 session)", &vaioidc.User{Sub: "s", Email: "a@example.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ = io.ReadAll(r.Body)
				_, _ = io.WriteString(w, `{"data":{"user_id":"u","memberships":[{"org_id":"o"}]},"error":null}`)
			}))
			defer srv.Close()

			r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
			ctx := vaioidc.ContextWithAdmission(context.Background(), vaioidc.AdmissionLogin)
			if _, err := r(ctx, tc.user); err != nil {
				t.Fatalf("resolver: %v", err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("body parse: %v (raw: %s)", err, raw)
			}
			got, present := body["email_verified"]
			if !present {
				t.Fatalf("email_verified absent from the ensure body (raw: %s)", raw)
			}
			var v bool
			if err := json.Unmarshal(got, &v); err != nil {
				t.Fatalf("email_verified is not a JSON bool: %v (raw: %s)", err, raw)
			}
			if v != tc.want {
				t.Errorf("email_verified = %v, want %v (raw: %s)", v, tc.want, raw)
			}
		})
	}
}
