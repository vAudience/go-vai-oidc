package obolresolver

// admission_test.go — v0.29.0 (go-vai-oidc#16): the admission kind reaches obol.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	vaioidc "github.com/vAudience/go-vai-oidc"
)

// TestEnsureBodyCarriesTheAdmissionKind pins the wire half of obol ADR-376.
//
// ⚠️ A REVALIDATION THAT REACHES obol UNLABELLED IS A FABRICATED SIGN-IN. obol
// files a login audit row and an evidence-chain entry on every ensure call it
// cannot tell apart from a login, so dropping the kind here makes every
// ReresolveOnRevalidate interval a "sign-in" on a tamper-evident record
// (obol#151, ADR-366). The bare-context arm matters as much: a resolver called
// by the consumer's own code must send NO admission rather than guess one, so
// the test reads the RAW body and asserts the key is absent, not merely empty.
func TestEnsureBodyCarriesTheAdmissionKind(t *testing.T) {
	cases := []struct {
		name    string
		ctx     context.Context
		want    string
		present bool
	}{
		{"revalidation", vaioidc.ContextWithAdmission(context.Background(), vaioidc.AdmissionRevalidation), "revalidation", true},
		{"login", vaioidc.ContextWithAdmission(context.Background(), vaioidc.AdmissionLogin), "login", true},
		{"bare context", context.Background(), "", false},
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
			if _, err := r(tc.ctx, &vaioidc.User{Sub: "s"}); err != nil {
				t.Fatalf("resolver: %v", err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("body parse: %v (raw: %s)", err, raw)
			}
			got, present := body["admission"]
			if present != tc.present {
				t.Fatalf("admission present = %v, want %v (raw: %s)", present, tc.present, raw)
			}
			if !present {
				return
			}
			var kind string
			if err := json.Unmarshal(got, &kind); err != nil {
				t.Fatalf("admission parse: %v", err)
			}
			if kind != tc.want {
				t.Errorf("admission = %q, want %q", kind, tc.want)
			}
		})
	}
}
