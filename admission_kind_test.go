package vaioidc

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdmissionKindReachesTheResolver — v0.26.0. The resolver learns WHY it is
// asked: the login callback says AdmissionLogin, re-resolution on revalidation
// says AdmissionRevalidation. A resolver with sign-in side effects (an audit
// row, invite acceptance) keys on it; without it every revalidation interval
// was indistinguishable from a fresh sign-in.
func TestAdmissionKindReachesTheResolver(t *testing.T) {
	var (
		mu    sync.Mutex
		kinds []Admission
	)
	recordKind := func(ctx context.Context, in *User) (*User, error) {
		mu.Lock()
		kinds = append(kinds, AdmissionFromContext(ctx))
		mu.Unlock()
		out := *in
		out.OrgID = reresOrgNew
		out.Memberships = []Membership{{OrgID: reresOrgNew, Role: reresRoleMember}}
		return &out, nil
	}

	t.Run("revalidation", func(t *testing.T) {
		kinds = nil
		kc := newSyncKeycloak(t)
		kc.respondRefresh(t, reresTestSub, map[string]any{"email": "a@example.com", "email_verified": true})
		res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
		a := newReresAuth(t, kc, res, func(c *Config) { c.UserResolver = recordKind })
		_, _, err := revalidate(t, a, resolvedSession())
		require.NoError(t, err)
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []Admission{AdmissionRevalidation}, kinds)
	})

	t.Run("login callback", func(t *testing.T) {
		kinds = nil
		kc := newSyncKeycloak(t)
		kc.respondRefresh(t, reresTestSub, map[string]any{"email": reresTestEmail})
		res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
		a := newReresAuth(t, kc, res, func(c *Config) { c.UserResolver = recordKind })
		rec := login(t, a) // the REAL callback
		require.Equal(t, http.StatusFound, rec.Code)
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []Admission{AdmissionLogin}, kinds)
	})

	t.Run("a context the library did not build answers empty", func(t *testing.T) {
		assert.Equal(t, Admission(""), AdmissionFromContext(context.Background()))
		//nolint:staticcheck // a nil context is exactly the input under test
		assert.Equal(t, Admission(""), AdmissionFromContext(nil))
	})
}

func TestContextWithAdmissionRoundTrips(t *testing.T) {
	for _, k := range []Admission{AdmissionLogin, AdmissionRevalidation} {
		assert.Equal(t, k, AdmissionFromContext(ContextWithAdmission(context.Background(), k)))
	}
}
