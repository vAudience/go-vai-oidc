package vaioidc

// Behaviour tests for Config.ReresolveOnRevalidate (v0.25.0).
//
// The fixture is a real Auth from New() over a fake IdP (discovery + JWKS + a
// controllable token endpoint) and a fake UserResolver whose answer and call
// count the test controls, so every test drives the production maybeRevalidate
// and — where the claim is "applied the way the callback applies it" — the
// production callback too, with the same resolver.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	reresTestInterval = 5 * time.Minute
	reresTestSub      = "user-reres-1"
	reresTestEmail    = "reres@example.com"
	reresOrgOld       = "org-old"
	reresOrgNew       = "org-new"
	reresOrgPicked    = "org-picked"
	reresRoleAdmin    = "admin"
	reresRoleMember   = "member"
	reresFunnelURL    = "https://obol.example/app/onboarding"
)

// fakeResolver is a UserResolver whose answer the test sets and whose calls it
// counts and records.
type fakeResolver struct {
	calls  atomic.Int64
	mu     sync.Mutex
	inputs []User
	answer func(in *User) (*User, error)
}

func (f *fakeResolver) resolve(_ context.Context, in *User) (*User, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.inputs = append(f.inputs, *in)
	f.mu.Unlock()
	return f.answer(in)
}

func (f *fakeResolver) lastInput(t *testing.T) User {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.inputs, "the resolver was never called")
	return f.inputs[len(f.inputs)-1]
}

// answerOrgs makes the resolver place the person in the given orgs (first is
// the default OrgID), with role on each.
func answerOrgs(role string, orgs ...string) func(*User) (*User, error) {
	return func(in *User) (*User, error) {
		out := *in
		out.Memberships = nil
		for _, o := range orgs {
			out.Memberships = append(out.Memberships, Membership{OrgID: o, Role: role})
		}
		if len(orgs) > 0 {
			out.OrgID = orgs[0]
		}
		return &out, nil
	}
}

func newReresAuth(t *testing.T, kc *syncKeycloak, res *fakeResolver, mutate func(*Config)) *Auth {
	t.Helper()
	cfg := Config{
		KeycloakURL:           kc.srv.URL,
		Realm:                 testRealm,
		ClientID:              testClientID,
		ClientSecret:          "irrelevant",
		CallbackURL:           kc.srv.URL + testCallback,
		SessionSecret:         base64.StdEncoding.EncodeToString(bytes32()),
		CookieName:            syncTestCookie,
		SessionTTL:            syncTestTTL,
		LogoutRedirect:        staffTestLogout,
		RetainTokens:          true,
		RevalidateInterval:    reresTestInterval,
		UserResolver:          res.resolve,
		ReresolveOnRevalidate: true,
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		InsecureCookie:        true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(context.Background(), cfg)
	require.NoError(t, err)
	return a
}

// respondRefresh makes the token endpoint answer every grant with fresh tokens
// and, when claims is non-nil, an ID token for sub carrying those claims.
func (kc *syncKeycloak) respondRefresh(t *testing.T, sub string, claims map[string]any) {
	t.Helper()
	var idt string
	if claims != nil {
		idt = signRS256(t, kc.key, tokenHeader(),
			tokenPayload(kc.issuer, testClientID, sub, time.Now().Add(verifyTestTokenTTL), claims), false)
	}
	kc.token = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{
			"access_token": revalTestAccess, "refresh_token": revalTestRotated,
			"token_type": "Bearer", "expires_in": 300,
		}
		if idt != "" {
			out["id_token"] = idt
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

// resolvedSession is a session past the floor that the login-time resolver
// placed in org-old as admin.
func resolvedSession() *sessionPayload {
	p := agedSession(reresTestInterval + time.Minute)
	p.Sub = reresTestSub
	p.Email = reresTestEmail
	p.Ev = true
	p.OrgID = reresOrgOld
	p.Mbs = []Membership{{OrgID: reresOrgOld, Role: reresRoleAdmin}}
	p.Claims = map[string]string{"tier": "gold"}
	return p
}

// persisted decodes the session cookie the response wrote.
func persisted(t *testing.T, a *Auth, rec *httptest.ResponseRecorder) *sessionPayload {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	p, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err, "the response must carry a readable session cookie")
	return p
}

func revalidate(t *testing.T, a *Auth, p *sessionPayload) (*sessionPayload, *httptest.ResponseRecorder, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	got, err := a.maybeRevalidate(rec, httptest.NewRequest(http.MethodGet, "/gated", nil), p)
	return got, rec, err
}

func TestReresolve_ChangedAnswerLandsInTheSession(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.respondRefresh(t, reresTestSub, map[string]any{"email": "renamed@example.com", "email_verified": true})
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, nil)

	got, rec, err := revalidate(t, a, resolvedSession())

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(1), res.calls.Load(), "a successful refresh must re-ask the resolver exactly once")
	assert.Equal(t, reresOrgNew, got.OrgID, "the resolver's new org must replace the login-time one")
	assert.Equal(t, []Membership{{OrgID: reresOrgNew, Role: reresRoleMember}}, got.Mbs,
		"a demotion (admin → member) and a removal (org-old gone) must both land")

	in := res.lastInput(t)
	assert.Equal(t, reresTestSub, in.Sub)
	assert.Equal(t, "renamed@example.com", in.Email, "with an id_token in the refresh, the input is built from ITS claims")
	assert.Empty(t, in.OrgID, "the resolver's input must look like the callback's: nothing a resolver sets")
	assert.Empty(t, in.Memberships)

	stored := persisted(t, a, rec)
	assert.Equal(t, reresOrgNew, stored.OrgID, "the new answer must be re-stamped into the cookie")
	assert.Equal(t, got.Mbs, stored.Mbs)
	assert.Equal(t, revalTestRotated, stored.RefreshToken)
	assert.Greater(t, stored.Exp, resolvedSession().Exp, "an applied answer re-stamps and slides like any revalidation")
}

func TestReresolve_WithoutAnIDTokenUsesTheStoredIdentity(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.respondRefresh(t, reresTestSub, nil)
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, nil)

	got, _, err := revalidate(t, a, resolvedSession())

	require.NoError(t, err)
	assert.Equal(t, reresOrgNew, got.OrgID)
	in := res.lastInput(t)
	assert.Equal(t, reresTestEmail, in.Email, "no id_token → the session's stored identity is the input")
	assert.True(t, in.EmailVerified)
	assert.Equal(t, map[string]string{"tier": "gold"}, in.Claims)
	assert.Empty(t, in.OrgID, "the stored identity must be stripped of the login-time resolution")
	assert.Empty(t, in.Memberships)
}

func TestReresolve_AnIDTokenForAnotherSubjectFallsBackToTheSession(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.respondRefresh(t, "someone-else", map[string]any{"email": "other@example.com"})
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, nil)

	_, _, err := revalidate(t, a, resolvedSession())

	require.NoError(t, err)
	in := res.lastInput(t)
	assert.Equal(t, reresTestSub, in.Sub, "a token naming another subject must never become the resolver's input")
	assert.Equal(t, reresTestEmail, in.Email)
}

func TestReresolve_OffNeverCallsTheResolver(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.respondRefresh(t, reresTestSub, map[string]any{"email": reresTestEmail})
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, func(c *Config) { c.ReresolveOnRevalidate = false })

	got, _, err := revalidate(t, a, resolvedSession())

	require.NoError(t, err)
	assert.Equal(t, int64(0), res.calls.Load(), "default off is v0.24.0 exactly: the resolver runs at login only")
	assert.Equal(t, reresOrgOld, got.OrgID)
	assert.Equal(t, revalTestRotated, got.RefreshToken, "the revalidation itself still happened")
}

func TestReresolve_ResolverErrorFailsOpenAndBacksOff(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.respondRefresh(t, reresTestSub, map[string]any{"email": reresTestEmail})
	res := &fakeResolver{answer: func(*User) (*User, error) { return nil, errors.New("obol unavailable") }}
	a := newReresAuth(t, kc, res, nil)

	before := resolvedSession()
	start := time.Now().UTC()
	got, rec, err := revalidate(t, a, resolvedSession())

	require.NoError(t, err, "a resolver ERROR is the backend failing to answer — never a sign-out")
	require.NotNil(t, got)
	assert.Equal(t, int64(1), res.calls.Load())
	assert.Equal(t, reresOrgOld, got.OrgID, "the previous resolution must be kept")
	assert.Equal(t, before.Mbs, got.Mbs)
	assert.Equal(t, before.Claims, got.Claims)
	assert.Equal(t, before.Exp, got.Exp, "a session must not gain life while its resolution cannot be re-derived")

	stored := persisted(t, a, rec)
	assert.Equal(t, revalTestRotated, stored.RefreshToken, "the refreshed tokens must still be persisted")
	assert.Equal(t, reresOrgOld, stored.OrgID)
	// v0.30.0 (go-vai-oidc#19): the IdP check SUCCEEDED and is recorded; only
	// the resolver retry is backed off, on its own anchor.
	assert.InDelta(t, start.Unix(), stored.LastValidated, 2,
		"the successful IdP check must be recorded — backing LastValidated off makes the retry re-run the Keycloak grant")
	assert.InDelta(t, start.Add(revalidateTransportBackoff).Unix(), stored.ResolveRetryAt, 2,
		"the resolver retry must be backed off on its own anchor")
	assert.Equal(t, before.Exp, stored.Exp, "Exp must not slide on a resolver soft-fail")
}

// The callback's two answers to an empty set, and revalidation's matching ones.
func TestReresolve_EmptyAnswersAreAppliedAsTheCallbackAppliesThem(t *testing.T) {
	noUser := func(*User) (*User, error) { return nil, nil }
	orgless := func(in *User) (*User, error) { out := *in; return &out, nil }
	funnel := func(in *User) (*User, error) {
		out := *in
		out.Landing = &Landing{Decision: LandingDecisionOnboarding, URL: reresFunnelURL}
		return &out, nil
	}

	for name, tc := range map[string]struct {
		answer func(*User) (*User, error)
		// callback's observable answer
		loginTarget  string
		loginSession bool
		// revalidation's
		ended bool
	}{
		"(nil, nil) — the callback refuses the login, revalidation ends the session": {
			answer: noUser, loginTarget: staffTestLogout, loginSession: false, ended: true,
		},
		"no org, no landing — the callback stores an org-less session, revalidation applies it": {
			answer: orgless, loginTarget: "/", loginSession: true, ended: false,
		},
		"no org, redirecting landing — the callback sends the browser to the funnel, revalidation ends the session": {
			answer: funnel, loginTarget: reresFunnelURL, loginSession: true, ended: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			res := &fakeResolver{answer: tc.answer}
			a := newReresAuth(t, kc, res, nil)

			// The callback, with the same resolver.
			kc.respondRefresh(t, reresTestSub, map[string]any{"email": reresTestEmail})
			loginRec := login(t, a)
			assert.Equal(t, http.StatusFound, loginRec.Code)
			assert.Equal(t, tc.loginTarget, loginRec.Header().Get("Location"))
			assert.Equal(t, tc.loginSession, sessionCookieFrom(loginRec, syncTestCookie) != nil)

			// Revalidation.
			got, rec, err := revalidate(t, a, resolvedSession())
			if tc.ended {
				require.ErrorIs(t, err, ErrSessionRevoked)
				assert.Nil(t, got)
				assert.True(t, sessionCleared(t, rec, syncTestCookie),
					"a person the login would not admit to a product session must not keep the old one")
				return
			}
			require.NoError(t, err)
			assert.Empty(t, got.OrgID, "the login-time org must not survive an answer that places the person nowhere")
			assert.Empty(t, got.Mbs)
			assert.Empty(t, persisted(t, a, rec).OrgID)
		})
	}
}

func TestReresolve_APickedOrgSurvivesWhileStillAMembership(t *testing.T) {
	for name, tc := range map[string]struct {
		orgs []string
		want string
	}{
		"still a member of the picked org": {orgs: []string{reresOrgNew, reresOrgPicked}, want: reresOrgPicked},
		"removed from the picked org":      {orgs: []string{reresOrgNew}, want: reresOrgNew},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			kc.respondRefresh(t, reresTestSub, nil)
			res := &fakeResolver{answer: answerOrgs(reresRoleMember, tc.orgs...)}
			a := newReresAuth(t, kc, res, nil)

			p := resolvedSession()
			p.OrgID = reresOrgPicked
			got, _, err := revalidate(t, a, p)

			require.NoError(t, err)
			assert.Equal(t, tc.want, got.OrgID)
		})
	}
}

func TestReresolve_ALoginGateRefusalEndsTheSession(t *testing.T) {
	kc := newSyncKeycloak(t)
	// The refreshed ID token no longer asserts a verified address.
	kc.respondRefresh(t, reresTestSub, map[string]any{"email": reresTestEmail, "email_verified": false})
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, func(c *Config) { c.RequireEmailVerified = true })

	got, rec, err := revalidate(t, a, resolvedSession())

	require.ErrorIs(t, err, ErrSessionRevoked)
	assert.Nil(t, got)
	assert.True(t, sessionCleared(t, rec, syncTestCookie))
	assert.Equal(t, int64(0), res.calls.Load(), "the gates run BEFORE the resolver, as at login")
}

func TestReresolve_ThroughRequireSession(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.respondRefresh(t, reresTestSub, nil)
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, nil)

	var seen *User
	h := a.RequireSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = UserFromContext(r.Context())
	}))
	r := sessionRequest(t, a, resolvedSession())
	r.Header.Set("Accept", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), r)

	require.NotNil(t, seen, "the request must be served")
	assert.Equal(t, reresOrgNew, seen.OrgID, "the handler must see the re-resolved org on the SAME request")
}

func TestConfigValidate_ReresolveOnRevalidateRefusals(t *testing.T) {
	kc := newSyncKeycloak(t)
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	for name, mutate := range map[string]func(*Config){
		"without RevalidateInterval": func(c *Config) { c.RevalidateInterval = 0 },
		"without UserResolver":       func(c *Config) { c.UserResolver = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				KeycloakURL: kc.srv.URL, Realm: testRealm, ClientID: testClientID, ClientSecret: "x",
				CallbackURL: kc.srv.URL + testCallback, SessionSecret: base64.StdEncoding.EncodeToString(bytes32()),
				SessionTTL: syncTestTTL, RetainTokens: true, RevalidateInterval: reresTestInterval,
				UserResolver: res.resolve, ReresolveOnRevalidate: true, InsecureCookie: true,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			mutate(&cfg)
			_, err := New(context.Background(), cfg)
			require.ErrorIs(t, err, ErrInvalidConfig, "an inert ReresolveOnRevalidate must be refused, not accepted")
		})
	}
}
