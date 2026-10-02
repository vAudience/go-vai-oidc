package vaioidc

// Behaviour tests for v0.30.0 (go-vai-oidc#19, #20), end to end through the real
// session middleware over a fake IdP that signs real ID tokens.
//
//   - #19.1 a resolver soft-fail records the IdP check and retries ONLY the
//     resolver, so an identity-backend outage does not become a Keycloak grant
//     every 30 s per session;
//   - #19.2 concurrent (and straggling) requests carrying one cookie share ONE
//     grant and ONE resolver call — under refresh-token rotation the second use
//     of a refresh token is invalid_grant, i.e. a self-inflicted sign-out;
//   - #20 UpdateSession builds on the payload the middleware served the request
//     with, so it never reverts a re-resolution or a rotated refresh token.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingRefresh makes the token endpoint answer refresh grants with rotated
// tokens and an ID token for sub, counting grants. When rotate is true it
// behaves like Keycloak with "Revoke Refresh Token": a refresh token that was
// already used answers invalid_grant. delay widens the overlap window.
func (kc *syncKeycloak) countingRefresh(t *testing.T, sub string, rotate bool, delay time.Duration) *atomic.Int64 {
	t.Helper()
	var grants atomic.Int64
	var mu sync.Mutex
	used := map[string]bool{}
	kc.respondRefresh(t, sub, map[string]any{"email": reresTestEmail})
	answer := kc.token
	kc.token = func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		rt := form.Get("refresh_token")
		time.Sleep(delay)
		if rotate {
			mu.Lock()
			reused := used[rt]
			used[rt] = true
			mu.Unlock()
			if reused {
				respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant)(w, r)
				return
			}
		}
		answer(w, r)
	}
	return &grants
}

// lastCookies returns the cookies a browser would hold after rec's response:
// the LAST Set-Cookie per name wins, and a deletion removes the name.
func lastCookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	byName := map[string]*http.Cookie{}
	var order []string
	for _, c := range rec.Result().Cookies() {
		if _, seen := byName[c.Name]; !seen {
			order = append(order, c.Name)
		}
		if c.MaxAge < 0 {
			byName[c.Name] = nil
			continue
		}
		byName[c.Name] = c
	}
	var out []*http.Cookie
	for _, n := range order {
		if c := byName[n]; c != nil {
			out = append(out, c)
		}
	}
	return out
}

// browserSession decodes the session the browser holds after rec's response.
func browserSession(t *testing.T, a *Auth, rec *httptest.ResponseRecorder) *sessionPayload {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	for _, c := range lastCookies(rec) {
		r.AddCookie(c)
	}
	p, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err, "the browser must end up holding a readable session")
	return p
}

// requestWithCookies builds a JSON API request carrying cookies.
func requestWithCookies(cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/gated", nil)
	r.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// #19.1 — the issue's first test: a resolver soft-fail followed by a request
// 31 s later makes NO second token grant; the retry asks the resolver alone.
func TestRevalidate_ResolverSoftFailRetriesTheResolverNotTheIdP(t *testing.T) {
	kc := newSyncKeycloak(t)
	grants := kc.countingRefresh(t, reresTestSub, false, 0)
	var failing atomic.Bool
	failing.Store(true)
	ok := answerOrgs(reresRoleMember, reresOrgNew)
	res := &fakeResolver{answer: func(in *User) (*User, error) {
		if failing.Load() {
			return nil, errors.New("obol unavailable")
		}
		return ok(in)
	}}
	a := newReresAuth(t, kc, res, nil)
	clock := time.Now().UTC()
	a.now = func() time.Time { return clock }

	var seen *User
	h := a.RequireSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = UserFromContext(r.Context())
	}))

	// Request 1: past the floor, the grant succeeds, the resolver fails.
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, sessionRequestJSON(t, a, resolvedSession()))
	require.NotNil(t, seen, "a resolver error fails open")
	assert.Equal(t, reresOrgOld, seen.OrgID)
	require.Equal(t, int64(1), grants.Load())
	require.Equal(t, int64(1), res.calls.Load())
	after1 := browserSession(t, a, rec1)
	assert.Equal(t, clock.Unix(), after1.LastValidated, "the IdP's successful answer is recorded")
	assert.Equal(t, revalTestRotated, after1.RefreshToken)

	// Request 2, 31 s later, while the backend is still down: the resolver is
	// retried, the IdP is NOT asked again.
	clock = clock.Add(31 * time.Second)
	seen = nil
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, requestWithCookies(lastCookies(rec1)))
	require.NotNil(t, seen)
	assert.Equal(t, int64(1), grants.Load(),
		"a resolver retry must not re-run the Keycloak grant — that is 10× the IdP load during an outage of a DIFFERENT service")
	assert.Equal(t, int64(2), res.calls.Load(), "the resolver is what is retried")
	after2 := browserSession(t, a, rec2)
	assert.Equal(t, after1.Exp, after2.Exp, "a session must not gain life while its resolution cannot be re-derived")

	// Request 3, 31 s later again, with the backend back: the resolver answer
	// lands, still without a grant, and Exp slides only to what the IdP check
	// allowed.
	failing.Store(false)
	clock = clock.Add(31 * time.Second)
	seen = nil
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, requestWithCookies(lastCookies(rec2)))
	require.NotNil(t, seen)
	assert.Equal(t, int64(1), grants.Load(), "still no second grant inside the IdP floor")
	assert.Equal(t, int64(3), res.calls.Load())
	assert.Equal(t, reresOrgNew, seen.OrgID, "the retried resolution must reach the handler on the same request")
	after3 := browserSession(t, a, rec3)
	assert.Equal(t, int64(0), after3.ResolveRetryAt, "a successful retry clears the pending retry")
	assert.Equal(t, after1.LastValidated, after3.LastValidated, "a resolver retry is not an IdP check")
	assert.Equal(t, after1.LastValidated+int64(a.cfg.SessionTTL.Seconds()), after3.Exp,
		"Exp slides to what the last IdP check allowed, never past it")
}

// #19.2 — the issue's second test: N parallel requests past the floor make ONE
// grant and ONE resolver call. The IdP rotates refresh tokens, so without
// deduplication every request after the first reads invalid_grant and the
// session signs itself out; a straggler sent after the first response landed
// (but still carrying the old cookie) is covered too.
func TestRevalidate_ConcurrentRequestsShareOneGrantAndOneResolverCall(t *testing.T) {
	const n = 8
	kc := newSyncKeycloak(t)
	grants := kc.countingRefresh(t, reresTestSub, true, 50*time.Millisecond)
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, nil)

	h := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := UserFromContext(r.Context()); u != nil && u.OrgID == reresOrgNew {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	cookies := lastCookies(func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		require.NoError(t, setSessionCookie(rec, resolvedSession(), a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger))
		return rec
	}())

	recs := make([]*httptest.ResponseRecorder, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		recs[i] = httptest.NewRecorder()
		wg.Add(1)
		go func(rec *httptest.ResponseRecorder) {
			defer wg.Done()
			<-start
			h.ServeHTTP(rec, requestWithCookies(cookies))
		}(recs[i])
	}
	close(start)
	wg.Wait()

	// The straggler: same OLD cookie, after every response has landed.
	straggler := httptest.NewRecorder()
	h.ServeHTTP(straggler, requestWithCookies(cookies))

	assert.Equal(t, int64(1), grants.Load(), "N requests carrying one cookie must make ONE refresh grant")
	assert.Equal(t, int64(1), res.calls.Load(), "and ONE resolver call")
	for i, rec := range append(recs, straggler) {
		require.Equal(t, http.StatusNoContent, rec.Code,
			"request %d must be served with the re-resolved org — a 401 here is the session signed out by its own parallel requests", i)
		got := browserSession(t, a, rec)
		assert.Equal(t, revalTestRotated, got.RefreshToken, "request %d must persist the rotated refresh token", i)
		assert.Equal(t, reresOrgNew, got.OrgID)
	}
}

// #20 — the issue's test: a past-floor request served by RequireSession and a
// handler calling UpdateSession ends with a cookie carrying the re-resolved
// memberships, the rotated refresh token, the new LastValidated / Exp — and the
// handler's own mutation.
func TestUpdateSession_BuildsOnThePayloadTheMiddlewareServed(t *testing.T) {
	kc := newSyncKeycloak(t)
	kc.countingRefresh(t, reresTestSub, false, 0)
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew, reresOrgPicked)}
	a := newReresAuth(t, kc, res, nil)

	stale := resolvedSession()
	start := time.Now().UTC()
	h := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The org switcher: pick a different org of the CURRENT memberships.
		require.NoError(t, a.UpdateSession(w, r, func(u *User) { u.OrgID = reresOrgPicked }))
		// A second update on the same request compounds with the first.
		require.NoError(t, a.UpdateSession(w, r, func(u *User) {
			u.Claims = map[string]string{"switched": "yes"}
		}))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sessionRequestJSON(t, a, stale))

	got := browserSession(t, a, rec)
	assert.Equal(t, []Membership{
		{OrgID: reresOrgNew, Role: reresRoleMember},
		{OrgID: reresOrgPicked, Role: reresRoleMember},
	}, got.Mbs, "the re-resolved memberships must survive the handler's UpdateSession — not the login-time ones")
	assert.Equal(t, reresOrgPicked, got.OrgID, "the handler's mutation applies")
	assert.Equal(t, "yes", got.Claims["switched"], "successive updates on one request compound")
	assert.Equal(t, revalTestRotated, got.RefreshToken,
		"the rotated refresh token must not be lost — the old one is revoked under rotation and the next revalidation would sign the person out")
	assert.InDelta(t, start.Unix(), got.LastValidated, 2, "LastValidated must not go backwards")
	assert.Greater(t, got.Exp, stale.Exp, "Exp must not go backwards")
}

// #20 — a session OptionalSession revoked on this request is not resurrected by
// a handler's UpdateSession from the cookie the request still carries.
func TestUpdateSession_DoesNotResurrectASessionRevokedOnThisRequest(t *testing.T) {
	stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
	a := newRevalAuth(t, stub.srv.URL, nil)

	var updateErr error
	h := a.OptionalSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		updateErr = a.UpdateSession(w, r, func(u *User) { u.OrgID = "anything" })
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sessionRequest(t, a, agedSession(revalTestInterval+time.Minute)))

	require.ErrorIs(t, updateErr, ErrSessionRevoked)
	assert.Empty(t, lastCookies(rec), "the browser must end up holding no session")
}

// sessionRequestJSON is sessionRequest with a JSON Accept header, so a refusal
// is a 401 rather than a redirect.
func sessionRequestJSON(t *testing.T, a *Auth, p *sessionPayload) *http.Request {
	t.Helper()
	r := sessionRequest(t, a, p)
	r.Header.Set("Accept", "application/json")
	return r
}

// #20's sibling — AccessToken on a request the middleware revalidated returns
// the token that revalidation obtained, instead of refreshing AGAIN from the
// stale request cookie (a second use of the old refresh token, which rotation
// answers with invalid_grant).
func TestAccessToken_UsesThePayloadTheMiddlewareServed(t *testing.T) {
	kc := newSyncKeycloak(t)
	grants := kc.countingRefresh(t, reresTestSub, true, 0)
	res := &fakeResolver{answer: answerOrgs(reresRoleMember, reresOrgNew)}
	a := newReresAuth(t, kc, res, nil)

	var token string
	var tokenErr error
	h := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, tokenErr = a.AccessToken(w, r)
	}))
	stale := resolvedSession()
	stale.AccessTokenExp = time.Now().Add(-time.Minute).Unix()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sessionRequestJSON(t, a, stale))

	require.NoError(t, tokenErr)
	assert.Equal(t, revalTestAccess, token)
	assert.Equal(t, int64(1), grants.Load(), "the revalidation's grant is the only one this request may make")
	assert.Equal(t, revalTestRotated, browserSession(t, a, rec).RefreshToken)
}

// The retained answer serves only the SAME due revalidation. With an interval
// shorter than the retention window and an IdP that does not rotate, the next
// due revalidation carries the same refresh token — and must still ask the IdP.
func TestRevalidate_ARetainedAnswerNeverServesALaterRevalidation(t *testing.T) {
	stub := newTokenStub(t, respondTokens(""))
	a := newRevalAuth(t, stub.srv.URL, func(c *Config) { c.RevalidateInterval = 2 * time.Second })
	clock := time.Now().UTC()
	a.now = func() time.Time { return clock }

	p := agedSession(time.Minute)
	got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), p)
	require.NoError(t, err)
	require.Equal(t, int64(1), stub.calls.Load())

	clock = clock.Add(3 * time.Second) // past the 2 s floor, inside the 10 s retention
	_, err = a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), got)
	require.NoError(t, err)
	assert.Equal(t, int64(2), stub.calls.Load(), "a later due revalidation must ask the IdP, not reuse a retained answer")
}
