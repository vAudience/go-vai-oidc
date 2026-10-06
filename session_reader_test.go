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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// go-vai-oidc#22 — Auth.Session and Auth.UpdateSessionIf.

const (
	readerTestOrgA     = "org_reader_a"
	readerTestOrgB     = "org_reader_b"
	readerTestTeam     = "team_reader_1"
	readerTestRole     = "member"
	readerTestRealm    = "staff"
	readerTestClaimKey = "dept"
	readerTestClaimVal = "eng"
	readerTestMutated  = "MUTATED"
	// readerTestBigToken is large enough that a RetainTokens session needs the
	// chunked cookie path (maxCookieValueBytes is ~3.8 KB).
	readerTestBigTokenBytes = 6000
)

// readerSession is a fresh (below the revalidation floor) session carrying every
// shareable field: memberships with team ids, claims and realm roles.
func readerSession() *sessionPayload {
	p := agedSession(time.Minute)
	p.OrgID = readerTestOrgA
	p.Mbs = []Membership{{OrgID: readerTestOrgA, Role: readerTestRole, TeamIDs: []string{readerTestTeam}}}
	p.Claims = map[string]string{readerTestClaimKey: readerTestClaimVal}
	p.Rls = []string{readerTestRealm}
	return p
}

// recordingHandler captures every log record, so a test can assert a WARN never fired.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }
func (h *recordingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.records))
	for _, r := range h.records {
		out = append(out, r.Message)
	}
	return out
}

// TestSession_HasNoSideEffect — Session never asks the IdP (not even for a
// session past the revalidation floor, whose middleware read WOULD), and never
// encrypts a cookie, so the chunked-cookie WARN cannot fire from it.
// Session takes no ResponseWriter, so "no Set-Cookie" holds by construction;
// these are the side effects that remain possible.
func TestSession_HasNoSideEffect(t *testing.T) {
	bigToken := strings.Repeat("a", readerTestBigTokenBytes)
	cases := []struct {
		name    string
		payload func() *sessionPayload
	}{
		{"fresh", readerSession},
		{"stale past the revalidation interval", func() *sessionPayload {
			return agedSession(revalTestInterval + time.Minute)
		}},
		{"chunked RetainTokens session", func() *sessionPayload {
			p := readerSession()
			p.AccessToken = bigToken
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newTokenStub(t, respondTokens(revalTestRotated))
			a := newRevalAuth(t, stub.srv.URL, nil)
			r := sessionRequest(t, a, tc.payload()) // built with the discard logger
			if strings.HasPrefix(tc.name, "chunked") {
				_, cerr := r.Cookie(chunkCookieName(a.cfg.CookieName, 1))
				require.NoError(t, cerr, "the fixture must really be a chunked session")
			}

			rec := &recordingHandler{}
			a.logger = slog.New(rec)
			u, err := a.Session(r)

			require.NoError(t, err)
			assert.Equal(t, revalTestSub, u.Sub)
			assert.Zero(t, stub.calls.Load(), "Session must never contact the IdP")
			assert.NotContains(t, rec.messages(), logMsgCookieLarge, "Session must never re-encrypt the session")
		})
	}
}

// TestSession_VerdictsMatchTheMiddleware drives the middleware and Session with
// the SAME request and demands the same verdict: served ⇔ no error, and the
// same sentinel on refusal (read through OptionalSession, which records why).
func TestSession_VerdictsMatchTheMiddleware(t *testing.T) {
	expired := readerSession()
	expired.Exp = time.Now().Add(-time.Minute).Unix()

	cases := []struct {
		name    string
		request func(t *testing.T, a *Auth) *http.Request
		want    error // nil = a valid session
	}{
		{"valid", func(t *testing.T, a *Auth) *http.Request { return sessionRequest(t, a, readerSession()) }, nil},
		{"chunked valid", func(t *testing.T, a *Auth) *http.Request {
			p := readerSession()
			p.AccessToken = strings.Repeat("b", readerTestBigTokenBytes)
			return sessionRequest(t, a, p)
		}, nil},
		{"expired", func(t *testing.T, a *Auth) *http.Request { return sessionRequest(t, a, expired) }, ErrSessionExpired},
		{"absent", func(*testing.T, *Auth) *http.Request { return httptest.NewRequest(http.MethodGet, "/gated", nil) }, ErrNoSession},
		{"tampered", func(t *testing.T, a *Auth) *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/gated", nil)
			good := sessionRequest(t, a, readerSession())
			c, err := good.Cookie(a.cfg.CookieName)
			require.NoError(t, err)
			b := []byte(c.Value)
			b[len(b)/2] ^= 0x01
			if b[len(b)/2] == '-' || b[len(b)/2] == '_' { // keep it base64url-shaped
				b[len(b)/2] = 'A'
			}
			r.AddCookie(&http.Cookie{Name: c.Name, Value: string(b)})
			return r
		}, ErrSessionInvalid},
		{"missing chunk", func(t *testing.T, a *Auth) *http.Request {
			p := readerSession()
			p.AccessToken = strings.Repeat("c", readerTestBigTokenBytes)
			full := sessionRequest(t, a, p)
			r := httptest.NewRequest(http.MethodGet, "/gated", nil)
			for _, c := range full.Cookies() {
				if c.Name != chunkCookieName(a.cfg.CookieName, 1) {
					r.AddCookie(c)
				}
			}
			return r
		}, ErrSessionInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newTokenStub(t, respondTokens(revalTestRotated))
			a := newRevalAuth(t, stub.srv.URL, nil)
			r := tc.request(t, a)

			var mwUser *User
			var mwErr error
			h := a.OptionalSession()(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				mwUser = UserFromContext(req.Context())
				_, mwErr = a.currentSession(req)
			}))
			h.ServeHTTP(httptest.NewRecorder(), r.Clone(context.Background()))

			u, err := a.Session(r)
			if tc.want == nil {
				require.NoError(t, err)
				require.NotNil(t, mwUser, "the middleware must serve this session too")
				assert.Equal(t, mwUser.Sub, u.Sub)
				return
			}
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, mwUser, "the middleware must refuse this session too")
			assert.ErrorIs(t, mwErr, tc.want, "same sentinel as the middleware")
		})
	}
}

// TestSession_ReturnsADeepCopy — inside the middleware every reader shares ONE
// request-scoped payload, so a shallow copy would let a caller's edit leak into
// the session a later UpdateSession persists.
func TestSession_ReturnsADeepCopy(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	var second *User
	h := a.RequireSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		first, err := a.Session(r)
		require.NoError(t, err)
		first.Memberships[0].TeamIDs[0] = readerTestMutated
		first.Memberships[0].Role = readerTestMutated
		first.Claims[readerTestClaimKey] = readerTestMutated
		first.RealmRoles[0] = readerTestMutated
		second, err = a.Session(r)
		require.NoError(t, err)
	}))
	h.ServeHTTP(httptest.NewRecorder(), sessionRequest(t, a, readerSession()))

	require.NotNil(t, second)
	assert.Equal(t, []string{readerTestTeam}, second.Memberships[0].TeamIDs)
	assert.Equal(t, readerTestRole, second.Memberships[0].Role)
	assert.Equal(t, readerTestClaimVal, second.Claims[readerTestClaimKey])
	assert.Equal(t, []string{readerTestRealm}, second.RealmRoles)
}

// TestSession_ReadsThePayloadThisRequestIsServedWith — after an UpdateSession
// on the same request Session sees the change, and a session OptionalSession
// revoked on this request is not resurrected from the cookie.
func TestSession_ReadsThePayloadThisRequestIsServedWith(t *testing.T) {
	t.Run("sees an earlier UpdateSession", func(t *testing.T) {
		stub := newTokenStub(t, respondTokens(revalTestRotated))
		a := newRevalAuth(t, stub.srv.URL, nil)
		var got *User
		h := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, a.UpdateSession(w, r, func(u *User) { u.OrgID = readerTestOrgB }))
			var err error
			got, err = a.Session(r)
			require.NoError(t, err)
		}))
		h.ServeHTTP(httptest.NewRecorder(), sessionRequest(t, a, readerSession()))
		require.NotNil(t, got)
		assert.Equal(t, readerTestOrgB, got.OrgID)
	})
	t.Run("revoked on this request", func(t *testing.T) {
		stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
		a := newRevalAuth(t, stub.srv.URL, nil)
		var err error
		h := a.OptionalSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, err = a.Session(r)
		}))
		h.ServeHTTP(httptest.NewRecorder(), sessionRequest(t, a, agedSession(revalTestInterval+time.Minute)))
		require.ErrorIs(t, err, ErrSessionRevoked)
	})
}

// TestUpdateSessionIf — writes only when mutate reports a change, and a
// declined mutation leaves the request-scoped session untouched even though
// the copy it was handed was modified (slice elements included).
func TestUpdateSessionIf(t *testing.T) {
	cases := []struct {
		name      string
		change    bool
		wantWrite bool
		wantOrg   string
		wantRole  string
	}{
		{"declined", false, false, readerTestOrgA, readerTestRole},
		{"applied", true, true, readerTestOrgB, readerTestMutated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newTokenStub(t, respondTokens(revalTestRotated))
			a := newRevalAuth(t, stub.srv.URL, nil)
			var wrote bool
			var after *User
			var cookieWritten bool
			h := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				before := w.Header().Values("Set-Cookie")
				var err error
				wrote, err = a.UpdateSessionIf(w, r, func(u *User) bool {
					u.OrgID = readerTestOrgB
					u.Memberships[0].Role = readerTestMutated
					return tc.change
				})
				require.NoError(t, err)
				cookieWritten = len(w.Header().Values("Set-Cookie")) > len(before)
				after, err = a.Session(r)
				require.NoError(t, err)
			}))
			h.ServeHTTP(httptest.NewRecorder(), sessionRequest(t, a, readerSession()))

			assert.Equal(t, tc.wantWrite, wrote)
			assert.Equal(t, tc.wantWrite, cookieWritten, "a cookie is written exactly when a change is reported")
			require.NotNil(t, after)
			assert.Equal(t, tc.wantOrg, after.OrgID)
			assert.Equal(t, tc.wantRole, after.Memberships[0].Role)
		})
	}
	t.Run("nil mutate and no session", func(t *testing.T) {
		stub := newTokenStub(t, respondTokens(revalTestRotated))
		a := newRevalAuth(t, stub.srv.URL, nil)
		wrote, err := a.UpdateSessionIf(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), nil)
		require.NoError(t, err)
		assert.False(t, wrote)
		wrote, err = a.UpdateSessionIf(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), func(*User) bool { return true })
		require.ErrorIs(t, err, ErrNoSession)
		assert.False(t, wrote)
	})
}
