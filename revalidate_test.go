package vaioidc

// Behaviour tests for the v0.19.0 session-revalidation floor.
//
// The subject is a mechanism that can sign every user of every product out at
// once, so the tests are weighted toward the FAIL-OPEN side: five of them assert
// that a session SURVIVES a refusal, and only one asserts that it dies. That
// ratio is deliberate. The dangerous defect here is not "a revoked session
// lingers for another interval" — it is "one Keycloak blip, or one rotated
// client secret, logs the fleet out simultaneously and reads as an incident".

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	revalTestCookie   = "vai_reval_test"
	revalTestInterval = 5 * time.Minute
	revalTestTTL      = 2 * time.Hour
	revalTestRefresh  = "refresh-token-original"
	revalTestRotated  = "refresh-token-rotated"
	revalTestAccess   = "access-token-fresh"
	revalTestSub      = "user-reval-1"
)

// tokenStub is a controllable OAuth2 token endpoint that counts the grants it
// receives, so a test can assert not only WHAT the library decided but whether
// it asked the IdP at all — the distinction the whole floor turns on.
type tokenStub struct {
	srv   *httptest.Server
	calls atomic.Int64
	// lastGrant records the grant_type of the most recent request, which is how
	// these tests prove the call was a refresh and not something else.
	lastGrant atomic.Value
}

func newTokenStub(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) *tokenStub {
	t.Helper()
	stub := &tokenStub{}
	stub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if form, err := url.ParseQuery(string(body)); err == nil {
			stub.lastGrant.Store(form.Get("grant_type"))
		}
		respond(w, r)
	}))
	t.Cleanup(stub.srv.Close)
	return stub
}

// respondTokens writes a successful token response carrying the given refresh
// token (empty means "the IdP did not rotate it").
func respondTokens(refresh string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{
			"access_token": revalTestAccess,
			"token_type":   "Bearer",
			"expires_in":   300,
		}
		if refresh != "" {
			out["refresh_token"] = refresh
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

// respondOAuthError writes an RFC 6749 error response with the given code.
func respondOAuthError(status int, code string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             code,
			"error_description": "stub",
		})
	}
}

// newRevalAuth builds an Auth wired to the stub's token endpoint, skipping OIDC
// discovery entirely: discovery is not what these tests are about, and a real
// provider would make the token endpoint uncontrollable.
func newRevalAuth(t *testing.T, tokenURL string, mutate func(*Config)) *Auth {
	t.Helper()
	cfg := Config{
		ClientID:           "reval-client",
		ClientSecret:       "reval-secret",
		CookieName:         revalTestCookie,
		SessionTTL:         revalTestTTL,
		RetainTokens:       true,
		RevalidateInterval: revalTestInterval,
		InsecureCookie:     true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.applyDefaults()
	return &Auth{
		provider: &oidcProvider{
			oauth2Cfg: oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				Endpoint: oauth2.Endpoint{
					TokenURL:  tokenURL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
		},
		sessionKey: testKey(t),
		cfg:        cfg,
		logger:     slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

// agedSession returns a session issued and last validated `age` ago, with a
// refresh token.
//
// ⚠️ Exp is `now + TTL - age`, not `now + TTL`: a session that was validated in
// the past must carry the Exp it was stamped with THEN, or the fixture is a
// session that has somehow aged without its expiry moving — and under that shape
// a successful revalidation lands on exactly the same Exp it started with, so
// the assertion that the session becomes SLIDING silently proves nothing.
func agedSession(age time.Duration) *sessionPayload {
	issued := time.Now().UTC().Add(-age)
	return &sessionPayload{
		Sub:           revalTestSub,
		Email:         "reval@example.com",
		RefreshToken:  revalTestRefresh,
		AccessToken:   "access-token-stale",
		LastValidated: issued.Unix(),
		Exp:           issued.Add(revalTestTTL).Unix(),
	}
}

// ---------------------------------------------------------------------------
// The floor itself
// ---------------------------------------------------------------------------

func TestMaybeRevalidate_BelowTheFloor_DoesNotAskTheIdP(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	payload := agedSession(revalTestInterval / 2)
	before := *payload

	got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), payload)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(0), stub.calls.Load(),
		"a session inside the floor must be served from the cookie — the floor is the only thing bounding how often every gated request pays for a network round trip")
	assert.Equal(t, before.Exp, got.Exp, "Exp must not slide without a successful grant")
	assert.Equal(t, before.LastValidated, got.LastValidated)
}

func TestMaybeRevalidate_Disabled_NeverAsksTheIdP(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, func(c *Config) { c.RevalidateInterval = 0 })

	// Far past any floor — the point is that a zero interval is OFF, not "a
	// floor of zero seconds", which would revalidate on every single request.
	got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), agedSession(24*time.Hour))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(0), stub.calls.Load(),
		"RevalidateInterval=0 is the pre-v0.19.0 behaviour exactly; a consumer that sets nothing must see no new network calls")
}

func TestMaybeRevalidate_AboveTheFloor_RefreshesSlidesAndStamps(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	payload := agedSession(revalTestInterval + time.Minute)
	oldExp := payload.Exp
	rec := httptest.NewRecorder()

	got, err := a.maybeRevalidate(rec, httptest.NewRequest(http.MethodGet, "/x", nil), payload)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(1), stub.calls.Load(), "the floor elapsed, so the IdP must have been asked")
	assert.Equal(t, "refresh_token", stub.lastGrant.Load(),
		"the question put to the IdP must be a refresh grant — that is the only request whose refusal means 'this SSO session ended'")
	assert.Equal(t, revalTestAccess, got.AccessToken)
	assert.Equal(t, revalTestRotated, got.RefreshToken, "a rotated refresh token must be persisted or the NEXT revalidation fails")
	assert.Greater(t, got.Exp, oldExp, "a successful revalidation makes the session sliding; before v0.19.0 Exp was absolute")
	assert.InDelta(t, time.Now().UTC().Unix(), got.LastValidated, 5)
	assert.NotEmpty(t, rec.Result().Cookies(), "the re-stamped session must be written back, or the next request re-does the grant")
}

// TestMaybeRevalidate_KeepsRefreshTokenWhenTheIdPDoesNotRotateIt asserts the
// OBSERVABLE contract: after a refresh response that omits `refresh_token` —
// which is what Keycloak sends with `revokeRefreshToken=false`, this fleet's
// setting — the session still holds a usable refresh token, so the NEXT
// revalidation can still ask.
//
// ⚠️ IT DOES NOT PROVE THE LOCAL GUARD IN maybeRevalidate, AND CANNOT.
// x/oauth2 already carries the previous refresh token forward on a refresh
// request, so the guard's branch is unreachable through a real TokenSource and a
// mutation deleting it survives this test — verified, not assumed. The test is
// kept because the CONTRACT is what matters and it would go red if the
// dependency ever stopped honouring it; the guard is kept because the invariant
// is ours. Neither is evidence for the other.
func TestMaybeRevalidate_KeepsRefreshTokenWhenTheIdPDoesNotRotateIt(t *testing.T) {
	stub := newTokenStub(t, respondTokens(""))
	a := newRevalAuth(t, stub.srv.URL, nil)

	got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil),
		agedSession(revalTestInterval+time.Minute))

	require.NoError(t, err)
	assert.Equal(t, revalTestRefresh, got.RefreshToken,
		"an absent refresh_token in the response means 'unchanged', never 'discard the one you have'")
}

// ---------------------------------------------------------------------------
// The one refusal that fails CLOSED
// ---------------------------------------------------------------------------

func TestMaybeRevalidate_InvalidGrant_RevokesAndClearsCookies(t *testing.T) {
	stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
	a := newRevalAuth(t, stub.srv.URL, nil)
	rec := httptest.NewRecorder()

	got, err := a.maybeRevalidate(rec, httptest.NewRequest(http.MethodGet, "/x", nil),
		agedSession(revalTestInterval+time.Minute))

	require.ErrorIs(t, err, ErrSessionRevoked,
		"invalid_grant is Keycloak saying the SSO session behind this token has ended — the sign-out-elsewhere signal")
	assert.Nil(t, got)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == revalTestCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared,
		"a revoked session must be cleared from the browser, or the next request repeats the grant and the person sees a broken app instead of a login")
}

// ---------------------------------------------------------------------------
// Everything else fails OPEN — the half that keeps this mechanism safe
// ---------------------------------------------------------------------------

func TestMaybeRevalidate_FailsOpen(t *testing.T) {
	cases := []struct {
		name    string
		respond func(http.ResponseWriter, *http.Request)
		why     string
	}{
		{
			name:    "idp_5xx",
			respond: respondOAuthError(http.StatusInternalServerError, "server_error"),
			why:     "a 5xx says the IdP is unwell, not that the person left; failing closed here signs the fleet out during a Keycloak restart",
		},
		{
			name:    "invalid_client",
			respond: respondOAuthError(http.StatusUnauthorized, "invalid_client"),
			why:     "invalid_client is a rotated or wrong CLIENT SECRET; failing closed logs out every user at the moment of a credential rotation, and reads as a security incident rather than a config error",
		},
		{
			name: "unparseable_body",
			respond: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("<html>gateway says no</html>"))
			},
			why: "a 4xx with no OAuth2 error code carries no verdict — an intermediary, not the IdP, may have written it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newTokenStub(t, tc.respond)
			a := newRevalAuth(t, stub.srv.URL, nil)
			payload := agedSession(revalTestInterval + time.Minute)
			oldExp := payload.Exp

			got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), payload)

			require.NoError(t, err, tc.why)
			require.NotNil(t, got)
			assert.Equal(t, oldExp, got.Exp, "a session must not gain life from a refusal it survived")
		})
	}
}

func TestMaybeRevalidate_TransportError_FailsOpenAndBacksOff(t *testing.T) {
	// A closed listener: the IdP is never reached, so it said nothing.
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	url := stub.srv.URL
	stub.srv.Close()

	a := newRevalAuth(t, url, nil)
	payload := agedSession(revalTestInterval + time.Minute)
	oldExp := payload.Exp
	rec := httptest.NewRecorder()

	got, err := a.maybeRevalidate(rec, httptest.NewRequest(http.MethodGet, "/x", nil), payload)

	require.NoError(t, err, "an unreachable IdP is not a sign-out")
	require.NotNil(t, got)
	assert.Equal(t, oldExp, got.Exp)

	// The anchor must move forward far enough that the NEXT request does not
	// immediately retry. Without this, "retry next request" means "retry on
	// every request", against an IdP that is already unwell — and the cost lands
	// on every page load as a failing network call.
	nextDue := time.Unix(a.validationAnchor(got), 0).Add(a.cfg.RevalidateInterval)
	assert.True(t, nextDue.After(time.Now().UTC().Add(time.Second)),
		"a fail-open must back the anchor off; next attempt was due at %s", nextDue)
	assert.True(t, nextDue.Before(time.Now().UTC().Add(a.cfg.RevalidateInterval)),
		"the backoff must be SHORTER than a full interval — an outage must not suppress revalidation for longer than the configured floor")
}

func TestMaybeRevalidate_NoRefreshToken_FailsOpenWithoutAsking(t *testing.T) {
	stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
	a := newRevalAuth(t, stub.srv.URL, nil)

	payload := agedSession(revalTestInterval + time.Minute)
	payload.RefreshToken = "" // a session issued before RetainTokens was enabled

	got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), payload)

	require.NoError(t, err,
		"killing sessions that carry no refresh token would make a library upgrade sign out everyone currently logged in")
	require.NotNil(t, got)
	assert.Equal(t, int64(0), stub.calls.Load(), "there is no question to ask without a refresh token")
}

// ---------------------------------------------------------------------------
// The anchor — the upgrade-stampede guard
// ---------------------------------------------------------------------------

func TestValidationAnchor_ZeroIsIssueTimeNotTheEpoch(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	// A session shaped exactly like one issued by a pre-v0.19.0 build: no
	// LastValidated, issued a minute ago.
	now := time.Now().UTC()
	payload := &sessionPayload{
		Sub:          revalTestSub,
		RefreshToken: revalTestRefresh,
		Exp:          now.Add(revalTestTTL - time.Minute).Unix(),
	}

	got, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), payload)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(0), stub.calls.Load(),
		"⛔ reading a zero LastValidated as the epoch makes the floor overdue for EVERY pre-existing session at once, "+
			"so the first request after a rolling upgrade fires a refresh grant for every logged-in user simultaneously")
}

func TestValidationAnchor_ZeroAndOldEnoughStillRevalidates(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	// Same shape, but genuinely older than the floor: Exp is close, so the
	// derived issue time is far back.
	now := time.Now().UTC()
	payload := &sessionPayload{
		Sub:          revalTestSub,
		RefreshToken: revalTestRefresh,
		Exp:          now.Add(revalTestTTL - revalTestInterval - time.Minute).Unix(),
	}

	_, err := a.maybeRevalidate(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), payload)

	require.NoError(t, err)
	assert.Equal(t, int64(1), stub.calls.Load(),
		"the anchor derivation must still let an old pre-v0.19.0 session be revalidated — otherwise the guard against a stampede becomes a permanent exemption")
}

// ---------------------------------------------------------------------------
// Middleware and endpoint integration
// ---------------------------------------------------------------------------

// sessionRequest returns a request carrying an encrypted session cookie for the
// given payload.
func sessionRequest(t *testing.T, a *Auth, payload *sessionPayload) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	require.NoError(t, setSessionCookie(rec, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger))
	r := httptest.NewRequest(http.MethodGet, "/gated", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestRequireSession_RevokedSessionIsRefused(t *testing.T) {
	stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
	a := newRevalAuth(t, stub.srv.URL, nil)

	var served bool
	h := a.RequireSession()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true }))

	r := sessionRequest(t, a, agedSession(revalTestInterval+time.Minute))
	r.Header.Set("Accept", "application/json") // API client → 401 rather than a redirect
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.False(t, served, "a revoked session must not reach the handler with a stale identity")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestOptionalSession_RevokedSessionBecomesAnonymous(t *testing.T) {
	stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
	a := newRevalAuth(t, stub.srv.URL, nil)

	var sawUser bool
	h := a.OptionalSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawUser = UserFromContext(r.Context()) != nil
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sessionRequest(t, a, agedSession(revalTestInterval+time.Minute)))

	assert.False(t, sawUser,
		"⛔ this is the more dangerous omission of the two: OptionalSession runs on every public page, so a signed-out person "+
			"would keep being rendered as signed in — account menu, personalised chrome, 'logged in as' — across every product")
	assert.Equal(t, http.StatusOK, rec.Code, "the page itself must still render, anonymously")
}

func TestHandleSession_LiveSessionIsNoStoreAnd200(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	rec := httptest.NewRecorder()
	a.handleSession(rec, sessionRequest(t, a, agedSession(revalTestInterval+time.Minute)))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, cacheControlNoStore, rec.Header().Get(headerCacheControl),
		"a cached liveness answer keeps a signed-out browser looking signed in for as long as the cache lives — the exact divergence this endpoint detects, reintroduced by an intermediary")

	var status SessionStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	assert.True(t, status.Authenticated)
	assert.Equal(t, revalTestSub, status.Sub)
	assert.NotZero(t, status.RevalidatedAt, "the client's only honest bound on this answer's freshness")
	assert.NotContains(t, rec.Body.String(), revalTestAccess,
		"a liveness probe that leaks a token is an oracle for anything that can reach it")
}

func TestHandleSession_RevokedIs401(t *testing.T) {
	stub := newTokenStub(t, respondOAuthError(http.StatusBadRequest, oauthErrorInvalidGrant))
	a := newRevalAuth(t, stub.srv.URL, nil)

	rec := httptest.NewRecorder()
	a.handleSession(rec, sessionRequest(t, a, agedSession(revalTestInterval+time.Minute)))

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"false must arrive with 401 so a client that reads only the status code is never misled by a 200")
	assert.Contains(t, rec.Body.String(), `"authenticated":false`)
}

func TestHandleSession_NoSessionIs401(t *testing.T) {
	stub := newTokenStub(t, respondTokens(revalTestRotated))
	a := newRevalAuth(t, stub.srv.URL, nil)

	rec := httptest.NewRecorder()
	a.handleSession(rec, httptest.NewRequest(http.MethodGet, "/auth/session", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, int64(0), stub.calls.Load(), "no cookie means no question to ask")
}

// ---------------------------------------------------------------------------
// Config refusals — the two shapes that would be silently inert
// ---------------------------------------------------------------------------

func TestConfigValidate_RevalidateIntervalRefusals(t *testing.T) {
	base := func() Config {
		return Config{
			IssuerURL:     "https://idp.example.com",
			ClientID:      "c",
			ClientSecret:  "s",
			CallbackURL:   "https://app.example.com/auth/callback",
			SessionSecret: validTestSessionSecret(t),
		}
	}

	t.Run("without RetainTokens", func(t *testing.T) {
		cfg := base()
		cfg.RetainTokens = false
		cfg.RevalidateInterval = time.Minute
		cfg.applyDefaults()
		_, err := cfg.validate()
		require.ErrorIs(t, err, ErrInvalidConfig)
		assert.Contains(t, err.Error(), "RetainTokens",
			"the refusal must name the field that has to change; an interval without the token it needs is inert in a way nothing else can report")
	})

	t.Run("not shorter than SessionTTL", func(t *testing.T) {
		cfg := base()
		cfg.RetainTokens = true
		cfg.SessionTTL = 10 * time.Minute
		cfg.RevalidateInterval = 10 * time.Minute
		cfg.applyDefaults()
		_, err := cfg.validate()
		require.ErrorIs(t, err, ErrInvalidConfig)
		assert.Contains(t, err.Error(), "SessionTTL")
	})

	t.Run("valid combination is accepted", func(t *testing.T) {
		cfg := base()
		cfg.RetainTokens = true
		cfg.RevalidateInterval = 5 * time.Minute
		cfg.applyDefaults()
		_, err := cfg.validate()
		require.NoError(t, err)
	})

	t.Run("zero interval needs nothing", func(t *testing.T) {
		// The pre-v0.19.0 shape must keep validating untouched, or the release
		// stops being additive for every consumer that has not opted in.
		cfg := base()
		cfg.applyDefaults()
		_, err := cfg.validate()
		require.NoError(t, err)
	})
}

// validTestSessionSecret returns a base64 32-byte key for Config.validate().
func validTestSessionSecret(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(testKey(t))
}
