package vaioidc

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	guardTestLogout        = "/signed-out"
	guardTestAttackerState = "state-attacker-planted"
	guardTestAttackerPKCE  = "verifier-attacker-planted-0123456789"
	guardTestStatePrefixed = cookieHostPrefix + cookieOIDCState
	guardTestPKCEPrefixed  = cookieHostPrefix + cookiePKCEVerifier
	guardTestCustomPath    = "/deepr"
)

// newGuardAuth is a real New() against the controllable IdP, with the token
// endpoint answering a valid login and counting how often it was asked.
func newGuardAuth(t *testing.T, mutate func(*Config)) (*Auth, *atomic.Int64) {
	t.Helper()
	kc := newSyncKeycloak(t)
	cfg := Config{
		KeycloakURL:        kc.srv.URL,
		Realm:              testRealm,
		ClientID:           testClientID,
		ClientSecret:       "irrelevant",
		CallbackURL:        kc.srv.URL + testCallback,
		SessionSecret:      base64.StdEncoding.EncodeToString(bytes32()),
		CookieName:         syncTestCookie,
		SessionTTL:         syncTestTTL,
		LogoutRedirect:     guardTestLogout,
		SessionSyncEnabled: true,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(context.Background(), cfg)
	require.NoError(t, err)

	c := claims(true)
	c[claimAuthTime] = float64(time.Now().Unix()) // so a single max_age marker is satisfied
	kc.respondWithClaims(t, c)
	inner := kc.token
	var calls atomic.Int64
	kc.token = func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		inner(w, r)
	}
	return a, &calls
}

func guardCallback(state string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, testCallback+"?state="+state+"&code=c", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func ck(name, value string) *http.Cookie { return &http.Cookie{Name: name, Value: value} }

// guardMaxAgeMarker is a max_age marker a fresh login satisfies.
func guardMaxAgeMarker() string { return maxAgeCookieValue(3600, time.Now().UTC()) }

func minted(rec *httptest.ResponseRecorder, name string) bool {
	return sessionCookieFrom(rec, name) != nil
}

// --- config ------------------------------------------------------------------

func guardBaseConfig() Config {
	return Config{
		IssuerURL:     "https://idp.example.com",
		ClientID:      testClientID,
		ClientSecret:  "irrelevant",
		CallbackURL:   "https://auth.example.com/auth/callback",
		SessionSecret: base64.StdEncoding.EncodeToString(bytes32()),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestConfig_CookieHostPrefix_Validation(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate     func(*Config)
		wantErr    bool
		wantCookie string
	}{
		"off: names unchanged":                  {func(*Config) {}, false, defaultCookieName},
		"on: default session name prefixed":     {func(c *Config) { c.CookieHostPrefix = true }, false, cookieHostPrefix + defaultCookieName},
		"on: custom session name prefixed":      {func(c *Config) { c.CookieHostPrefix = true; c.CookieName = "insula_session" }, false, cookieHostPrefix + "insula_session"},
		"on: already-prefixed name kept":        {func(c *Config) { c.CookieHostPrefix = true; c.CookieName = cookieHostPrefix + "x" }, false, cookieHostPrefix + "x"},
		"on: explicit Path=/ accepted":          {func(c *Config) { c.CookieHostPrefix = true; c.CookiePath = "/" }, false, cookieHostPrefix + defaultCookieName},
		"on + InsecureCookie: refused":          {func(c *Config) { c.CookieHostPrefix = true; c.InsecureCookie = true }, true, ""},
		"on + CookiePath other than /: refused": {func(c *Config) { c.CookieHostPrefix = true; c.CookiePath = guardTestCustomPath }, true, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := guardBaseConfig()
			tc.mutate(&cfg)
			cfg.applyDefaults()
			_, err := cfg.validate()
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidConfig)
				assert.Contains(t, err.Error(), "CookieHostPrefix")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantCookie, cfg.CookieName)
		})
	}
}

func TestConfig_HandPrefixedNameWithoutOptionWarns(t *testing.T) {
	var logs strings.Builder
	cfg := guardBaseConfig()
	cfg.CookieName = cookieHostPrefix + "s"
	cfg.CookiePath = guardTestCustomPath
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	cfg.applyDefaults()
	_, err := cfg.validate()
	require.NoError(t, err, "a pre-existing hand-prefixed name must not become a boot failure")
	assert.Contains(t, logs.String(), "CookieName carries the __Host- prefix")
}

// --- /auth/login writes the cookies a browser will accept ---------------------

func TestLogin_FlowCookieNamesAndAttributes(t *testing.T) {
	for name, tc := range map[string]struct {
		prefix bool
		want   []string
	}{
		// ⛔ The default must stay byte-for-byte what every pinned consumer sees today.
		"default: pre-v0.32.0 names": {false, []string{cookieOIDCState, cookiePKCEVerifier, cookieOIDCMaxAge}},
		"CookieHostPrefix: __Host-":  {true, []string{guardTestStatePrefixed, guardTestPKCEPrefixed, cookieHostPrefix + cookieOIDCMaxAge}},
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := newGuardAuth(t, func(c *Config) { c.CookieHostPrefix = tc.prefix })
			rec := httptest.NewRecorder()
			a.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
			require.Equal(t, http.StatusFound, rec.Code)

			got := map[string]*http.Cookie{}
			for _, c := range rec.Result().Cookies() {
				got[c.Name] = c
			}
			require.Len(t, got, len(tc.want), "login writes exactly the state, verifier and max_age-clear cookies")
			for _, n := range tc.want {
				c := got[n]
				require.NotNil(t, c, "missing cookie %q", n)
				// The three attributes a browser checks for __Host- — and the
				// attributes every default login has always had.
				assert.True(t, c.Secure, n)
				assert.Equal(t, "/", c.Path, n)
				assert.Empty(t, c.Domain, n)
				assert.True(t, c.HttpOnly, n)
				assert.Equal(t, http.SameSiteLaxMode, c.SameSite, n)
			}
		})
	}
}

func TestLogin_DefaultSetCookieHeaderIsUnchanged(t *testing.T) {
	a, _ := newGuardAuth(t, nil)
	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	headers := rec.Header().Values("Set-Cookie")
	require.Len(t, headers, 3)
	assert.Regexp(t, `^vai_oidc_state=[^;]+; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax$`, headers[0])
	assert.Regexp(t, `^vai_pkce_verifier=[^;]+; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax$`, headers[1])
	assert.Equal(t, `vai_oidc_max_age=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`, headers[2])
}

// --- the callback under CookieHostPrefix -------------------------------------

func TestCallback_CookieHostPrefix(t *testing.T) {
	a, calls := newGuardAuth(t, func(c *Config) { c.CookieHostPrefix = true })

	t.Run("prefixed flow cookies sign in, session cookie prefixed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		a.handleCallback(rec, guardCallback(syncTestState,
			ck(guardTestStatePrefixed, syncTestState), ck(guardTestPKCEPrefixed, syncTestVerifier)))
		require.Equal(t, http.StatusFound, rec.Code)
		assert.NotEqual(t, guardTestLogout, rec.Header().Get("Location"))
		assert.True(t, minted(rec, cookieHostPrefix+syncTestCookie))
		assert.False(t, minted(rec, syncTestCookie), "no unprefixed session cookie is written")
	})

	t.Run("tossed unprefixed cookies are ignored", func(t *testing.T) {
		before := calls.Load()
		rec := httptest.NewRecorder()
		// What a sibling host CAN plant: the unprefixed names, on the parent domain.
		a.handleCallback(rec, guardCallback(guardTestAttackerState,
			ck(cookieOIDCState, guardTestAttackerState), ck(cookiePKCEVerifier, guardTestAttackerPKCE)))
		assert.Equal(t, guardTestLogout, rec.Header().Get("Location"))
		assert.False(t, minted(rec, cookieHostPrefix+syncTestCookie))
		assert.Equal(t, before, calls.Load(), "the attacker's code must never be redeemed")
	})
}

// --- duplicate (tossed) flow cookies, default config ---------------------------

func TestCallback_DuplicateFlowCookieIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		state   string
		cookies []*http.Cookie
		admit   bool
	}{
		"control: one state, one verifier signs in": {syncTestState, []*http.Cookie{
			ck(cookieOIDCState, syncTestState), ck(cookiePKCEVerifier, syncTestVerifier)}, true},
		// The attacker's planted cookie sorts FIRST (a longer Path does that), so
		// r.Cookie would have read it and the attacker's state would have matched.
		"tossed state cookie ahead of the genuine one": {guardTestAttackerState, []*http.Cookie{
			ck(cookieOIDCState, guardTestAttackerState), ck(cookieOIDCState, syncTestState),
			ck(cookiePKCEVerifier, syncTestVerifier)}, false},
		"tossed verifier cookie": {syncTestState, []*http.Cookie{
			ck(cookieOIDCState, syncTestState),
			ck(cookiePKCEVerifier, guardTestAttackerPKCE), ck(cookiePKCEVerifier, syncTestVerifier)}, false},
		"tossed state AND verifier": {guardTestAttackerState, []*http.Cookie{
			ck(cookieOIDCState, guardTestAttackerState), ck(cookiePKCEVerifier, guardTestAttackerPKCE),
			ck(cookieOIDCState, syncTestState), ck(cookiePKCEVerifier, syncTestVerifier)}, false},
		"control: one max_age marker signs in": {syncTestState, []*http.Cookie{
			ck(cookieOIDCState, syncTestState), ck(cookiePKCEVerifier, syncTestVerifier),
			ck(cookieOIDCMaxAge, guardMaxAgeMarker())}, true},
		"tossed max_age marker": {syncTestState, []*http.Cookie{
			ck(cookieOIDCState, syncTestState), ck(cookiePKCEVerifier, syncTestVerifier),
			ck(cookieOIDCMaxAge, guardMaxAgeMarker()), ck(cookieOIDCMaxAge, guardMaxAgeMarker())}, false},
	} {
		t.Run(name, func(t *testing.T) {
			a, calls := newGuardAuth(t, nil)
			rec := httptest.NewRecorder()
			a.handleCallback(rec, guardCallback(tc.state, tc.cookies...))
			require.Equal(t, http.StatusFound, rec.Code)
			if tc.admit {
				assert.True(t, minted(rec, syncTestCookie))
				return
			}
			assert.Equal(t, guardTestLogout, rec.Header().Get("Location"))
			assert.False(t, minted(rec, syncTestCookie), "a duplicate must mint no session")
			if !strings.Contains(name, "max_age") {
				assert.Zero(t, calls.Load(), "a duplicate state/verifier must be refused before the code exchange")
			}
		})
	}
}

func TestSyncCallback_DuplicateFlowCookieIsAnError(t *testing.T) {
	a, calls := newGuardAuth(t, nil)
	// The planted state sorts FIRST, so reading "the first" would match the query.
	r := httptest.NewRequest(http.MethodGet,
		testCallback+"?"+queryParamState+"="+guardTestAttackerState+"&"+queryParamCode+"=abc", nil)
	seedSession(t, a, r, syncTestSubA, syncTestSidOne)
	r.AddCookie(ck(cookieOIDCState, guardTestAttackerState))
	r.AddCookie(ck(cookieOIDCState, syncTestState))
	r.AddCookie(ck(cookiePKCEVerifier, syncTestVerifier))
	r.AddCookie(ck(cookieOIDCSync, cookieSyncMarkerValue))
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	assert.Equal(t, string(SessionSyncError), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie), "a refused sync must not touch the session")
	assert.Zero(t, calls.Load())
}

// --- RejectSameSiteCallback ---------------------------------------------------

func TestCallback_RejectSameSiteCallback(t *testing.T) {
	for name, tc := range map[string]struct {
		enabled bool
		header  string
		admit   bool
	}{
		"on, same-site: refused":      {true, secFetchSiteSameSite, false},
		"on, same-origin: refused":    {true, secFetchSiteSameOrigin, false},
		"on, cross-site: admitted":    {true, "cross-site", true},
		"on, none: admitted":          {true, "none", true},
		"on, header absent: admitted": {true, "", true},
		"off, same-site: admitted":    {false, secFetchSiteSameSite, true},
	} {
		t.Run(name, func(t *testing.T) {
			a, calls := newGuardAuth(t, func(c *Config) { c.RejectSameSiteCallback = tc.enabled })
			r := guardCallback(syncTestState, ck(cookieOIDCState, syncTestState), ck(cookiePKCEVerifier, syncTestVerifier))
			if tc.header != "" {
				r.Header.Set(headerSecFetchSite, tc.header)
			}
			rec := httptest.NewRecorder()
			a.handleCallback(rec, r)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, tc.admit, minted(rec, syncTestCookie))
			if !tc.admit {
				assert.Equal(t, guardTestLogout, rec.Header().Get("Location"))
				assert.Zero(t, calls.Load())
				assert.Empty(t, rec.Header().Values("Set-Cookie"),
					"a refused same-site attempt must not clear a genuine login in flight")
			}
		})
	}
}

func TestSyncCallback_RejectSameSiteCallback(t *testing.T) {
	a, calls := newGuardAuth(t, func(c *Config) { c.RejectSameSiteCallback = true })
	r := syncCallbackRequest(t, a, queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc",
		syncTestSubA, syncTestSidOne)
	r.Header.Set(headerSecFetchSite, secFetchSiteSameSite)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	assert.Equal(t, string(SessionSyncError), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie))
	assert.Zero(t, calls.Load())
}

func TestUniqueCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := uniqueCookie(r, cookieOIDCState)
	require.ErrorIs(t, err, http.ErrNoCookie)

	r.AddCookie(ck(cookieOIDCState, "a"))
	c, err := uniqueCookie(r, cookieOIDCState)
	require.NoError(t, err)
	assert.Equal(t, "a", c.Value)

	r.AddCookie(ck(cookieOIDCState, "b"))
	_, err = uniqueCookie(r, cookieOIDCState)
	require.ErrorIs(t, err, errDuplicateCookie)
}
