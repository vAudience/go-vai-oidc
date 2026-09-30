package vaioidc

// Step-up (v0.28.0): max_age at /auth/login, auth_time at the callback and in
// the session, the never-advance rule on refresh, and the two helpers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLogin drives the real /auth/login handler with the given raw query.
func startLogin(t *testing.T, a *Auth, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	target := testLoginPathForStepUp
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

const testLoginPathForStepUp = "/auth/login"

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestLogin_MaxAge(t *testing.T) {
	for name, tc := range map[string]struct {
		query      string
		wantStatus int
		wantMaxAge string // "" = not forwarded
	}{
		"absent: not forwarded":            {"", http.StatusFound, ""},
		"zero forces re-authentication":    {"max_age=0", http.StatusFound, "0"},
		"positive seconds forwarded":       {"max_age=300", http.StatusFound, "300"},
		"leading zeros normalised":         {"max_age=007", http.StatusFound, "7"},
		"empty value reads as absent":      {"max_age=", http.StatusFound, ""},
		"alongside redirect and prompt":    {"max_age=0&redirect=/app/x&prompt=login", http.StatusFound, "0"},
		"negative refused":                 {"max_age=-1", http.StatusBadRequest, ""},
		"letters refused":                  {"max_age=abc", http.StatusBadRequest, ""},
		"fraction refused":                 {"max_age=1.5", http.StatusBadRequest, ""},
		"plus sign refused":                {"max_age=%2B5", http.StatusBadRequest, ""},
		"space refused":                    {"max_age=%205", http.StatusBadRequest, ""},
		"hex refused":                      {"max_age=0x10", http.StatusBadRequest, ""},
		"beyond int32 refused":             {"max_age=2147483648", http.StatusBadRequest, ""},
		"eleven digits refused":            {"max_age=00000000001", http.StatusBadRequest, ""},
		"largest accepted value forwarded": {"max_age=2147483647", http.StatusFound, "2147483647"},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			a := newSyncAuth(t, kc, false)
			rec := startLogin(t, a, tc.query)
			require.Equal(t, tc.wantStatus, rec.Code)

			if tc.wantStatus == http.StatusBadRequest {
				assert.Empty(t, rec.Header().Get("Location"), "a malformed max_age must not start a login")
				assert.Nil(t, cookieNamed(rec, cookieOIDCState), "no state may be minted for a refused login")
				assert.Contains(t, rec.Body.String(), errBodyInvalidMaxAge)
				return
			}

			loc, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			marker := cookieNamed(rec, cookieOIDCMaxAge)
			require.NotNil(t, marker, "the marker is always written: set for a step-up, expired otherwise")
			if tc.wantMaxAge == "" {
				assert.False(t, loc.Query().Has(queryParamMaxAge))
				assert.Equal(t, -1, marker.MaxAge, "an ordinary login must clear a stale step-up marker")
				return
			}
			assert.Equal(t, tc.wantMaxAge, loc.Query().Get(queryParamMaxAge))
			gotAge, startedAt, ok := parseMaxAgeCookie(marker.Value)
			require.True(t, ok, "marker %q must decode", marker.Value)
			assert.Equal(t, tc.wantMaxAge, jsonInt(gotAge))
			assert.WithinDuration(t, time.Now(), startedAt, 5*time.Second)
		})
	}
}

func jsonInt(v int64) string { return strconv.FormatInt(v, 10) }

// loginWithMaxAge drives the real callback, optionally carrying a max_age
// marker cookie as handleLogin would have set it.
func loginWithMaxAge(t *testing.T, a *Auth, marker string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, testCallback+"?state="+syncTestState+"&code=c", nil)
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: syncTestState})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: syncTestVerifier})
	if marker != "" {
		r.AddCookie(&http.Cookie{Name: cookieOIDCMaxAge, Value: marker})
	}
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	return rec
}

// freshUserResolver builds a NEW User carrying none of its input's AuthTime —
// the shape a real resolver (obolresolver) may have. The callback must record
// auth_time regardless.
func freshUserResolver() *fakeResolver {
	return &fakeResolver{answer: func(in *User) (*User, error) {
		return &User{Sub: in.Sub, Email: in.Email, OrgID: reresOrgOld,
			Memberships: []Membership{{OrgID: reresOrgOld, Role: reresRoleAdmin}}}, nil
	}}
}

func TestAuthTime_CallbackVerifiesRequestedMaxAge(t *testing.T) {
	now := time.Now().UTC()
	at := func(d time.Duration) float64 { return float64(now.Add(d).Unix()) }
	marker := func(maxAge int64, start time.Duration) string { return maxAgeCookieValue(maxAge, now.Add(start)) }

	for name, tc := range map[string]struct {
		authTime any // nil = claim absent
		marker   string
		admit    bool
		wantAut  int64
	}{
		"no max_age requested, auth_time recorded":           {at(-2 * time.Hour), "", true, now.Add(-2 * time.Hour).Unix()},
		"no max_age requested, no auth_time: admitted, zero": {nil, "", true, 0},
		"max_age=0, authenticated after the login started":   {at(-5 * time.Second), marker(0, -10*time.Second), true, now.Add(-5 * time.Second).Unix()},
		"max_age=0, within clock skew of the start":          {at(-20 * time.Second), marker(0, 0), true, now.Add(-20 * time.Second).Unix()},
		"max_age=600, authenticated five minutes before":     {at(-5 * time.Minute), marker(600, 0), true, now.Add(-5 * time.Minute).Unix()},
		"max_age=0, auth_time MISSING: refused":              {nil, marker(0, 0), false, 0},
		"max_age=0, auth_time not a number: refused":         {"1700000000", marker(0, 0), false, 0},
		"max_age=0, auth_time ten minutes old: refused":      {at(-10 * time.Minute), marker(0, 0), false, 0},
		"max_age=60, auth_time just beyond max_age+skew":     {at(-91 * time.Second), marker(60, 0), false, 0},
		"malformed marker: refused, never read as absent":    {at(0), "garbage", false, 0},
		"marker with negative max_age: refused":              {at(0), "-1." + jsonInt(now.Unix()), false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			res := freshUserResolver()
			a := newReresAuth(t, kc, res, nil)
			claims := map[string]any{"email": reresTestEmail}
			if tc.authTime != nil {
				claims[claimAuthTime] = tc.authTime
			}
			kc.respondRefresh(t, reresTestSub, claims)

			rec := loginWithMaxAge(t, a, tc.marker)
			require.Equal(t, http.StatusFound, rec.Code)
			if !tc.admit {
				assert.Equal(t, staffTestLogout, rec.Header().Get("Location"))
				assert.Nil(t, sessionCookieFrom(rec, syncTestCookie), "a refused step-up must mint no session")
				assert.Zero(t, res.calls.Load(), "a refused step-up must not reach the resolver (no sign-in side effects)")
				return
			}
			require.NotNil(t, sessionCookieFrom(rec, syncTestCookie))
			p := persisted(t, a, rec)
			assert.Equal(t, tc.wantAut, p.Aut)
			assert.Equal(t, timeOrZero(tc.wantAut), p.toUser().AuthTime)
			if m := cookieNamed(rec, cookieOIDCMaxAge); m != nil {
				assert.Equal(t, -1, m.MaxAge, "the callback must clear the marker")
			}
		})
	}
}

func TestAuthTime_RefreshDoesNotAdvance(t *testing.T) {
	now := time.Now().UTC()
	stored := now.Add(-3 * time.Hour).Unix()
	earlier := now.Add(-5 * time.Hour).Unix()

	for _, reresolve := range []bool{false, true} {
		for name, tc := range map[string]struct {
			storedAut int64
			claims    map[string]any // nil = no id_token in the refresh response
			sub       string
			want      int64
		}{
			"refreshed auth_time is LATER (now): stored kept": {stored, map[string]any{claimAuthTime: float64(now.Unix()), "email": reresTestEmail}, reresTestSub, stored},
			"refreshed auth_time equals stored: unchanged":    {stored, map[string]any{claimAuthTime: float64(stored), "email": reresTestEmail}, reresTestSub, stored},
			"refreshed auth_time is EARLIER: adopted":         {stored, map[string]any{claimAuthTime: float64(earlier), "email": reresTestEmail}, reresTestSub, earlier},
			"unknown stored value filled from the IdP":        {0, map[string]any{claimAuthTime: float64(stored), "email": reresTestEmail}, reresTestSub, stored},
			"refreshed token without auth_time: stored kept":  {stored, map[string]any{"email": reresTestEmail}, reresTestSub, stored},
			"no id_token in the refresh: stored kept":         {stored, nil, reresTestSub, stored},
			"no id_token, unknown stays unknown (never now)":  {0, nil, reresTestSub, 0},
			"id_token for another subject: ignored":           {0, map[string]any{claimAuthTime: float64(stored), "email": reresTestEmail}, "someone-else", 0},
		} {
			t.Run(name+map[bool]string{false: " [plain]", true: " [re-resolve]"}[reresolve], func(t *testing.T) {
				kc := newSyncKeycloak(t)
				res := freshUserResolver()
				a := newReresAuth(t, kc, res, func(c *Config) { c.ReresolveOnRevalidate = reresolve })
				kc.respondRefresh(t, tc.sub, tc.claims)

				p := resolvedSession()
				p.Aut = tc.storedAut
				got, rec, err := revalidate(t, a, p)
				require.NoError(t, err)
				assert.Equal(t, tc.want, got.Aut)
				assert.Equal(t, tc.want, persisted(t, a, rec).Aut, "the persisted cookie must carry the same value")
				assert.Greater(t, got.LastValidated, now.Add(-time.Minute).Unix(), "the grant must have succeeded")
			})
		}
	}
}

func TestAuthTime_PreV028SessionDecodesAsUnknown(t *testing.T) {
	// The v0.27.0 wire shape: no "aut" key.
	old := `{"sub":"s","email":"e@x","name":"n","idt":"t","exp":` + jsonInt(time.Now().Add(time.Hour).Unix()) + `}`
	var p sessionPayload
	require.NoError(t, json.Unmarshal([]byte(old), &p))
	assert.Zero(t, p.Aut)
	assert.True(t, p.toUser().AuthTime.IsZero())
	assert.False(t, RecentlyAuthenticated(p.toUser(), time.Hour, time.Now()), "unknown must never read as recent")

	// And the round trip through a real cookie.
	ta := NewTestAuth(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(ta.TestSessionCookie(t, &User{Sub: "s"}))
	got, err := readSessionCookie(r, ta.sessionKey, ta.cfg.CookieName)
	require.NoError(t, err)
	assert.True(t, got.toUser().AuthTime.IsZero())

	// A zero value stays off the wire, so an old binary reads a new cookie unchanged.
	b, err := json.Marshal(&sessionPayload{Sub: "s"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"aut"`)
}

func TestAuthTime_WritersAndNonWriters(t *testing.T) {
	authAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

	t.Run("TestSessionCookie carries it", func(t *testing.T) {
		ta := NewTestAuth(t)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(ta.TestSessionCookie(t, &User{Sub: "s", AuthTime: authAt}))
		got, err := readSessionCookie(r, ta.sessionKey, ta.cfg.CookieName)
		require.NoError(t, err)
		assert.Equal(t, authAt, got.toUser().AuthTime)
	})

	t.Run("IssueSession records the caller's value", func(t *testing.T) {
		ta := NewTestAuth(t)
		rec := httptest.NewRecorder()
		require.NoError(t, ta.IssueSession(rec, httptest.NewRequest(http.MethodGet, "/", nil), &User{Sub: "s", AuthTime: authAt}, ""))
		assert.Equal(t, authAt.Unix(), persisted(t, ta.Auth, rec).Aut)
	})

	t.Run("UpdateSession cannot move it", func(t *testing.T) {
		ta := NewTestAuth(t)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(ta.TestSessionCookie(t, &User{Sub: "s", AuthTime: authAt}))
		rec := httptest.NewRecorder()
		require.NoError(t, ta.UpdateSession(rec, r, func(u *User) {
			u.OrgID = "picked"
			u.AuthTime = time.Now()
		}))
		p := persisted(t, ta.Auth, rec)
		assert.Equal(t, "picked", p.OrgID)
		assert.Equal(t, authAt.Unix(), p.Aut)
	})

	t.Run("RequireSession serves it on the User", func(t *testing.T) {
		ta := NewTestAuth(t)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(ta.TestSessionCookie(t, &User{Sub: "s", AuthTime: authAt}))
		var seen time.Time
		ta.RequireSession()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen = UserFromContext(r.Context()).AuthTime
		})).ServeHTTP(httptest.NewRecorder(), r)
		assert.Equal(t, authAt, seen)
	})
}

func TestExtractAuthTime(t *testing.T) {
	for name, tc := range map[string]struct {
		claim any
		want  time.Time
	}{
		"number":        {float64(1700000000), time.Unix(1700000000, 0).UTC()},
		"absent":        {nil, time.Time{}},
		"string":        {"1700000000", time.Time{}},
		"zero":          {float64(0), time.Time{}},
		"negative":      {float64(-5), time.Time{}},
		"boolean":       {true, time.Time{}},
		"fraction kept": {float64(1700000000.9), time.Unix(1700000000, 0).UTC()},
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]interface{}{}
			if tc.claim != nil {
				claims[claimAuthTime] = tc.claim
			}
			assert.Equal(t, tc.want, extractAuthTime(claims))
		})
	}
}

func TestRecentlyAuthenticated(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	u := func(d time.Duration) *User { return &User{AuthTime: now.Add(d)} }
	for name, tc := range map[string]struct {
		user   *User
		window time.Duration
		want   bool
	}{
		"nil user":                          {nil, time.Hour, false},
		"zero AuthTime is unknown":          {&User{}, time.Hour, false},
		"inside the window":                 {u(-4 * time.Minute), 5 * time.Minute, true},
		"exactly at the window edge":        {u(-5 * time.Minute), 5 * time.Minute, true},
		"one second past the window":        {u(-5*time.Minute - time.Second), 5 * time.Minute, false},
		"just now":                          {u(0), 5 * time.Minute, true},
		"slightly in the future (skew)":     {u(AuthTimeSkew), 5 * time.Minute, true},
		"beyond skew in the future":         {u(AuthTimeSkew + time.Second), 5 * time.Minute, false},
		"zero window refuses":               {u(0), 0, false},
		"negative window refuses":           {u(0), -time.Minute, false},
		"day-old sign-in, 15-minute window": {u(-24 * time.Hour), 15 * time.Minute, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, RecentlyAuthenticated(tc.user, tc.window, now))
		})
	}
}

func TestStepUpLoginURL(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)

	for name, tc := range map[string]struct {
		returnTo string
		wantErr  bool
		wantRed  string
	}{
		"same-origin path":        {"/app/credentials", false, "/app/credentials"},
		"path with query":         {"/app/credentials?tab=org", false, "/app/credentials?tab=org"},
		"empty: no redirect":      {"", false, ""},
		"absolute URL refused":    {"https://evil.example/x", true, ""},
		"protocol-relative":       {"//evil.example/x", true, ""},
		"backslash trick":         {"/\\evil.example", true, ""},
		"relative without slash":  {"app/credentials", true, ""},
		"scheme inside the path":  {"/x?next=https://evil.example", true, ""},
		"javascript scheme":       {"javascript:alert(1)", true, ""},
		"embedded scheme no path": {"http://evil.example", true, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := a.StepUpLoginURL(tc.returnTo)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidReturnPath)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			u, perr := url.Parse(got)
			require.NoError(t, perr)
			assert.Equal(t, a.cfg.LoginPath, u.Path)
			assert.Equal(t, "0", u.Query().Get(queryParamMaxAge))
			assert.Equal(t, tc.wantRed, u.Query().Get(queryParamRedirect))

			// And the URL it builds drives the real login into a step-up.
			rec := startLogin(t, a, u.RawQuery)
			require.Equal(t, http.StatusFound, rec.Code)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			assert.Equal(t, "0", loc.Query().Get(queryParamMaxAge))
		})
	}
}

// Belt for mergeRefreshedAuthTime's contract, independent of the IdP fixture.
func TestMergeRefreshedAuthTime(t *testing.T) {
	for name, tc := range map[string]struct{ stored, refreshed, want int64 }{
		"later ignored":        {100, 200, 100},
		"earlier adopted":      {100, 50, 50},
		"unknown filled":       {0, 100, 100},
		"no refreshed value":   {100, 0, 100},
		"both unknown":         {0, 0, 0},
		"negative is no value": {100, -1, 100},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, mergeRefreshedAuthTime(tc.stored, tc.refreshed))
		})
	}
}
