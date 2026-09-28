package vaioidc

// v0.24.0: RequireEmailVerified + the ONE staff predicate (go-vai-oidc#10,
// operator ruling D2). The acceptance has three halves and each is pinned here:
// an unverified in-domain token is refused, a verified in-domain user WITHOUT a
// role is refused, and a real staff login succeeds — the last two end to end
// through a signed ID token, the callback and the middleware.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	staffTestSub      = "staff-sub"
	staffTestEmail    = "toni@vaudience.ai"
	staffTestLogout   = "/signed-out"
	staffTestLoginURL = "/auth/login"
)

func staffUser(email string, verified bool, roles ...string) *User {
	return &User{Sub: staffTestSub, Email: email, EmailVerified: verified, RealmRoles: roles}
}

func TestExtractEmailVerified(t *testing.T) {
	cases := []struct {
		name  string
		claim any
		set   bool
		want  bool
	}{
		{"bool true", true, true, true},
		{"bool false", false, true, false},
		{"string true", "true", true, true},
		{"string TRUE", "TRUE", true, true},
		{"string false", "false", true, false},
		{"string yes is not true", "yes", true, false},
		{"number is not true", float64(1), true, false},
		{"null", nil, true, false},
		{"absent", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{}
			if tc.set {
				claims[claimEmailVerified] = tc.claim
			}
			assert.Equal(t, tc.want, extractEmailVerified(claims))
		})
	}
}

func TestStaffPolicy_Check(t *testing.T) {
	p := VAIStaffPolicy()
	cases := []struct {
		name    string
		user    *User
		wantErr error
	}{
		{"platform admin", staffUser(staffTestEmail, true, RealmRoleObolSystemAdmin), nil},
		{"business manager", staffUser(staffTestEmail, true, "offline_access", RealmRoleVAIBusinessManager), nil},
		{"domain case-insensitive", staffUser("Toni@VAudience.AI", true, RealmRoleObolSystemAdmin), nil},
		{"nil user", nil, ErrNoSession},
		{"unverified in-domain with role", staffUser(staffTestEmail, false, RealmRoleObolSystemAdmin), ErrEmailNotVerified},
		{"verified in-domain without role", staffUser(staffTestEmail, true, "offline_access"), ErrStaffRoleMissing},
		{"role name is case-sensitive", staffUser(staffTestEmail, true, "OBOL-SYSTEM-ADMIN"), ErrStaffRoleMissing},
		{"suffix lookalike domain", staffUser("eve@evilvaudience.ai", true, RealmRoleObolSystemAdmin), ErrEmailDomainMismatch},
		{"subdomain", staffUser("eve@x.vaudience.ai", true, RealmRoleObolSystemAdmin), ErrEmailDomainMismatch},
		{"domain as local part", staffUser("vaudience.ai@evil.com", true, RealmRoleObolSystemAdmin), ErrEmailDomainMismatch},
		{"double at", staffUser("eve@vaudience.ai@evil.com", true, RealmRoleObolSystemAdmin), ErrEmailClaimMissing},
		{"display-name form", staffUser("Eve <eve@vaudience.ai>", true, RealmRoleObolSystemAdmin), ErrEmailClaimMissing},
		{"surrounding whitespace", staffUser(" eve@vaudience.ai", true, RealmRoleObolSystemAdmin), ErrEmailClaimMissing},
		{"empty email", staffUser("", true, RealmRoleObolSystemAdmin), ErrEmailClaimMissing},
		{"trailing at", staffUser("eve@", true, RealmRoleObolSystemAdmin), ErrEmailClaimMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Check(tc.user)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				assert.True(t, tc.user.IsStaff(p))
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
			if !errors.Is(tc.wantErr, ErrNoSession) {
				assert.ErrorIs(t, err, ErrNotStaff, "every refusal of an authenticated user must answer errors.Is(ErrNotStaff)")
			}
			assert.False(t, tc.user.IsStaff(p))
		})
	}
}

func TestStaffPolicy_InvalidPolicyRefusesEveryone(t *testing.T) {
	staff := staffUser(staffTestEmail, true, RealmRoleObolSystemAdmin)
	for name, p := range map[string]StaffPolicy{
		"zero value":        {},
		"no roles":          {Domain: StaffDomainVAudience},
		"blank roles":       {Domain: StaffDomainVAudience, Roles: []string{" ", ""}},
		"no domain":         {Roles: []string{RealmRoleObolSystemAdmin}},
		"full email":        {Domain: "a@vaudience.ai", Roles: []string{RealmRoleObolSystemAdmin}},
		"dotless domain":    {Domain: "localhost", Roles: []string{RealmRoleObolSystemAdmin}},
		"domain with space": {Domain: "vaudience .ai", Roles: []string{RealmRoleObolSystemAdmin}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, p.Validate(), ErrStaffPolicyInvalid)
			assert.ErrorIs(t, p.Check(staff), ErrStaffPolicyInvalid)
		})
	}
	// A leading "@" is tolerated rather than refused.
	p := StaffPolicy{Domain: "@VAudience.ai", Roles: []string{RealmRoleObolSystemAdmin}}
	require.NoError(t, p.Validate())
	assert.NoError(t, p.Check(staff))
}

func TestVAIStaffPolicy_IsRulingD2(t *testing.T) {
	p := VAIStaffPolicy()
	assert.Equal(t, "vaudience.ai", p.Domain)
	assert.ElementsMatch(t, []string{"obol-system-admin", "vai-business-manager"}, p.Roles)
	assert.Nil(t, p.Forbidden)
}

func staffRequest(t *testing.T, ta *TestAuth, user *User, accept string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/console/orgs?x=1", nil)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	if user != nil {
		r.AddCookie(ta.TestSessionCookie(t, user))
	}
	return r
}

func newStaffTestAuth(t *testing.T) (*TestAuth, *bytes.Buffer) {
	t.Helper()
	ta := NewTestAuth(t)
	ta.cfg.LoginPath = staffTestLoginURL
	var logs bytes.Buffer
	ta.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	return ta, &logs
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
}

func TestRequireStaff_Middleware(t *testing.T) {
	ta, logs := newStaffTestAuth(t)
	h := ta.RequireStaff(VAIStaffPolicy())(okHandler())

	t.Run("staff passes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staffRequest(t, ta, staffUser(staffTestEmail, true, RealmRoleVAIBusinessManager), ""))
		assert.Equal(t, http.StatusTeapot, rec.Code)
	})
	t.Run("no session, browser: login redirect carrying the deep link", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staffRequest(t, ta, nil, "text/html"))
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), staffTestLoginURL+"?redirect=")
	})
	t.Run("no session, API: 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staffRequest(t, ta, nil, ""))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
	t.Run("verified in-domain without role: 403", func(t *testing.T) {
		logs.Reset()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staffRequest(t, ta, staffUser(staffTestEmail, true), "text/html"))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.JSONEq(t, `{"error":"staff access required"}`, rec.Body.String())
		assert.Contains(t, logs.String(), `"staff_reason":"role_missing"`)
	})
	t.Run("unverified in-domain with role: 403", func(t *testing.T) {
		logs.Reset()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, staffRequest(t, ta, staffUser(staffTestEmail, false, RealmRoleObolSystemAdmin), ""))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, logs.String(), `"staff_reason":"email_not_verified"`)
	})
	t.Run("pre-v0.24.0 cookie (no ev) fails closed", func(t *testing.T) {
		// A cookie written before EmailVerified was persisted decodes as false.
		payload := &sessionPayload{Sub: staffTestSub, Email: staffTestEmail,
			Rls: []string{RealmRoleObolSystemAdmin}, Exp: time.Now().Add(time.Hour).Unix()}
		enc, err := encryptSession(payload, ta.sessionKey)
		require.NoError(t, err)
		r := httptest.NewRequest(http.MethodGet, "/console", nil)
		r.AddCookie(&http.Cookie{Name: ta.cfg.CookieName, Value: enc})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestRequireStaff_CustomForbidden(t *testing.T) {
	ta, _ := newStaffTestAuth(t)
	p := VAIStaffPolicy()
	p.Forbidden = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	rec := httptest.NewRecorder()
	ta.RequireStaff(p)(okHandler()).ServeHTTP(rec, staffRequest(t, ta, staffUser("eve@evilvaudience.ai", true, RealmRoleObolSystemAdmin), ""))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRequireStaff_InvalidPolicyIsClosedAndLoggedAtError(t *testing.T) {
	ta, logs := newStaffTestAuth(t)
	h := ta.RequireStaff(StaffPolicy{Domain: StaffDomainVAudience})(okHandler())
	assert.Contains(t, logs.String(), `"level":"ERROR"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, staffRequest(t, ta, staffUser(staffTestEmail, true, RealmRoleObolSystemAdmin), ""))
	assert.Equal(t, http.StatusForbidden, rec.Code, "a staff user must be refused by a policy that cannot be evaluated")
	assert.Contains(t, logs.String(), `"staff_reason":"policy_invalid"`)
}

// --- end to end: signed ID token → callback → session → RequireStaff --------

func newStaffKeycloakAuth(t *testing.T, kc *syncKeycloak, requireVerified bool, logs *bytes.Buffer) *Auth {
	t.Helper()
	a, err := New(context.Background(), Config{
		KeycloakURL:          kc.srv.URL,
		Realm:                testRealm,
		ClientID:             testClientID,
		ClientSecret:         "irrelevant",
		CallbackURL:          kc.srv.URL + testCallback,
		SessionSecret:        base64.StdEncoding.EncodeToString(bytes32()),
		CookieName:           syncTestCookie,
		SessionTTL:           syncTestTTL,
		LogoutRedirect:       staffTestLogout,
		RequireEmailDomain:   StaffDomainVAudience,
		RequireEmailVerified: requireVerified,
		Logger:               slog.New(slog.NewJSONHandler(logs, nil)),
		InsecureCookie:       true,
	})
	require.NoError(t, err)
	return a
}

// respondWithClaims makes the token endpoint answer the code exchange with an ID
// token carrying the given extra claims.
func (kc *syncKeycloak) respondWithClaims(t *testing.T, extra map[string]any) {
	t.Helper()
	idt := signRS256(t, kc.key, tokenHeader(),
		tokenPayload(kc.issuer, testClientID, staffTestSub, time.Now().Add(verifyTestTokenTTL), extra), false)
	kc.token = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "refresh_token": "rt", "token_type": "Bearer",
			"expires_in": 300, "id_token": idt,
		})
	}
}

// login drives the authorization-code callback and returns the response.
func login(t *testing.T, a *Auth) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, testCallback+"?state="+syncTestState+"&code=c", nil)
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: syncTestState})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: syncTestVerifier})
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func claims(verified any, roles ...any) map[string]any {
	c := map[string]any{"email": staffTestEmail, "realm_access": map[string]any{"roles": roles}}
	if verified != nil {
		c["email_verified"] = verified
	}
	return c
}

func TestCallback_RequireEmailVerified(t *testing.T) {
	for name, tc := range map[string]struct {
		claims  map[string]any
		require bool
		admit   bool
	}{
		"unverified in-domain, gate on: refused":  {claims(false, RealmRoleObolSystemAdmin), true, false},
		"claim absent, gate on: refused":          {claims(nil, RealmRoleObolSystemAdmin), true, false},
		"verified in-domain, gate on: admitted":   {claims(true), true, true},
		"unverified, gate off: admitted (compat)": {claims(false), false, true},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			var logs bytes.Buffer
			a := newStaffKeycloakAuth(t, kc, tc.require, &logs)
			kc.respondWithClaims(t, tc.claims)
			rec := login(t, a)
			require.Equal(t, http.StatusFound, rec.Code)
			if tc.admit {
				assert.NotNil(t, sessionCookieFrom(rec, syncTestCookie))
				assert.NotEqual(t, staffTestLogout, rec.Header().Get("Location"))
				return
			}
			assert.Nil(t, sessionCookieFrom(rec, syncTestCookie), "a refused login must mint no session")
			assert.Equal(t, staffTestLogout, rec.Header().Get("Location"))
			assert.Contains(t, logs.String(), `"reason":"email_not_verified"`)
		})
	}
}

func TestNew_WarnsWhenDomainGateHasNoVerifiedGate(t *testing.T) {
	kc := newSyncKeycloak(t)
	var logs bytes.Buffer
	newStaffKeycloakAuth(t, kc, false, &logs)
	assert.Contains(t, logs.String(), logMsgDomainGateUnverified)

	logs.Reset()
	newStaffKeycloakAuth(t, kc, true, &logs)
	assert.NotContains(t, logs.String(), logMsgDomainGateUnverified)
}

func TestStaff_EndToEnd_LoginThenGate(t *testing.T) {
	for name, tc := range map[string]struct {
		claims map[string]any
		want   int
	}{
		"real staff login succeeds":        {claims(true, "offline_access", RealmRoleObolSystemAdmin), http.StatusTeapot},
		"string-typed verified claim":      {claims("true", RealmRoleVAIBusinessManager), http.StatusTeapot},
		"verified in-domain, no role: 403": {claims(true, "offline_access"), http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			var logs bytes.Buffer
			a := newStaffKeycloakAuth(t, kc, true, &logs)
			kc.respondWithClaims(t, tc.claims)
			cookie := sessionCookieFrom(login(t, a), syncTestCookie)
			require.NotNil(t, cookie, "the login itself must succeed; the staff gate is per request")

			r := httptest.NewRequest(http.MethodGet, "/console", nil)
			r.AddCookie(cookie)
			rec := httptest.NewRecorder()
			a.RequireStaff(VAIStaffPolicy())(okHandler()).ServeHTTP(rec, r)
			assert.Equal(t, tc.want, rec.Code)
		})
	}
}

// TestPathPrefixMount pins the README's "one seam" claims for a product mounted
// at a prefix: the redirect_uri is CallbackURL byte-for-byte, and the state and
// PKCE cookies are scoped to CookiePath (so they reach the prefixed callback).
func TestPathPrefixMount(t *testing.T) {
	kc := newSyncKeycloak(t)
	callback := "https://app.example.test/deepr/auth/callback"
	a, err := New(context.Background(), Config{
		KeycloakURL: kc.srv.URL, Realm: testRealm, ClientID: testClientID, ClientSecret: "x",
		CallbackURL: callback, SessionSecret: base64.StdEncoding.EncodeToString(bytes32()),
		LoginPath: "/deepr/auth/login", PostLoginRedirect: "/deepr/", CookiePath: "/deepr",
		CookieName: "deepr_session", Logger: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)),
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/deepr/auth/login?redirect=/deepr/c/1", nil))
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, callback, loc.Query().Get("redirect_uri"))
	cookies := rec.Result().Cookies()
	require.NotEmpty(t, cookies)
	for _, c := range cookies {
		assert.Equal(t, "/deepr", c.Path, "cookie %s must be scoped to the mount prefix", c.Name)
	}
}
