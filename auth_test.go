package vaioidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Unit tests: helpers
// ---------------------------------------------------------------------------

func TestGeneratePKCE_Length(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	require.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	// base64url-encoded 32 bytes = 43 chars (no padding)
	assert.Len(t, verifier, 43)
}

func TestGeneratePKCE_Uniqueness(t *testing.T) {
	v1, c1, err := generatePKCE()
	require.NoError(t, err)
	v2, c2, err := generatePKCE()
	require.NoError(t, err)
	assert.NotEqual(t, v1, v2)
	assert.NotEqual(t, c1, c2)
}

func TestGeneratePKCE_S256Verify(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	require.NoError(t, err)

	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, expected, challenge)
}

func TestGenerateState_Length(t *testing.T) {
	state, err := generateState()
	require.NoError(t, err)
	// hex-encoded 32 bytes = 64 chars
	assert.Len(t, state, 64)
}

func TestGenerateState_Uniqueness(t *testing.T) {
	s1, err := generateState()
	require.NoError(t, err)
	s2, err := generateState()
	require.NoError(t, err)
	assert.NotEqual(t, s1, s2)
}

func TestIsValidRedirect(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"/dashboard", true},
		{"/org/settings?tab=1", true},
		{"/", true},
		{"", false},
		{"https://evil.com", false},
		{"//evil.com", false},
		{"http://evil.com/path", false},
		{"javascript:alert(1)", false},
		{"dashboard", false},       // no leading /
		{"/\\evil.com", false},     // backslash — browser normalization attack
		{"/path\\other", false},    // backslash in path
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.valid, isValidRedirect(tt.input))
		})
	}
}

func TestParseStateCookie(t *testing.T) {
	state, redirect := parseStateCookie("abc123")
	assert.Equal(t, "abc123", state)
	assert.Empty(t, redirect)

	state, redirect = parseStateCookie("abc123|/dashboard")
	assert.Equal(t, "abc123", state)
	assert.Equal(t, "/dashboard", redirect)

	state, redirect = parseStateCookie("abc|/path|extra")
	assert.Equal(t, "abc", state)
	assert.Equal(t, "/path|extra", redirect)
}

func TestBuildLogoutURL(t *testing.T) {
	url := buildLogoutURL(
		"https://kc.example.com/realms/test/protocol/openid-connect/logout",
		"id-token-value",
		"https://app.example.com/",
	)
	assert.Contains(t, url, "id_token_hint=id-token-value")
	assert.Contains(t, url, "post_logout_redirect_uri=")
}

func TestBuildLogoutURL_NoHint(t *testing.T) {
	url := buildLogoutURL(
		"https://kc.example.com/realms/test/protocol/openid-connect/logout",
		"",
		"/",
	)
	assert.NotContains(t, url, "id_token_hint")
	assert.Contains(t, url, "post_logout_redirect_uri=")
}

func TestWantsBrowser(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	assert.True(t, wantsBrowser(req))

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Accept", "application/json")
	assert.False(t, wantsBrowser(req2))

	req3 := httptest.NewRequest("GET", "/", nil)
	assert.False(t, wantsBrowser(req3))
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	assert.Equal(t, "1.2.3.4", clientIP(req))

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Forwarded-For", "5.6.7.8, 9.10.11.12")
	assert.Equal(t, "5.6.7.8", clientIP(req2))

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "10.0.0.1:12345"
	assert.Equal(t, "10.0.0.1:12345", clientIP(req3))
}

func TestSkipPaths(t *testing.T) {
	a := &Auth{}
	paths := a.SkipPaths()
	assert.Equal(t, []string{"/login", "/callback", "/logout"}, paths)
}

func TestSkipPathsWithPrefix(t *testing.T) {
	a := &Auth{}
	paths := a.SkipPathsWithPrefix("/auth")
	assert.Equal(t, []string{"/auth/login", "/auth/callback", "/auth/logout"}, paths)
}

// ---------------------------------------------------------------------------
// Middleware tests (using pre-built session cookies)
// ---------------------------------------------------------------------------

func TestRequireSession_ValidSession(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test"},
	}

	payload := &sessionPayload{
		Sub:   "user-1",
		Email: "a@b.com",
		Name:  "A",
		Exp:   time.Now().UTC().Add(time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	var capturedUser *User
	handler := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, "user-1", capturedUser.Sub)
	assert.Equal(t, "a@b.com", capturedUser.Email)
}

func TestRequireSession_NoSession_Browser(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg:        Config{CookieName: "vai_test", LoginPath: "/auth/login"},
		logger:     noopLogger(),
	}

	handler := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/auth/login", w.Header().Get("Location"))
}

func TestRequireSession_NoSession_API(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg:        Config{CookieName: "vai_test"},
		logger:     noopLogger(),
	}

	handler := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "authentication required", body["error"])
}

func TestRequireSession_ExpiredSession(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test"},
		logger:     noopLogger(),
	}

	payload := &sessionPayload{
		Sub: "user-1",
		Exp: time.Now().UTC().Add(-time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	handler := a.RequireSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
}

func TestOptionalSession_WithSession(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test"},
	}

	payload := &sessionPayload{
		Sub: "user-opt",
		Exp: time.Now().UTC().Add(time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	var capturedUser *User
	handler := a.OptionalSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, "user-opt", capturedUser.Sub)
}

func TestOptionalSession_NoSession(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg:        Config{CookieName: "vai_test"},
	}

	var capturedUser *User
	handler := a.OptionalSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Nil(t, capturedUser)
}

// ---------------------------------------------------------------------------
// Login handler tests
// ---------------------------------------------------------------------------

func TestHandleLogin_RedirectsToKeycloak(t *testing.T) {
	// We can't fully test the login handler without a real OIDC provider,
	// but we can test the route exists and the handler doesn't panic.
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "/",
			InsecureCookie: true,
		},
		logger: noopLogger(),
		provider: &oidcProvider{
			endSessionURL: "https://kc.example.com/logout",
		},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	// Login without provider (no authCodeURL) will redirect to LogoutRedirect on error.
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should redirect somewhere (302) — either to Keycloak or to fallback.
	assert.Equal(t, http.StatusFound, w.Code)
}

// ---------------------------------------------------------------------------
// Logout handler tests
// ---------------------------------------------------------------------------

func TestHandleLogout_ClearsSessionAndRedirects(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "/goodbye",
			InsecureCookie: true,
		},
		logger:   noopLogger(),
		provider: &oidcProvider{endSessionURL: ""},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	// Create a valid session cookie.
	payload := &sessionPayload{Sub: "user-1", Exp: time.Now().UTC().Add(time.Hour).Unix()}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/goodbye", w.Header().Get("Location"))

	// Session cookie should be cleared.
	for _, c := range w.Result().Cookies() {
		if c.Name == "vai_test" {
			assert.Equal(t, -1, c.MaxAge)
		}
	}
}

func TestHandleLogout_WithKeycloakEndSession(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "https://app.example.com/",
			InsecureCookie: true,
		},
		logger: noopLogger(),
		provider: &oidcProvider{
			endSessionURL: "https://kc.example.com/realms/test/protocol/openid-connect/logout",
		},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	payload := &sessionPayload{
		Sub:     "user-1",
		IDToken: "test-id-token",
		Exp:     time.Now().UTC().Add(time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "kc.example.com")
	assert.Contains(t, loc, "id_token_hint=test-id-token")
	assert.Contains(t, loc, "post_logout_redirect_uri=")
}

// ---------------------------------------------------------------------------
// Callback error path tests
// ---------------------------------------------------------------------------

func TestHandleCallback_MissingStateCookie(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "/",
			InsecureCookie: true,
		},
		logger:   noopLogger(),
		provider: &oidcProvider{},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	req := httptest.NewRequest("GET", "/auth/callback?state=abc&code=xyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
}

func TestHandleCallback_IdPError(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "/error-page",
			InsecureCookie: true,
		},
		logger:   noopLogger(),
		provider: &oidcProvider{},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	req := httptest.NewRequest("GET", "/auth/callback?error=access_denied&error_description=user+cancelled", nil)
	req.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: "test-state"})
	req.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: "test-verifier"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/error-page", w.Header().Get("Location"))
}

func TestHandleCallback_StateMismatch(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "/",
			InsecureCookie: true,
		},
		logger:   noopLogger(),
		provider: &oidcProvider{},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	req := httptest.NewRequest("GET", "/auth/callback?state=wrong-state&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: "correct-state"})
	req.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: "test-verifier"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
}

func TestHandleCallback_MissingCode(t *testing.T) {
	a := &Auth{
		sessionKey: testKey(t),
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			LogoutRedirect: "/",
			InsecureCookie: true,
		},
		logger:   noopLogger(),
		provider: &oidcProvider{},
	}

	r := chi.NewRouter()
	r.Mount("/auth", a.Routes())

	state := "matching-state"
	req := httptest.NewRequest("GET", "/auth/callback?state="+state, nil)
	req.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: state})
	req.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: "test-verifier"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
}

// ---------------------------------------------------------------------------
// UserFromContext
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UpdateSession tests
// ---------------------------------------------------------------------------

func TestUpdateSession_SetOrgID(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			InsecureCookie: true,
			SessionTTL:     time.Hour,
		},
	}

	// Create initial session without OrgID.
	payload := &sessionPayload{
		Sub:     "user-1",
		Email:   "a@b.com",
		Name:    "A",
		IDToken: "original-jwt",
		Exp:     time.Now().UTC().Add(time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	// Build request with the session cookie.
	req := httptest.NewRequest("POST", "/select-org", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()

	// Mutate: set OrgID.
	err = a.UpdateSession(w, req, func(u *User) {
		u.OrgID = "new-org-id"
	})
	require.NoError(t, err)

	// Read back the updated cookie.
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	updated, err := decryptSession(cookies[0].Value, key)
	require.NoError(t, err)
	assert.Equal(t, "new-org-id", updated.OrgID)
	assert.Equal(t, "user-1", updated.Sub)
	assert.Equal(t, "a@b.com", updated.Email)
	assert.Equal(t, "original-jwt", updated.IDToken) // preserved
	assert.Equal(t, payload.Exp, updated.Exp)        // preserved
}

func TestUpdateSession_NoSession(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test"},
	}

	req := httptest.NewRequest("POST", "/select-org", nil) // no cookie
	w := httptest.NewRecorder()

	err := a.UpdateSession(w, req, func(u *User) {
		u.OrgID = "should-not-matter"
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// IssueSession tests (v0.10.0+)
// ---------------------------------------------------------------------------

func TestIssueSession_WritesCookieMatchingHandleCallbackShape(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg: Config{
			CookieName:     "vai_test",
			CookiePath:     "/",
			InsecureCookie: true,
			SessionTTL:     2 * time.Hour,
		},
	}

	user := &User{
		Sub:    "user-7",
		Email:  "x@y.com",
		Name:   "X Y",
		OrgID:  "org-z",
		Claims: map[string]string{"dept": "eng"},
	}
	req := httptest.NewRequest("POST", "/auth/login/password", nil)
	w := httptest.NewRecorder()

	err := a.IssueSession(w, req, user, "raw-id-token-xyz")
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "vai_test", cookies[0].Name)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, "/", cookies[0].Path)

	// Decrypt + verify payload is the same shape handleCallback would emit.
	payload, err := decryptSession(cookies[0].Value, key)
	require.NoError(t, err)
	assert.Equal(t, "user-7", payload.Sub)
	assert.Equal(t, "x@y.com", payload.Email)
	assert.Equal(t, "X Y", payload.Name)
	assert.Equal(t, "org-z", payload.OrgID)
	assert.Equal(t, "eng", payload.Claims["dept"])
	assert.Equal(t, "raw-id-token-xyz", payload.IDToken)
	// Exp should be ~now + SessionTTL (within 5s slack).
	assert.InDelta(t, time.Now().Add(2*time.Hour).Unix(), payload.Exp, 5)
}

func TestIssueSession_NilUserReturnsErr(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test", InsecureCookie: true, SessionTTL: time.Hour},
	}
	req := httptest.NewRequest("POST", "/auth/login/password", nil)
	w := httptest.NewRecorder()

	err := a.IssueSession(w, req, nil, "")
	assert.ErrorIs(t, err, ErrSessionInvalid)
	assert.Empty(t, w.Result().Cookies())
}

func TestIssueSession_EmptyIDTokenAllowed(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test", InsecureCookie: true, SessionTTL: time.Hour},
	}
	user := &User{Sub: "user-2", Email: "a@b.com"}
	req := httptest.NewRequest("POST", "/auth/login/password", nil)
	w := httptest.NewRecorder()

	err := a.IssueSession(w, req, user, "")
	require.NoError(t, err)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	payload, err := decryptSession(cookies[0].Value, key)
	require.NoError(t, err)
	assert.Equal(t, "", payload.IDToken)
}

// ---------------------------------------------------------------------------
// UserFromContext
// ---------------------------------------------------------------------------

func TestUserFromContext_NilWhenAbsent(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.Nil(t, UserFromContext(req.Context()))
}

func TestUserFromContext_ReturnsUser(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	ctx := contextWithUser(req.Context(), &User{Sub: "test-sub", Email: "a@b.com"})
	u := UserFromContext(ctx)
	require.NotNil(t, u)
	assert.Equal(t, "test-sub", u.Sub)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

