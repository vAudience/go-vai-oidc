package vaioidc

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

// TestAuth is a test-only Auth instance with no real OIDC provider.
// Use NewTestAuth to create one, then SetTestUser to inject users into requests.
type TestAuth struct {
	*Auth
}

// NewTestAuth creates an Auth instance suitable for testing.
// It uses a random session key and no OIDC provider (login/callback routes will
// redirect to "/" but middleware and session crypto work normally).
func NewTestAuth(t *testing.T) *TestAuth {
	if t != nil {
		t.Helper()
	}

	key := make([]byte, aesKeyLength)
	if _, err := rand.Read(key); err != nil {
		if t != nil {
			t.Fatalf("vai-oidc: NewTestAuth: generate key: %v", err)
		}
		panic("vai-oidc: NewTestAuth: generate key: " + err.Error())
	}

	return &TestAuth{
		Auth: &Auth{
			sessionKey: key,
			cfg: Config{
				CookieName:     "vai_test_session",
				CookiePath:     "/",
				LogoutRedirect: "/",
				InsecureCookie: true,
				SessionTTL:     time.Hour,
				Logger:         slog.Default(),
			},
			logger:   slog.Default(),
			provider: &oidcProvider{},
		},
	}
}

// SetTestUser injects an authenticated User into the request context.
// Use this in handler tests to simulate an authenticated request without
// going through the full OIDC login flow.
//
//	req := httptest.NewRequest("GET", "/dashboard", nil)
//	req = testAuth.SetTestUser(req, &vaioidc.User{Sub: "user-1", Email: "a@b.com"})
func (ta *TestAuth) SetTestUser(r *http.Request, user *User) *http.Request {
	ctx := contextWithUser(r.Context(), user)
	return r.WithContext(ctx)
}

// TestSessionCookie creates a valid encrypted session cookie for the given user.
// Add it to an httptest.Request to simulate an authenticated browser request
// that will pass through RequireSession middleware.
//
//	cookie := testAuth.TestSessionCookie(t, &vaioidc.User{Sub: "user-1"})
//	req.AddCookie(cookie)
func (ta *TestAuth) TestSessionCookie(t *testing.T, user *User) *http.Cookie {
	if t != nil {
		t.Helper()
	}

	payload := &sessionPayload{
		Sub:   user.Sub,
		Email: user.Email,
		Name:  user.Name,
		Exp:   time.Now().UTC().Add(ta.cfg.SessionTTL).Unix(),
	}

	encrypted, err := encryptSession(payload, ta.sessionKey)
	if err != nil {
		if t != nil {
			t.Fatalf("vai-oidc: TestSessionCookie: encrypt: %v", err)
		}
		panic("vai-oidc: TestSessionCookie: encrypt: " + err.Error())
	}

	return &http.Cookie{
		Name:  ta.cfg.CookieName,
		Value: encrypted,
	}
}

// TestSessionSecret returns a random base64-encoded 32-byte key
// suitable for use as Config.SessionSecret in tests.
func TestSessionSecret(t *testing.T) string {
	t.Helper()
	key := make([]byte, aesKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("vai-oidc: TestSessionSecret: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}
