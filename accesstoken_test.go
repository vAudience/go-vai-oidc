package vaioidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// retainAuth builds an Auth wired only enough to exercise AccessToken: a
// sessionKey, a logger, and (optionally) a provider whose oauth2 token endpoint
// is `tokenURL`. New()/discovery is intentionally bypassed.
func retainAuth(t *testing.T, retain bool, tokenURL string) ([]byte, *Auth) {
	t.Helper()
	key := testKey(t)
	return key, &Auth{
		provider: &oidcProvider{
			oauth2Cfg: oauth2.Config{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				Endpoint:     oauth2.Endpoint{TokenURL: tokenURL},
			},
		},
		sessionKey: key,
		cfg: Config{
			RetainTokens:   retain,
			CookieName:     "vai_test",
			CookiePath:     "/",
			InsecureCookie: true,
		},
		logger: discardLogger(),
	}
}

// requestWithSession returns a GET request carrying a session cookie that
// encrypts `payload` under `key`.
func requestWithSession(t *testing.T, key []byte, payload *sessionPayload) *http.Request {
	t.Helper()
	enc, err := encryptSession(payload, key)
	if err != nil {
		t.Fatalf("encryptSession: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: enc})
	return req
}

func TestSessionPayload_RetainedTokensRoundTrip(t *testing.T) {
	key := testKey(t)
	in := &sessionPayload{
		Sub:            "user-1",
		IDToken:        "id.jwt",
		Exp:            time.Now().Add(time.Hour).Unix(),
		AccessToken:    "access.jwt",
		RefreshToken:   "refresh.jwt",
		AccessTokenExp: time.Now().Add(5 * time.Minute).Unix(),
	}
	enc, err := encryptSession(in, key)
	if err != nil {
		t.Fatalf("encryptSession: %v", err)
	}
	out, err := decryptSession(enc, key)
	if err != nil {
		t.Fatalf("decryptSession: %v", err)
	}
	if out.AccessToken != in.AccessToken || out.RefreshToken != in.RefreshToken || out.AccessTokenExp != in.AccessTokenExp {
		t.Errorf("retained tokens not round-tripped: got %+v", out)
	}
}

func TestAccessToken_RetentionDisabled(t *testing.T) {
	key, a := retainAuth(t, false, "http://127.0.0.1:1/never")
	req := requestWithSession(t, key, &sessionPayload{
		Sub: "u", Exp: time.Now().Add(time.Hour).Unix(), AccessToken: "access.jwt",
	})
	if _, err := a.AccessToken(httptest.NewRecorder(), req); !errors.Is(err, ErrTokensNotRetained) {
		t.Fatalf("want ErrTokensNotRetained, got %v", err)
	}
}

func TestAccessToken_SessionWithoutToken(t *testing.T) {
	key, a := retainAuth(t, true, "http://127.0.0.1:1/never")
	req := requestWithSession(t, key, &sessionPayload{Sub: "u", Exp: time.Now().Add(time.Hour).Unix()})
	if _, err := a.AccessToken(httptest.NewRecorder(), req); !errors.Is(err, ErrTokensNotRetained) {
		t.Fatalf("want ErrTokensNotRetained for token-less session, got %v", err)
	}
}

func TestAccessToken_ValidTokenNoRefresh(t *testing.T) {
	// TokenURL points at a server that fails the test if hit — a non-expired
	// token must be returned as-is with no refresh round-trip and no rewrite.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("token endpoint must not be called for a valid token")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	key, a := retainAuth(t, true, srv.URL)
	req := requestWithSession(t, key, &sessionPayload{
		Sub:            "u",
		Exp:            time.Now().Add(time.Hour).Unix(),
		AccessToken:    "valid.access",
		RefreshToken:   "refresh.jwt",
		AccessTokenExp: time.Now().Add(30 * time.Minute).Unix(),
	})
	w := httptest.NewRecorder()
	got, err := a.AccessToken(w, req)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got != "valid.access" {
		t.Errorf("token = %q, want valid.access", got)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Errorf("expected no cookie rewrite for a valid token, got %d", len(w.Result().Cookies()))
	}
}

func TestAccessToken_ExpiredTriggersRefreshAndPersist(t *testing.T) {
	// Minimal OAuth2 token endpoint returning a rotated access+refresh pair.
	var gotGrant, gotRefresh string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotGrant = r.Form.Get("grant_type")
		gotRefresh = r.Form.Get("refresh_token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new.access",
			"refresh_token": "new.refresh",
			"token_type":    "Bearer",
			"expires_in":    300,
		})
	}))
	t.Cleanup(srv.Close)

	key, a := retainAuth(t, true, srv.URL)
	origExp := time.Now().Add(time.Hour).Unix()
	req := requestWithSession(t, key, &sessionPayload{
		Sub:            "u",
		Exp:            origExp,
		AccessToken:    "old.access",
		RefreshToken:   "old.refresh",
		AccessTokenExp: time.Now().Add(-time.Minute).Unix(), // expired
	})
	w := httptest.NewRecorder()
	got, err := a.AccessToken(w, req)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got != "new.access" {
		t.Errorf("token = %q, want refreshed new.access", got)
	}
	if gotGrant != "refresh_token" || gotRefresh != "old.refresh" {
		t.Errorf("refresh request = grant %q refresh %q, want refresh_token/old.refresh", gotGrant, gotRefresh)
	}

	// The rotated tokens must be persisted back into a rewritten cookie.
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 rewritten cookie, got %d", len(cookies))
	}
	persisted, err := decryptSession(cookies[0].Value, key)
	if err != nil {
		t.Fatalf("decrypt rewritten cookie: %v", err)
	}
	if persisted.AccessToken != "new.access" || persisted.RefreshToken != "new.refresh" {
		t.Errorf("persisted tokens = %q/%q, want new.access/new.refresh", persisted.AccessToken, persisted.RefreshToken)
	}
	if persisted.Sub != "u" || persisted.Exp != origExp {
		t.Errorf("session identity/Exp must be preserved across refresh: sub=%q exp=%d (want exp=%d)", persisted.Sub, persisted.Exp, origExp)
	}
}
