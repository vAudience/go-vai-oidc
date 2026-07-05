package vaioidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, aesKeyLength)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub:     "user-123",
		Email:   "test@vaudience.ai",
		Name:    "Test User",
		IDToken: "eyJhbGciOiJSUzI1NiJ9.test.signature",
		Exp:     time.Now().UTC().Add(time.Hour).Unix(),
	}

	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := decryptSession(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, payload.Sub, decrypted.Sub)
	assert.Equal(t, payload.Email, decrypted.Email)
	assert.Equal(t, payload.Name, decrypted.Name)
	assert.Equal(t, payload.IDToken, decrypted.IDToken)
	assert.Equal(t, payload.Exp, decrypted.Exp)
}

func TestEncryptDecrypt_DifferentCiphertextEachTime(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub: "user-123",
		Exp: time.Now().UTC().Add(time.Hour).Unix(),
	}

	enc1, err := encryptSession(payload, key)
	require.NoError(t, err)

	enc2, err := encryptSession(payload, key)
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "same plaintext should produce different ciphertext (unique nonce)")
}

func TestDecrypt_ExpiredSession(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub: "user-123",
		Exp: time.Now().UTC().Add(-time.Hour).Unix(), // expired 1h ago
	}

	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	_, err = decryptSession(encrypted, key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionExpired))
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	payload := &sessionPayload{
		Sub: "user-123",
		Exp: time.Now().UTC().Add(time.Hour).Unix(),
	}

	encrypted, err := encryptSession(payload, key1)
	require.NoError(t, err)

	_, err = decryptSession(encrypted, key2)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionInvalid))
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub: "user-123",
		Exp: time.Now().UTC().Add(time.Hour).Unix(),
	}

	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	// Flip a byte in the middle.
	tampered := []byte(encrypted)
	tampered[len(tampered)/2] ^= 0xFF
	_, err = decryptSession(string(tampered), key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionInvalid))
}

func TestDecrypt_EmptyString(t *testing.T) {
	key := testKey(t)
	_, err := decryptSession("", key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionInvalid))
}

func TestDecrypt_GarbageInput(t *testing.T) {
	key := testKey(t)
	_, err := decryptSession("not-valid-base64!!!", key)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionInvalid))
}

func TestSessionPayload_ToUser(t *testing.T) {
	p := &sessionPayload{
		Sub:    "sub-1",
		Email:  "a@b.com",
		Name:   "A B",
		OrgID:  "org-uuid",
		Mbs:    []Membership{{OrgID: "org-uuid", OrgName: "Org", Role: "owner"}, {OrgID: "org-2"}},
		Claims: map[string]string{"dept": "eng"},
	}
	u := p.toUser()
	assert.Equal(t, "sub-1", u.Sub)
	assert.Equal(t, "a@b.com", u.Email)
	assert.Equal(t, "A B", u.Name)
	assert.Equal(t, "org-uuid", u.OrgID)
	assert.Equal(t, "eng", u.Claims["dept"])
	assert.Len(t, u.Memberships, 2)
	assert.Equal(t, "owner", u.Memberships[0].Role)
	assert.Equal(t, "org-2", u.Memberships[1].OrgID)
}

func TestSessionPayload_FromUser(t *testing.T) {
	p := &sessionPayload{
		Sub:     "original-sub",
		Email:   "old@email.com",
		IDToken: "keep-this",
		Exp:     12345,
	}
	u := &User{
		Sub:         "new-sub",
		Email:       "new@email.com",
		Name:        "New Name",
		OrgID:       "new-org",
		Memberships: []Membership{{OrgID: "new-org"}, {OrgID: "other-org", OrgSlug: "other"}},
		Claims:      map[string]string{"key": "val"},
	}
	p.fromUser(u)
	assert.Equal(t, "new-sub", p.Sub)
	assert.Equal(t, "new@email.com", p.Email)
	assert.Equal(t, "New Name", p.Name)
	assert.Equal(t, "new-org", p.OrgID)
	assert.Equal(t, "val", p.Claims["key"])
	assert.Len(t, p.Mbs, 2)
	assert.Equal(t, "other", p.Mbs[1].OrgSlug)
	// IDToken and Exp preserved
	assert.Equal(t, "keep-this", p.IDToken)
	assert.Equal(t, int64(12345), p.Exp)
}

// TestSessionPayload_ToUser_RealmRoles and its FromUser counterpart pin that
// RealmRoles (v0.15.0) rides through toUser/fromUser like every other
// User-visible field — the exact field-drift class fixed for Memberships in
// v0.14.1.
func TestSessionPayload_ToUser_RealmRoles(t *testing.T) {
	p := &sessionPayload{Sub: "sub-1", Rls: []string{"obol-system-admin", "offline_access"}}
	u := p.toUser()
	assert.Equal(t, []string{"obol-system-admin", "offline_access"}, u.RealmRoles)
}

func TestSessionPayload_FromUser_RealmRoles(t *testing.T) {
	p := &sessionPayload{}
	u := &User{Sub: "s", RealmRoles: []string{"obol-system-admin"}}
	p.fromUser(u)
	assert.Equal(t, []string{"obol-system-admin"}, p.Rls)
}

// TestEncryptDecrypt_RoundTrip_WithRealmRoles pins that RealmRoles survives
// the encrypted-cookie round-trip, so a system-admin check on a later request
// sees the same roles the login-time ID token carried.
func TestEncryptDecrypt_RoundTrip_WithRealmRoles(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub: "user-admin",
		Rls: []string{"obol-system-admin"},
		Exp: time.Now().UTC().Add(time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)
	decrypted, err := decryptSession(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, []string{"obol-system-admin"}, decrypted.Rls)
}

// TestEncryptDecrypt_RoundTrip_WithMemberships pins that the additive
// multi-org membership set (v0.14.0) survives the encrypted-cookie round-trip,
// so a consumer's org-picker still has the candidate orgs on the next request.
func TestEncryptDecrypt_RoundTrip_WithMemberships(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub:   "user-mbs",
		Email: "m@vaudience.ai",
		OrgID: "org-alpha",
		Mbs: []Membership{
			{OrgID: "org-alpha", OrgName: "Alpha", OrgSlug: "alpha", Role: "owner"},
			{OrgID: "org-beta", OrgName: "Beta", Role: "member"},
		},
		Exp: time.Now().UTC().Add(time.Hour).Unix(),
	}
	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)
	decrypted, err := decryptSession(encrypted, key)
	require.NoError(t, err)
	require.Len(t, decrypted.Mbs, 2)
	assert.Equal(t, "org-alpha", decrypted.Mbs[0].OrgID)
	assert.Equal(t, "Alpha", decrypted.Mbs[0].OrgName)
	assert.Equal(t, "alpha", decrypted.Mbs[0].OrgSlug)
	assert.Equal(t, "owner", decrypted.Mbs[0].Role)
	assert.Equal(t, "org-beta", decrypted.Mbs[1].OrgID)
	assert.Equal(t, "member", decrypted.Mbs[1].Role)
}

// TestCallbackPayloadConstruction_PersistsMemberships pins the regression fixed
// in v0.14.1: handleCallback used to build the session payload with a hand-rolled
// struct literal that omitted Mbs, so a multi-org user's membership set was
// resolved but never written to the cookie — UserFromContext on the next request
// saw an empty Memberships slice and the consumer's org-picker never triggered.
// This test reproduces the EXACT construction the callback now uses
// ({IDToken,Exp} literal + fromUser) and drives it through the real session read
// path (OptionalSession → UserFromContext), so any future refactor that drops a
// User field on the write side fails here instead of silently in production.
func TestCallbackPayloadConstruction_PersistsMemberships(t *testing.T) {
	key := testKey(t)
	a := &Auth{
		sessionKey: key,
		cfg:        Config{CookieName: "vai_test"},
	}

	resolvedUser := &User{
		Sub:   "multi-org-user",
		Email: "multi@vaudience.ai",
		Name:  "Multi Org",
		OrgID: "org-alpha", // resolver's default pick (memberships[0])
		Memberships: []Membership{
			{OrgID: "org-alpha", OrgName: "Alpha", OrgSlug: "alpha", Role: "owner"},
			{OrgID: "org-beta", OrgName: "Beta", OrgSlug: "beta", Role: "member"},
		},
		Claims: map[string]string{"aif_role": "user"},
	}

	// Mirror handleCallback's session construction verbatim.
	payload := &sessionPayload{
		IDToken: "raw-id-token",
		Exp:     time.Now().UTC().Add(time.Hour).Unix(),
	}
	payload.fromUser(resolvedUser)

	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	var captured *User
	handler := a.OptionalSession()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "vai_test", Value: encrypted})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, captured)
	require.Len(t, captured.Memberships, 2, "callback-written session must carry the full membership set")
	assert.Equal(t, "org-alpha", captured.OrgID)
	assert.Equal(t, "org-beta", captured.Memberships[1].OrgID)
	assert.Equal(t, "member", captured.Memberships[1].Role)
	// IDToken + Exp must survive fromUser (they are session-only fields).
	assert.NotZero(t, payload.Exp)
	assert.Equal(t, "raw-id-token", payload.IDToken)
}

func TestEncryptDecrypt_RoundTrip_WithOrgIDAndClaims(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub:     "user-456",
		Email:   "test@vaudience.ai",
		Name:    "Test",
		OrgID:   "00000000-0000-0000-0000-000000000000",
		Claims:  map[string]string{"tenant": "acme", "role": "admin"},
		IDToken: "jwt-token",
		Exp:     time.Now().UTC().Add(time.Hour).Unix(),
	}

	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)

	decrypted, err := decryptSession(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, payload.OrgID, decrypted.OrgID)
	assert.Equal(t, payload.Claims, decrypted.Claims)
	assert.Equal(t, "acme", decrypted.Claims["tenant"])
}

func TestSetAndReadSessionCookie(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub:   "user-456",
		Email: "test@example.com",
		Exp:   time.Now().UTC().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	err := setSessionCookie(w, payload, key, "vai_test", "/", false, nil)
	require.NoError(t, err)

	// Extract cookie from response and put it on a new request.
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "vai_test", cookies[0].Name)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])

	read, err := readSessionCookie(req, key, "vai_test")
	require.NoError(t, err)
	assert.Equal(t, payload.Sub, read.Sub)
	assert.Equal(t, payload.Email, read.Email)
}

func TestReadSessionCookie_Missing(t *testing.T) {
	key := testKey(t)
	req := httptest.NewRequest("GET", "/", nil)

	_, err := readSessionCookie(req, key, "vai_test")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoSession))
}

func TestClearSessionCookie(t *testing.T) {
	w := httptest.NewRecorder()
	clearSessionCookie(w, "vai_test", "/", false)

	// The base cookie plus every possible chunk slot are evicted (v0.13.0), so a
	// previously chunked session is fully cleared on logout.
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1+maxSessionCookieChunks)
	assert.Equal(t, "vai_test", cookies[0].Name)
	for i, c := range cookies {
		assert.Equal(t, -1, c.MaxAge, "cookie %d (%s) should be a deletion cookie", i, c.Name)
		assert.Empty(t, c.Value)
	}
	assert.Equal(t, "vai_test_1", cookies[1].Name)
	assert.Equal(t, chunkCookieName("vai_test", maxSessionCookieChunks), cookies[maxSessionCookieChunks].Name)
}

// TestSessionCookieChunking is the v0.13.0 regression guard: a session whose
// encrypted payload exceeds a single cookie (Config.RetainTokens storing
// Keycloak access+refresh tokens) must be split across multiple cookies and
// reassemble losslessly — without chunking the browser silently drops the
// oversized cookie and the user is stuck in an endless login redirect.
func TestSessionCookieChunking(t *testing.T) {
	key := testKey(t)
	// A realistic RetainTokens payload: three large JWT-shaped blobs that, once
	// encrypted + base64url-encoded, exceed maxCookieValueBytes.
	big := strings.Repeat("x", 3000)
	payload := &sessionPayload{
		Sub:          "user-123",
		Email:        "user@example.com",
		IDToken:      "id." + big,
		AccessToken:  "at." + big,
		RefreshToken: "rt." + big,
		Exp:          time.Now().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	require.NoError(t, setSessionCookie(w, payload, key, "vai_test", "/", false, nil))

	cookies := w.Result().Cookies()
	require.Greater(t, len(cookies), 1, "oversized session must be chunked into >1 cookie")
	// The base cookie carries the "chunked:N" header, never the payload, and no
	// single cookie value exceeds the per-cookie cap.
	require.Equal(t, "vai_test", cookies[0].Name)
	assert.True(t, strings.HasPrefix(cookies[0].Value, chunkCountPrefix),
		"base cookie must hold the chunk header, got %q", cookies[0].Value)
	for _, c := range cookies {
		assert.LessOrEqual(t, len(c.Value), maxCookieValueBytes,
			"cookie %s value %d bytes exceeds the per-cookie cap", c.Name, len(c.Value))
	}

	// Reassembly round-trips losslessly.
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	read, err := readSessionCookie(req, key, "vai_test")
	require.NoError(t, err)
	assert.Equal(t, payload.Sub, read.Sub)
	assert.Equal(t, payload.AccessToken, read.AccessToken)
	assert.Equal(t, payload.RefreshToken, read.RefreshToken)
	assert.Equal(t, payload.IDToken, read.IDToken)
}

// TestSessionCookieChunking_MissingChunk verifies a torn chunk set fails closed
// (treated as an invalid session → re-login), never a partial decrypt.
func TestSessionCookieChunking_MissingChunk(t *testing.T) {
	key := testKey(t)
	big := strings.Repeat("y", 3000)
	payload := &sessionPayload{
		Sub: "user-123", IDToken: "id." + big, AccessToken: "at." + big,
		RefreshToken: "rt." + big, Exp: time.Now().Add(time.Hour).Unix(),
	}
	w := httptest.NewRecorder()
	require.NoError(t, setSessionCookie(w, payload, key, "vai_test", "/", false, nil))

	// Drop the last data chunk to simulate a browser that didn't store it.
	cookies := w.Result().Cookies()
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies[:len(cookies)-1] {
		req.AddCookie(c)
	}
	_, err := readSessionCookie(req, key, "vai_test")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionInvalid))
}

// TestSessionCookieChunking_TooLarge verifies the write path refuses (rather
// than silently truncating) a session that needs more than maxSessionCookieChunks
// — reachable in production with an unusually claims-rich Keycloak token set.
func TestSessionCookieChunking_TooLarge(t *testing.T) {
	key := testKey(t)
	huge := strings.Repeat("z", maxSessionCookieChunks*maxCookieValueBytes+1)
	payload := &sessionPayload{
		Sub: "user-123", AccessToken: huge, Exp: time.Now().Add(time.Hour).Unix(),
	}
	w := httptest.NewRecorder()
	err := setSessionCookie(w, payload, key, "vai_test", "/", false, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionInvalid))
}

func TestOIDCCookie_SetAndClear(t *testing.T) {
	w := httptest.NewRecorder()
	setOIDCCookie(w, "vai_state", "test-state", "/auth", false)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "vai_state", cookies[0].Name)
	assert.Equal(t, "test-state", cookies[0].Value)
	assert.Equal(t, oidcCookieMaxAge, cookies[0].MaxAge)
	assert.True(t, cookies[0].HttpOnly)

	w2 := httptest.NewRecorder()
	clearOIDCCookie(w2, "vai_state", "/auth", false)
	cookies2 := w2.Result().Cookies()
	require.Len(t, cookies2, 1)
	assert.Equal(t, -1, cookies2[0].MaxAge)
}

func TestEncryptSession_CookieSizeReasonable(t *testing.T) {
	key := testKey(t)
	// Simulate a realistic payload with a ~1KB ID token.
	idToken := base64.RawURLEncoding.EncodeToString(make([]byte, 800))
	payload := &sessionPayload{
		Sub:     "08cfe0c0-049c-4cb5-b2ff-022bbf80b915",
		Email:   "toni.wagner@vaudience.ai",
		Name:    "Toni Wagner",
		IDToken: idToken,
		Exp:     time.Now().UTC().Add(24 * time.Hour).Unix(),
	}

	encrypted, err := encryptSession(payload, key)
	require.NoError(t, err)
	// Cookie value must be under 4096 bytes.
	assert.Less(t, len(encrypted), 4096, "encrypted session cookie should be under 4KB browser limit")
}
