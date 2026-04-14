package vaioidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
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
		Sub:   "sub-1",
		Email: "a@b.com",
		Name:  "A B",
	}
	u := p.toUser()
	assert.Equal(t, "sub-1", u.Sub)
	assert.Equal(t, "a@b.com", u.Email)
	assert.Equal(t, "A B", u.Name)
}

func TestSetAndReadSessionCookie(t *testing.T) {
	key := testKey(t)
	payload := &sessionPayload{
		Sub:   "user-456",
		Email: "test@example.com",
		Exp:   time.Now().UTC().Add(time.Hour).Unix(),
	}

	w := httptest.NewRecorder()
	err := setSessionCookie(w, payload, key, "vai_test", "/", false)
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

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, -1, cookies[0].MaxAge)
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
