package vaioidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// sessionPayload is the encrypted cookie content.
// The IDToken field stores the raw JWT for Keycloak RP-Initiated Logout (id_token_hint).
// Trade-off: adds ~1KB to cookie size but enables seamless federated logout without a
// Keycloak confirmation page. The token is protected by AES-256-GCM encryption — if the
// session key is compromised, the JWT is exposed, but so is the entire session.
type sessionPayload struct {
	Sub     string            `json:"sub"`
	Email   string            `json:"email"`
	Name    string            `json:"name"`
	OrgID   string            `json:"oid,omitempty"` // organization ID (resolved by UserResolver)
	Claims  map[string]string `json:"clm,omitempty"` // extra claims from ExtraClaims config
	IDToken string            `json:"idt"`            // raw ID token for Keycloak logout hint
	Exp     int64             `json:"exp"`            // unix timestamp
}

// toUser converts the payload to a public User.
func (p *sessionPayload) toUser() *User {
	return &User{
		Sub:    p.Sub,
		Email:  p.Email,
		Name:   p.Name,
		OrgID:  p.OrgID,
		Claims: p.Claims,
	}
}

// fromUser updates the payload's user-visible fields from a User.
// Preserves IDToken and Exp.
func (p *sessionPayload) fromUser(u *User) {
	p.Sub = u.Sub
	p.Email = u.Email
	p.Name = u.Name
	p.OrgID = u.OrgID
	p.Claims = u.Claims
}

// encryptSession serializes and encrypts a session payload.
// Returns a base64url-encoded string suitable for cookie storage.
func encryptSession(payload *sessionPayload, key []byte) (string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", ErrSessionInvalid)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", ErrSessionInvalid)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", ErrSessionInvalid)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", ErrSessionInvalid)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// decryptSession decrypts and deserializes a session payload.
// Returns an error wrapping ErrSessionInvalid (tampered/wrong key) or ErrSessionExpired.
func decryptSession(encoded string, key []byte) (*sessionPayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", ErrSessionInvalid)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", ErrSessionInvalid)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", ErrSessionInvalid)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %w", ErrSessionInvalid)
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", ErrSessionInvalid)
	}

	var payload sessionPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", ErrSessionInvalid)
	}

	if time.Now().UTC().Unix() > payload.Exp {
		return nil, fmt.Errorf("expired at %d: %w", payload.Exp, ErrSessionExpired)
	}

	return &payload, nil
}

// setSessionCookie encrypts the payload and writes the session cookie.
func setSessionCookie(w http.ResponseWriter, payload *sessionPayload, key []byte, cookieName, cookiePath string, secure bool) error {
	encrypted, err := encryptSession(payload, key)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    encrypted,
		Path:     cookiePath,
		Expires:  time.Unix(payload.Exp, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// readSessionCookie reads and decrypts the session cookie from the request.
// Returns an error wrapping ErrNoSession, ErrSessionInvalid, or ErrSessionExpired.
func readSessionCookie(r *http.Request, key []byte, cookieName string) (*sessionPayload, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, fmt.Errorf("cookie %q: %w", cookieName, ErrNoSession)
	}
	return decryptSession(cookie.Value, key)
}

// clearSessionCookie removes the session cookie.
// The secure flag must match the original cookie's Secure attribute for browsers to clear it.
func clearSessionCookie(w http.ResponseWriter, cookieName, cookiePath string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// setOIDCCookie writes a short-lived cookie for OIDC state/verifier parameters.
func setOIDCCookie(w http.ResponseWriter, name, value, path string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   oidcCookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearOIDCCookie removes an OIDC state/verifier cookie.
func clearOIDCCookie(w http.ResponseWriter, name, path string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
