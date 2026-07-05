package vaioidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
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
	OrgID   string            `json:"oid,omitempty"` // active organization ID (resolved by UserResolver)
	Mbs     []Membership      `json:"mbs,omitempty"` // full org membership set (v0.14.0; for multi-org pickers)
	Claims  map[string]string `json:"clm,omitempty"` // extra claims from ExtraClaims config
	Rls     []string          `json:"rls,omitempty"` // Keycloak realm roles (v0.15.0; first-class, no ExtraClaims entry needed)
	IDToken string            `json:"idt"`           // raw ID token for Keycloak logout hint
	Exp     int64             `json:"exp"`           // unix timestamp

	// Token retention (DC-APIKEY-03, v0.12.0). Populated only when
	// Config.RetainTokens is true; empty otherwise. AccessToken is the raw
	// Keycloak access token forwardable to downstream APIs; RefreshToken
	// renews it; AccessTokenExp is the access token's own expiry (unix), which
	// is independent of and shorter than the session Exp above.
	AccessToken    string `json:"at,omitempty"`
	RefreshToken   string `json:"rt,omitempty"`
	AccessTokenExp int64  `json:"ate,omitempty"`
}

// toUser converts the payload to a public User.
func (p *sessionPayload) toUser() *User {
	return &User{
		Sub:         p.Sub,
		Email:       p.Email,
		Name:        p.Name,
		OrgID:       p.OrgID,
		Memberships: p.Mbs,
		Claims:      p.Claims,
		RealmRoles:  p.Rls,
	}
}

// fromUser updates the payload's user-visible fields from a User.
// Preserves IDToken and Exp.
func (p *sessionPayload) fromUser(u *User) {
	p.Sub = u.Sub
	p.Email = u.Email
	p.Name = u.Name
	p.OrgID = u.OrgID
	p.Mbs = u.Memberships
	p.Claims = u.Claims
	p.Rls = u.RealmRoles
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

// setSessionCookie encrypts the payload and writes the session cookie(s).
//
// When the encrypted payload fits in a single cookie (≤ maxCookieValueBytes —
// the common case, byte-identical to pre-v0.13 behaviour) it writes one cookie.
// When it does not — which Config.RetainTokens can cause by storing the Keycloak
// access+refresh tokens — the payload is split across the base cookie plus
// cookieName_1..N, with the base cookie holding a "chunked:N" header so the
// reader reassembles exactly N chunks (and ignores stale higher-index remnants
// from a previously larger session). Without chunking, an oversized cookie is
// silently dropped by the browser, leaving the user in an endless login loop.
//
// logger may be nil; when non-nil it warns once when a session is chunked.
func setSessionCookie(w http.ResponseWriter, payload *sessionPayload, key []byte, cookieName, cookiePath string, secure bool, logger *slog.Logger) error {
	encrypted, err := encryptSession(payload, key)
	if err != nil {
		return err
	}

	// Single-cookie fast path: the base cookie carries the payload directly.
	if len(encrypted) <= maxCookieValueBytes {
		writeSessionCookie(w, cookieName, encrypted, cookiePath, payload.Exp, secure)
		return nil
	}

	// Chunked path. The base cookie becomes a "chunked:N" header; the payload
	// lives in cookieName_1..N.
	chunks := chunkString(encrypted, maxCookieValueBytes)
	n := len(chunks)
	if n > maxSessionCookieChunks {
		return fmt.Errorf("session payload of %d bytes needs %d chunks, exceeds max %d: %w",
			len(encrypted), n, maxSessionCookieChunks, ErrSessionInvalid)
	}
	if logger != nil {
		logger.Warn(logMsgCookieLarge,
			slog.String(logKeyComponent, logComponent),
			slog.Int(logKeyCookieBytes, len(encrypted)),
			slog.Int(logKeyCookieChunks, n),
		)
	}
	writeSessionCookie(w, cookieName, chunkCountPrefix+strconv.Itoa(n), cookiePath, payload.Exp, secure)
	for i, c := range chunks {
		writeSessionCookie(w, chunkCookieName(cookieName, i+1), c, cookiePath, payload.Exp, secure)
	}
	return nil
}

// readSessionCookie reads, reassembles, and decrypts the session cookie(s).
// Returns an error wrapping ErrNoSession, ErrSessionInvalid, or ErrSessionExpired.
func readSessionCookie(r *http.Request, key []byte, cookieName string) (*sessionPayload, error) {
	base, err := r.Cookie(cookieName)
	if err != nil {
		return nil, fmt.Errorf("cookie %q: %w", cookieName, ErrNoSession)
	}

	encoded := base.Value
	// A "chunked:N" base cookie signals the payload is split across
	// cookieName_1..N. base64url never contains ':', so this is unambiguous.
	if rest, ok := strings.CutPrefix(encoded, chunkCountPrefix); ok {
		n, perr := strconv.Atoi(rest)
		if perr != nil || n < 1 || n > maxSessionCookieChunks {
			return nil, fmt.Errorf("invalid session chunk header %q: %w", encoded, ErrSessionInvalid)
		}
		var b strings.Builder
		for i := 1; i <= n; i++ {
			c, cerr := r.Cookie(chunkCookieName(cookieName, i))
			if cerr != nil {
				return nil, fmt.Errorf("missing session chunk %d/%d: %w", i, n, ErrSessionInvalid)
			}
			// Bound each chunk to what the write path could legitimately produce,
			// so reassembly allocates at most maxSessionCookieChunks*maxCookieValueBytes
			// regardless of a (non-browser) client sending oversized chunk cookies.
			if len(c.Value) > maxCookieValueBytes {
				return nil, fmt.Errorf("session chunk %d/%d exceeds max size: %w", i, n, ErrSessionInvalid)
			}
			b.WriteString(c.Value)
		}
		encoded = b.String()
	}
	return decryptSession(encoded, key)
}

// clearSessionCookie removes the session cookie and any chunk cookies.
// The secure flag must match the original cookie's Secure attribute for browsers to clear it.
func clearSessionCookie(w http.ResponseWriter, cookieName, cookiePath string, secure bool) {
	expireSessionCookie(w, cookieName, cookiePath, secure)
	// Evict any chunk cookies a prior chunked session may have written. Bounded
	// by maxSessionCookieChunks; harmless when the names don't exist client-side.
	for i := 1; i <= maxSessionCookieChunks; i++ {
		expireSessionCookie(w, chunkCookieName(cookieName, i), cookiePath, secure)
	}
}

// writeSessionCookie writes one session cookie with the standard attributes.
func writeSessionCookie(w http.ResponseWriter, name, value, cookiePath string, exp int64, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cookiePath,
		Expires:  time.Unix(exp, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// expireSessionCookie writes a deletion cookie (MaxAge=-1) for name.
func expireSessionCookie(w http.ResponseWriter, name, cookiePath string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// chunkCookieName returns the cookie name for a 1-based data-chunk index.
func chunkCookieName(base string, i int) string {
	return base + sessionChunkNameSep + strconv.Itoa(i)
}

// chunkString splits s into substrings of at most size bytes each. s is always
// base64url (single-byte runes), so byte-slicing never splits a multibyte rune.
func chunkString(s string, size int) []string {
	var out []string
	for len(s) > size {
		out = append(out, s[:size])
		s = s[size:]
	}
	return append(out, s)
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
