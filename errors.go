package vaioidc

import "errors"

// Sentinel errors for programmatic handling via errors.Is().

// Config errors — returned by New().
var (
	// ErrInvalidConfig indicates one or more required Config fields are missing or invalid.
	ErrInvalidConfig = errors.New("vai-oidc: invalid configuration")

	// ErrSessionKeyInvalid indicates the SessionSecret is not valid base64 or not 32 bytes.
	ErrSessionKeyInvalid = errors.New("vai-oidc: session secret must be base64-encoded 32 bytes")

	// ErrDiscoveryFailed indicates OIDC provider discovery failed (network error or bad issuer URL).
	ErrDiscoveryFailed = errors.New("vai-oidc: OIDC provider discovery failed")
)

// Session errors — returned by middleware or session helpers.
var (
	// ErrSessionExpired indicates the session cookie exists but has passed its TTL.
	ErrSessionExpired = errors.New("vai-oidc: session expired")

	// ErrSessionInvalid indicates the session cookie could not be decrypted (tampered or wrong key).
	ErrSessionInvalid = errors.New("vai-oidc: session cookie invalid or tampered")

	// ErrNoSession indicates no session cookie was present on the request.
	ErrNoSession = errors.New("vai-oidc: no session cookie present")
)

// OIDC flow errors — logged internally by handlers; handlers redirect gracefully.
var (
	// ErrStateMismatch indicates the OIDC state parameter did not match the stored state.
	ErrStateMismatch = errors.New("vai-oidc: OIDC state mismatch")

	// ErrTokenExchange indicates the authorization code could not be exchanged for tokens.
	ErrTokenExchange = errors.New("vai-oidc: token exchange failed")

	// ErrTokenVerification indicates the ID token signature or claims could not be verified.
	ErrTokenVerification = errors.New("vai-oidc: ID token verification failed")
)
