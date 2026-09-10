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

// Token-retention errors (v0.12.0) — returned by Auth.AccessToken().
var (
	// ErrTokensNotRetained indicates Auth.AccessToken was called but the
	// access/refresh tokens are not available: either Config.RetainTokens is
	// false, or the session predates retention being enabled (e.g. an
	// IssueSession cookie). Re-login to obtain a token-bearing session.
	ErrTokensNotRetained = errors.New("vai-oidc: access token not retained in session")

	// ErrTokenRefreshFailed indicates a stored access token had expired and
	// the refresh attempt against Keycloak failed (refresh token expired,
	// SSO session ended, or Keycloak unreachable). The caller should treat
	// this as "re-authentication required".
	ErrTokenRefreshFailed = errors.New("vai-oidc: access token refresh failed")
)

// Session-revalidation errors (v0.19.0) — Option B of the "one logout" design.
var (
	// ErrSessionRevoked indicates the IdP explicitly refused this session's
	// refresh token with `invalid_grant`. Keycloak returns that when the SSO
	// session behind the token has ended — most commonly because the person
	// signed out of a SIBLING product. It is the one refusal that means "this
	// person is no longer signed in", as opposed to "the IdP could not answer
	// right now", and it is therefore the only one the revalidation floor fails
	// CLOSED on.
	//
	// ⛔ Deliberately distinct from ErrTokenRefreshFailed, which covers EVERY
	// refresh failure including transport errors. Collapsing the two would make
	// a single Keycloak blip sign the entire fleet out at once — the failure
	// mode that makes revalidation more dangerous than the gap it closes.
	ErrSessionRevoked = errors.New("vai-oidc: session revoked at the identity provider")
)

// Identity-gate errors — returned by the Config.RequireEmailDomain gate.
var (
	// ErrEmailDomainMismatch indicates the verified id_token's email
	// claim domain did not match Config.RequireEmailDomain.
	ErrEmailDomainMismatch = errors.New("vai-oidc: email domain does not match required domain")

	// ErrEmailClaimMissing indicates Config.RequireEmailDomain is set
	// but the verified id_token's email claim is missing or malformed
	// (no `@` separator). The login is rejected — the gate cannot
	// prove a match without a parseable email.
	ErrEmailClaimMissing = errors.New("vai-oidc: email claim missing or malformed; cannot enforce required domain")
)
