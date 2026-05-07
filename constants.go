package vaioidc

import "time"

// Cookie names.
const (
	defaultCookieName = "vai_session"
	cookieOIDCState   = "vai_oidc_state"
	cookiePKCEVerifier = "vai_pkce_verifier"
)

// Cookie defaults.
const (
	defaultCookiePath     = "/"
	defaultLogoutRedirect = "/"
	defaultLoginPath      = "/auth/login"
	defaultSessionTTL     = 24 * time.Hour
	oidcCookieMaxAge      = 300 // 5 minutes for state/PKCE cookies
)

// OIDC scopes.
const (
	scopeOpenID  = "openid"
	scopeProfile = "profile"
	scopeEmail   = "email"
)

// OIDC query parameters (standard OAuth2/OIDC).
const (
	queryParamState            = "state"
	queryParamCode             = "code"
	queryParamError            = "error"
	queryParamErrorDescription = "error_description"
	queryParamRedirect         = "redirect"
)

// OIDC token fields.
const (
	extraIDToken = "id_token"
)

// ID token claim names.
const (
	claimEmail             = "email"
	claimName              = "name"
	claimPreferredUsername = "preferred_username"
)

// PKCE parameters.
const (
	pkceVerifierBytes  = 32
	pkceChallengeMethod = "S256"
)

// Crypto.
const (
	aesKeyLength  = 32 // AES-256
	stateBytes    = 32
)

// Keycloak issuer URL template: BaseURL + "/realms/" + Realm.
const keycloakIssuerTemplate = "%s/realms/%s"

// State cookie delimiter — separates OIDC state from redirect path.
const stateCookieDelimiter = "|"

// Route paths (relative to mount point).
const (
	pathLogin    = "/login"
	pathCallback = "/callback"
	pathLogout   = "/logout"
)

// Log component.
const logComponent = "vai-oidc"

// Log keys.
const (
	logKeyComponent      = "component"
	logKeyClientID       = "client_id"
	logKeyIssuer         = "issuer"
	logKeyError          = "error"
	logKeySub            = "sub"
	logKeyEmail          = "email"
	logKeyReason         = "reason"
	logKeyClientIP       = "client_ip"
	logKeyPath           = "path"
	logKeyEmailDomain    = "email_domain"
	logKeyRequiredDomain = "required_domain"
)

// Email-domain gate.
const (
	emailAtSeparator                  = "@"
	requireEmailDomainForbiddenRunes  = "@ \t\r\n"
	logMsgEmailDomainRejected         = "OIDC callback: email domain rejected"
	logReasonEmailDomainMismatch      = "email_domain_mismatch"
	logReasonEmailDomainMissingClaim  = "email_claim_missing_or_malformed"
)
