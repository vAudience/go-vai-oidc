package vaioidc

import "time"

// Cookie names.
const (
	defaultCookieName  = "vai_session"
	cookieOIDCState    = "vai_oidc_state"
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
	pkceVerifierBytes   = 32
	pkceChallengeMethod = "S256"
)

// Crypto.
const (
	aesKeyLength = 32 // AES-256
	stateBytes   = 32
)

// CookieSizeWarnThreshold is the encoded session-cookie size (bytes) above
// which setSessionCookie logs a warning. Browsers cap a single cookie at
// ~4096 bytes; retaining Keycloak access+refresh tokens (Config.RetainTokens)
// can approach that. The threshold leaves headroom for the cookie name +
// attributes. DC-APIKEY-03 (v0.12.0).
const CookieSizeWarnThreshold = 3500

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
	logKeyCookieBytes    = "cookie_bytes"
)

// Token-retention log messages (DC-APIKEY-03, v0.12.0).
const (
	logMsgCookieLarge      = "vai-oidc: session cookie is large; browsers cap a single cookie at ~4KB"
	logMsgTokenRefreshed   = "vai-oidc: refreshed Keycloak access token"
	logMsgTokenPersistFail = "vai-oidc: failed to persist refreshed tokens (returning valid token anyway)"
)

// Discovery retry (DC-OIDC-RETRY-01, v0.8.0).
const (
	// DiscoveryRetryBudgetDefault is the default wall-clock budget
	// New() spends retrying transient OIDC discovery failures
	// before giving up. Public so consumers can override with
	// `cfg.DiscoveryRetryBudget = DiscoveryRetryBudgetDefault / 2`
	// or similar without hardcoding the value.
	DiscoveryRetryBudgetDefault = 90 * time.Second

	// discoveryRetryPerAttemptTimeout bounds any single discovery
	// attempt so one slow probe cannot consume the whole budget.
	// Calls inside the loop derive a child context with this
	// timeout (or the remaining budget, whichever is smaller).
	discoveryRetryPerAttemptTimeout = 15 * time.Second

	// discoveryRetryBaseDelay is the first backoff sleep. Doubles
	// each attempt up to discoveryRetryMaxDelay; jitter ±50%.
	discoveryRetryBaseDelay = 500 * time.Millisecond
	discoveryRetryMaxDelay  = 8 * time.Second
)

// Discovery retry log keys + messages.
const (
	logKeyDiscoveryAttempt = "attempt"
	logKeyDiscoveryElapsed = "elapsed"
	logKeyDiscoveryBackoff = "next_backoff"
	logMsgDiscoveryRetry   = "vai-oidc: discovery retry attempt"
	logMsgDiscoverySuccess = "vai-oidc: discovery succeeded after retry"
)

// Email-domain gate.
const (
	emailAtSeparator                 = "@"
	requireEmailDomainForbiddenRunes = "@ \t\r\n"
	logMsgEmailDomainRejected        = "OIDC callback: email domain rejected"
	logReasonEmailDomainMismatch     = "email_domain_mismatch"
	logReasonEmailDomainMissingClaim = "email_claim_missing_or_malformed"
)
