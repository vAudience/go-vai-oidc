package vaioidc

import "time"

// Cookie names.
const (
	defaultCookieName  = "vai_session"
	cookieOIDCState    = "vai_oidc_state"
	cookiePKCEVerifier = "vai_pkce_verifier"

	// cookieOIDCSync marks an in-flight authorization round trip as a SESSION
	// SYNC rather than a login (v0.20.0).
	//
	// ⛔ THE SYNC FLOW DELIBERATELY REUSES THE LOGIN CALLBACK URL, AND THIS
	// COOKIE IS THE PRICE OF THAT. A dedicated `/session/sync/callback` route
	// would have been a cleaner handler — but every realm client in this fleet
	// registers its `redirectUris` as an EXACT string, not a wildcard, so a
	// second redirect URI is a nine-client realm migration coupled to a library
	// release, on the one field DC-PORTAL-REDIRECT-01 measured as the field that
	// decides whether a login works at all. Reusing the registered callback URL
	// makes this change need NO realm edit on either fleet.
	cookieOIDCSync = "vai_oidc_sync"
)

// Cookie defaults.
const (
	defaultCookiePath     = "/"
	defaultLogoutRedirect = "/"
	// defaultPostLoginRedirect preserves the pre-v0.18.0 behaviour exactly, so the
	// new field is purely additive: a consumer that sets nothing lands where it
	// always did.
	defaultPostLoginRedirect = "/"
	defaultLoginPath         = "/auth/login"
	defaultSessionTTL        = 24 * time.Hour
	oidcCookieMaxAge         = 300 // 5 minutes for state/PKCE cookies
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

	// queryParamConsumerReturnTo carries the CONSUMER's absolute post-login
	// destination onto an identity-backend landing URL (v0.18.0).
	//
	// ⚠️ IT IS DELIBERATELY NOT NAMED `return_to`. That name is a same-origin
	// convention across these products — the identity backend's own login screen
	// refuses a value on it that is not a relative path — and handing it a
	// cross-origin absolute URL would be silently dropped at best and an open
	// redirect the first time somebody widened the reader. A distinct name means
	// only code written knowing the value is cross-origin can consume it, and such
	// code must check the origin against an allow-list first.
	queryParamConsumerReturnTo = "consumer_return_to"
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
	claimRealmAccess       = "realm_access"
	claimRealmAccessRoles  = "roles"

	// claimSid is Keycloak's SSO session id, present in ID tokens whenever the
	// realm advertises `backchannel_logout_session_supported` (measured true on
	// both fleets, 2026-09-11). It is what makes "the person signed in again as
	// somebody else" distinguishable from "nothing changed" — `sub` alone cannot
	// tell a NEW session for the SAME person from the original one.
	claimSid = "sid"
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
// which setSessionCookie splits the session across multiple cookies and logs a
// warning. Browsers cap a single cookie at ~4096 bytes; retaining Keycloak
// access+refresh tokens (Config.RetainTokens) can exceed that. The threshold
// leaves headroom for the cookie name + attributes (v0.12.0).
const CookieSizeWarnThreshold = 3500

// Session cookie chunking (v0.13.0). Config.RetainTokens can push the encrypted
// session past the browser's ~4KB single-cookie cap, which the browser silently
// rejects — leaving the user with no session and an endless login redirect. The
// session is therefore split across multiple cookies and reassembled on read.
const (
	// maxCookieValueBytes bounds a single cookie's value so the full Set-Cookie
	// line (name + value + attributes) stays under the ~4096-byte browser limit
	// with headroom. Reuses CookieSizeWarnThreshold as the single source of
	// truth: a value at or below this fits in one cookie, above it is chunked.
	maxCookieValueBytes = CookieSizeWarnThreshold

	// maxSessionCookieChunks caps the number of data chunks — a defense against a
	// pathologically large session (8 × maxCookieValueBytes ≈ 28KB of encrypted
	// payload, far beyond any legitimate token set).
	maxSessionCookieChunks = 8

	// chunkCountPrefix marks the base cookie as a chunk header ("chunked:N")
	// rather than the encrypted payload itself. The payload is base64url-encoded
	// (alphabet A-Za-z0-9-_), which never contains ':', so this sentinel can
	// never collide with a single-cookie value — keeping the single-cookie path
	// byte-identical and backward compatible with pre-v0.13 sessions.
	chunkCountPrefix = "chunked:"

	// sessionChunkNameSep joins the base cookie name and the 1-based chunk index
	// (e.g. "vai_session_1", "vai_session_2").
	sessionChunkNameSep = "_"
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

	// pathSession is the liveness endpoint added in v0.19.0. It performs the
	// same revalidation RequireSession does and reports whether the session is
	// still live, so a hidden browser tab can ping it and an SPA's 401 trap can
	// consult it. ⛔ It is registered by Routes() AND returned by SkipPaths():
	// an auth route that charonmw does not skip is an auth route nobody can
	// reach, and the failure looks like a dead session rather than a blocked
	// request.
	pathSession = "/session"

	// pathSessionSync is the silent identity-reconciliation endpoint added in
	// v0.20.0 (§C of the fleet's docs/PORTAL-ONE-LOGOUT.md). A browser loads it
	// in a hidden same-origin iframe; it performs an OIDC authorization request
	// with `prompt=none` and reports whether the browser's CURRENT Keycloak
	// session is the same one this product's cookie was minted from.
	//
	// ⛔ IT ANSWERS A QUESTION THE REVALIDATION FLOOR STRUCTURALLY CANNOT. The
	// floor asks the token endpoint "is session A still alive?" using a refresh
	// token bound to session A — so when a person signs in as somebody else,
	// Keycloak mints a NEW session, leaves A alive to its own idle timeout, and
	// answers "yes". The refreshed tokens even come back carrying A's `sub`.
	// Only a request that travels through the BROWSER carries the browser's
	// Keycloak cookie, and only that can see who is signed in now.
	pathSessionSync = "/session/sync"
)

// Session revalidation (v0.19.0) — Option B of docs/PORTAL-ONE-LOGOUT.md.
const (
	// oauthErrorInvalidGrant is RFC 6749's error code for a refresh token the
	// authorization server will not honour. ⛔ IT IS THE ONLY CODE THAT FAILS
	// CLOSED. Keycloak returns it when the SSO session behind the token has
	// ended — which is precisely the sign-out-elsewhere signal this whole
	// mechanism exists to observe. Every other refusal (invalid_client from a
	// rotated client secret, a 5xx, a transport error) fails OPEN, because
	// treating those as a sign-out turns one Keycloak blip or one bad secret
	// into a fleet-wide logout.
	oauthErrorInvalidGrant = "invalid_grant"

	// revalidateTransportBackoff is how long a session waits before retrying
	// after a FAIL-OPEN outcome. Without it, every request during a Keycloak
	// outage fires its own refresh attempt: the floor is only advanced on
	// success, so "retry next request" means "retry on every request" — a
	// thundering herd against an IdP that is already unwell, with the latency
	// of a failing network call added to every page load.
	//
	// It is persisted into the session (by moving the validation anchor
	// forward, never by extending Exp), so it holds across replicas and pod
	// restarts, which an in-process limiter could not.
	revalidateTransportBackoff = 30 * time.Second

	// headerCacheControl / cacheControlNoStore keep the liveness endpoint out of
	// every cache. A cached `authenticated: true` keeps a signed-out browser
	// looking signed in for as long as the cache lives — the exact divergence
	// the endpoint exists to detect, reintroduced by an intermediary.
	headerCacheControl  = "Cache-Control"
	cacheControlNoStore = "no-store"
)

// Session revalidation log keys + messages (v0.19.0).
const (
	logKeyRevalidateAge  = "session_age_seconds"
	logKeyOAuthErrorCode = "oauth_error"
	logMsgSessionRevoked = "go-vai-oidc: session revalidation refused by the IdP (invalid_grant) — signing out"
	logMsgRevalidateSoft = "go-vai-oidc: session revalidation could not reach a verdict; session kept (fail-open)"
	logMsgRevalidated    = "go-vai-oidc: session revalidated against the IdP"
	logMsgRevalidateSkip = "go-vai-oidc: session carries no refresh token; revalidation skipped (fail-open)"
)

// Log component.
const logComponent = "go-vai-oidc"

// Log keys.
const (
	logKeyComponent       = "component"
	logKeyClientID        = "client_id"
	logKeyIssuer          = "issuer"
	logKeyError           = "error"
	logKeySub             = "sub"
	logKeyTarget          = "target"
	logKeyLandingDecision = "landing_decision"
	logKeyEmail           = "email"
	logKeyReason          = "reason"
	logKeyClientIP        = "client_ip"
	logKeyPath            = "path"
	logKeyEmailDomain     = "email_domain"
	logKeyRequiredDomain  = "required_domain"
	logKeyCookieBytes     = "cookie_bytes"
	logKeyCookieChunks    = "cookie_chunks"
)

// Token-retention log messages (v0.12.0).
const (
	logMsgCookieLarge      = "go-vai-oidc: session exceeds the single-cookie limit; split across chunked cookies"
	logMsgTokenRefreshed   = "go-vai-oidc: refreshed access token"
	logMsgTokenPersistFail = "go-vai-oidc: failed to persist refreshed tokens (returning valid token anyway)"
)

// Discovery retry (v0.8.0).
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
	logMsgDiscoveryRetry   = "go-vai-oidc: discovery retry attempt"
	logMsgDiscoverySuccess = "go-vai-oidc: discovery succeeded after retry"
)

// Email-domain gate.
const (
	emailAtSeparator                 = "@"
	requireEmailDomainForbiddenRunes = "@ \t\r\n"
	logMsgEmailDomainRejected        = "OIDC callback: email domain rejected"
	logMsgLandingRedirect            = "OIDC callback: identity backend decided the landing destination"
	logReasonEmailDomainMismatch     = "email_domain_mismatch"
	logReasonEmailDomainMissingClaim = "email_claim_missing_or_malformed"
)

// Session sync (v0.20.0) — §C of docs/PORTAL-ONE-LOGOUT.md.
const (
	// queryParamPrompt / promptNone request a SILENT authorization: Keycloak
	// answers from the browser's existing SSO cookie or refuses, and never
	// renders a login form. Rendering one would be fatal here — the request runs
	// inside a hidden iframe, so an interactive prompt is an invisible dead end.
	queryParamPrompt = "prompt"
	promptNone       = "none"

	// cookieSyncMarkerValue is the sync cookie's only meaningful value. Its
	// PRESENCE is the signal; the value exists so the cookie is well-formed.
	cookieSyncMarkerValue = "1"

	// oauthErrorLoginRequired and its siblings are the IdP's EXPLICIT verdict
	// that `prompt=none` could not be satisfied without user interaction — i.e.
	// there is no usable SSO session in this browser. ⛔ These are the only
	// codes that fail CLOSED, by the same rule that makes `invalid_grant` the
	// only closing code for the revalidation floor: every other refusal is the
	// IdP failing to answer, and acting on those turns one Keycloak blip into a
	// synchronized fleet-wide logout.
	oauthErrorLoginRequired            = "login_required"
	oauthErrorInteractionRequired      = "interaction_required"
	oauthErrorConsentRequired          = "consent_required"
	oauthErrorAccountSelectionRequired = "account_selection_required"

	// syncCSP is the Content-Security-Policy the sync result document serves
	// ITSELF under.
	//
	// ⛔ IT IS NOT INHERITED FROM THE CONSUMER, DELIBERATELY. This fleet has
	// already shipped two total, invisible outages caused by a CSP that forbade
	// what the page needed (DC-PORTAL-ALPINECSP-01, DC-PORTAL-ASSETCSP-01), and
	// a violation is reported to a browser console and NOWHERE ELSE — so a
	// sync document relying on the consumer's policy would fail silently on
	// whichever product had the strictest one, and report nothing anywhere.
	// The document therefore carries its own minimal policy and a per-response
	// nonce. ⚠️ A consumer whose middleware OVERWRITES Content-Security-Policy on
	// every response defeats this; the data-attribute fallback below exists so
	// the parent can still read a result when that happens.
	syncCSPTemplate = "default-src 'none'; script-src 'nonce-%s'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"

	headerCSP = "Content-Security-Policy"

	// headerXFrameOptions / xFrameOptionsSameOrigin are set on the sync document
	// because the consumer's own security middleware almost certainly denied it
	// already.
	//
	// ⛔ FOUND BY INTEGRATING, NOT BY READING: werkzeuge — the first consumer —
	// sets `X-Frame-Options: DENY` on EVERY response from a global middleware.
	// That header is legacy and absolute: it outranks nothing, but nothing
	// overrides it either, so the browser refuses to render this document in a
	// frame AT ALL — including a frame on its own origin, created by the very
	// page the header is protecting. ⚠️ And the refusal is reported to a browser
	// console and NOWHERE ELSE (DC-PORTAL-ALPINECSP-01's class), so the sync
	// would simply never report, on every product, with every server-side signal
	// green.
	//
	// The library wins because a handler writes headers AFTER the middleware
	// that wrapped it. ⚠️ SAMEORIGIN, never a removal: this document must still
	// be unframeable by a foreign origin, which is also what its own
	// `frame-ancestors 'self'` says. The two agree deliberately — the modern
	// directive is the real control and this is the floor for anything still
	// reading the legacy header.
	headerXFrameOptions     = "X-Frame-Options"
	xFrameOptionsSameOrigin = "SAMEORIGIN"

	// syncNonceBytes sizes the per-response CSP nonce.
	syncNonceBytes = 16

	// syncMessageSource / syncMessageType namespace the postMessage payload so a
	// parent page hosting several iframes can tell this one's messages apart.
	syncMessageSource = "vaioidc"
	syncMessageType   = "session-sync"

	// syncResultDataAttr is the DOM fallback: the result is also written to
	// <html data-vaioidc-sync-result="...">, readable by a SAME-ORIGIN parent
	// through iframe.contentDocument even when the postMessage never arrives
	// (a consumer CSP overwrite, a listener attached too late).
	syncResultDataAttr = "data-vaioidc-sync-result"
)

// SessionSyncResult is the verdict of one silent identity reconciliation.
// It is a string rather than an enum int so it survives a postMessage, a log
// line and a JSON body unchanged.
type SessionSyncResult string

const (
	// SessionSyncUnchanged: the browser is signed in as the same person, in the
	// same Keycloak session. The product session was re-stamped.
	SessionSyncUnchanged SessionSyncResult = "unchanged"

	// SessionSyncSwitched: the browser is signed in as a DIFFERENT person (or in
	// a different Keycloak session). ⛔ The product session is CLEARED and the
	// product serves its own signed-out state — it is never silently re-minted
	// as the new person. Operator decision, 2026-09-11 (§C.7): an open editor or
	// workflow tab must not change owner underneath unsaved work. Nothing is
	// lost by the strictness — the browser still holds the new SSO session, so
	// the next sign-in click returns immediately without a credential prompt.
	SessionSyncSwitched SessionSyncResult = "switched"

	// SessionSyncSignedOut: the IdP explicitly refused `prompt=none`. There is no
	// SSO session in this browser; the product session is CLEARED.
	SessionSyncSignedOut SessionSyncResult = "signed_out"

	// SessionSyncNoSession: this product had no session to reconcile. Nothing was
	// touched and no authorization request was made.
	SessionSyncNoSession SessionSyncResult = "no_session"

	// SessionSyncDisabled: Config.SessionSyncEnabled is false. ⛔ Reported as a
	// distinct result rather than a 404, for the same reason pathSession is
	// registered unconditionally: a caller cannot tell a 404 from a signed-out
	// answer, and would sign its user out on a route that simply is not enabled.
	SessionSyncDisabled SessionSyncResult = "disabled"

	// SessionSyncError: no verdict could be reached — a transport failure, a 5xx,
	// an unexpected OAuth error, a state mismatch. ⛔ FAILS OPEN: nothing is
	// touched and the caller must change nothing.
	SessionSyncError SessionSyncResult = "error"
)

// Session sync log keys + messages (v0.20.0).
const (
	logKeySyncResult     = "sync_result"
	logKeySyncPriorSub   = "prior_sub"
	logKeySyncBrowserSub = "browser_sub"
	logMsgSyncSwitched   = "go-vai-oidc: the browser is signed in as a different identity; clearing this product's session"
	logMsgSyncSignedOut  = "go-vai-oidc: the IdP has no session for this browser; clearing this product's session"
	logMsgSyncUnchanged  = "go-vai-oidc: session sync confirmed the browser identity is unchanged"
	logMsgSyncSoft       = "go-vai-oidc: session sync could not reach a verdict; session kept (fail-open)"
	logMsgSyncStart      = "go-vai-oidc: session sync starting a silent authorization request"
)
