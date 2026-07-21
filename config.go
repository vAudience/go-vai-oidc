package vaioidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Config holds the configuration for OIDC authentication.
// Required fields must be set; optional fields have sensible defaults applied by New().
type Config struct {
	// Generic OIDC issuer (any spec-compliant provider).
	//
	// When set, discovery is performed directly against this issuer URL
	// (go-oidc appends "/.well-known/openid-configuration"), and
	// KeycloakURL/Realm are ignored. Use this for Google, Okta, Auth0,
	// Entra, Authentik, Dex, or any spec-compliant OIDC provider — e.g.
	// "https://accounts.google.com" or "https://auth.example.com/realms/acme".
	//
	// Leave empty to use the Keycloak convenience path (KeycloakURL +
	// Realm), which composes the issuer as "<KeycloakURL>/realms/<Realm>".
	// Exactly one of {IssuerURL} or {KeycloakURL + Realm} must be set.
	//
	// IssuerURL must equal the provider's own `iss` value exactly:
	// go-oidc verifies that the discovery document's `issuer` matches
	// the URL discovery was fetched from (byte-for-byte, trailing slash
	// aside — which this library trims). Providers whose `iss` differs
	// from their discovery base (e.g. a tenant-templated issuer, or a
	// split-horizon deployment) must set IssuerURLOverride to the
	// canonical `iss`.
	//
	// Distinct from IssuerURLOverride: IssuerURL is WHERE discovery
	// fetches from; IssuerURLOverride only changes WHICH issuer-claim
	// value is accepted (the split-horizon / iss-mismatch case).
	IssuerURL string

	// Required (Keycloak convenience path — omit when IssuerURL is set).
	KeycloakURL  string // Base URL, e.g. "https://keycloak.example.com"
	Realm        string // Realm name, e.g. "acme"
	ClientID     string // OIDC client ID registered with the provider
	ClientSecret string // OIDC client secret

	// Required: Service endpoints.
	CallbackURL string // Full callback URL, e.g. "https://myapp.example.com/auth/callback"

	// Required: Session encryption.
	SessionSecret string // base64-encoded 32-byte AES-256 key (openssl rand -base64 32)

	// Optional: Logout & login redirect.
	LogoutRedirect string // Where to redirect after logout (default: "/")
	LoginPath      string // Full login path for RequireSession redirects (default: "/auth/login")

	// Optional: Session.
	SessionTTL     time.Duration // Session cookie lifetime (default: 24h)
	CookieName     string        // Session cookie name (default: "vai_session")
	CookiePath     string        // Session cookie path (default: "/")
	InsecureCookie bool          // Set true to allow cookies over plain HTTP (default: false = HTTPS-only)

	// Optional: OIDC.
	Scopes []string // OIDC scopes (default: [openid, profile, email])

	// Optional: Claims & identity resolution.
	ExtraClaims  []string     // Extra ID token claim names to extract into User.Claims
	UserResolver UserResolver // Called during OIDC callback to enrich user (resolve org, etc.)

	// Optional: Token retention (v0.12.0).
	//
	// When true, the OIDC callback also stores the user's Keycloak
	// access_token + refresh_token + access-token expiry in the encrypted
	// session, enabling Auth.AccessToken(w, r) to return a currently-valid
	// access token (refreshing transparently via the refresh token) that the
	// service can forward as `Authorization: Bearer` to a downstream API that
	// validates Keycloak access tokens directly (e.g. charon /api/v1/keys for
	// self-service API-key minting).
	//
	// Default false — the pre-v0.12.0 behaviour, where only the id_token is
	// retained (for logout) and the access/refresh tokens are discarded.
	//
	// TRADE-OFF: retaining both tokens adds ~2–4 KB (encrypted+base64) to the
	// session cookie on top of the id_token. Combined with a large id_token
	// this can approach the ~4 KB per-cookie browser limit; New() logs a
	// warning when a written session cookie crosses CookieSizeWarnThreshold.
	// For long-lived refresh that survives Keycloak SSO logout, add
	// "offline_access" to Scopes; otherwise the refresh token is valid only
	// while the Keycloak SSO session lives.
	RetainTokens bool

	// Optional: Email domain gate.
	//
	// When set, the OIDC callback rejects logins whose `email` claim's
	// domain (the part after `@`) does not match this value. Comparison
	// is case-insensitive; the configured value is lowercased once at
	// applyDefaults() so the runtime check is a plain string equality.
	//
	// Validated at New(): non-empty values must contain no `@` and no
	// whitespace. The realm-side flow is the primary IdP gate (e.g. a
	// `google-only` browser flow constraining the upstream IdP
	// to Google); this field is the in-app belt-and-braces check that
	// keeps a misconfigured realm from federating arbitrary identities
	// into the consumer service.
	//
	// For Google Workspace tenants, set this to your primary domain
	// (e.g. "example.com"). For non-Google IdPs the same `email`-claim
	// rule applies — go-vai-oidc does not consult Google's `hd` claim
	// because IdP-portability matters more than tightening the check
	// against one provider.
	//
	// Empty (default) = no domain enforcement.
	RequireEmailDomain string

	// Optional: Observability.
	Logger *slog.Logger // Structured logger (default: slog.Default())

	// Optional: Discovery retry budget.
	//
	// Jittered discovery retry (v0.8.0). When non-zero, `New()` wraps the
	// initial OIDC discovery call in a jittered exponential-backoff
	// loop bounded by this wall-clock budget. Permanent-class errors
	// (4xx other than 408/429, malformed JSON) short-circuit
	// immediately; transient-class errors (5xx, 408, 429, raw
	// network, timeouts) retry until success or budget exhaustion.
	//
	// Default: 90 seconds (DiscoveryRetryBudgetDefault). Set
	// explicitly to 0 to disable retries entirely and preserve the
	// pre-v0.8.0 single-shot semantics.
	//
	// Rationale: closes the cold-cluster-boot failure class where a
	// consumer pod starts before keycloak finishes its own bootstrap,
	// the single discovery call gets "connection refused", and the
	// consumer locks in an `app.OIDCAuth = nil` state forever (until
	// a manual pod restart). 90s is generous enough to absorb
	// keycloak boot times on a fresh cluster and matches the same
	// retry budget shape used elsewhere for fail-open dependencies.
	DiscoveryRetryBudget time.Duration

	// Optional: Issuer URL override.
	//
	// When set, vai-oidc DISCOVERS at the URL composed from KeycloakURL+
	// Realm, but ACCEPTS the value of IssuerURLOverride as the issuer in
	// the discovery response (and uses it to verify ID-token `iss`
	// claims). This enables the kubernetes-native pattern where:
	//
	//   • the consumer pod calls discovery via the cluster-internal
	//     Keycloak Service URL (e.g.
	//     http://keycloak.<ns>.svc.cluster.local:8080),
	//
	//   • Keycloak (configured with `--hostname=keycloak.<public_base>`)
	//     returns the PUBLIC URL as the issuer field —
	//
	//   • without this override, the strict issuer-URL check inside
	//     go-oidc rejects the mismatch and discovery fails.
	//
	// Set to the SAME URL Keycloak returns as the issuer (i.e. the
	// public-base URL). Empty = use the strict default (discovery URL
	// must equal the issuer field).
	//
	// Internally implemented via go-oidc's `InsecureIssuerURLContext`
	// which is correctly named for the case where the API is exposed
	// publicly and the consumer chooses to bypass the check; in our
	// kubernetes-native deployment topology the override is a
	// LEGITIMATE configuration, not a security relaxation, because
	// the cluster-internal URL is just a different network path to
	// the same identity provider that issues the same tokens with
	// the same signing keys.
	IssuerURLOverride string
}

// UserResolver is called after ID token verification during the OIDC callback.
// It receives the user extracted from the token and must return the final user
// (with OrgID set, etc.) or an error to reject the login.
// If nil, no resolution is performed and the user is stored as-is.
type UserResolver func(ctx context.Context, user *User) (*User, error)

// secureCookie returns true if cookies should have the Secure flag.
func (c *Config) secureCookie() bool {
	return !c.InsecureCookie
}

// discoveryURL returns the OIDC issuer/discovery URL: the explicit generic
// IssuerURL when set, otherwise the Keycloak convenience composition
// (KeycloakURL + "/realms/" + Realm). go-oidc appends
// "/.well-known/openid-configuration" to the returned value.
//
// A trailing slash on IssuerURL is trimmed: go-oidc compares the returned
// value against the discovery document's `issuer`, and most providers publish
// an `iss` with no trailing slash — leaving one on would both double the path
// separator on the discovery fetch and cause a spurious iss mismatch.
func (c *Config) discoveryURL() string {
	if c.IssuerURL != "" {
		return strings.TrimRight(c.IssuerURL, "/")
	}
	return fmt.Sprintf(keycloakIssuerTemplate, c.KeycloakURL, c.Realm)
}

// applyDefaults fills zero-value optional fields with sensible defaults.
func (c *Config) applyDefaults() {
	if c.LogoutRedirect == "" {
		c.LogoutRedirect = defaultLogoutRedirect
	}
	if c.LoginPath == "" {
		c.LoginPath = defaultLoginPath
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = defaultSessionTTL
	}
	if c.CookieName == "" {
		c.CookieName = defaultCookieName
	}
	if c.CookiePath == "" {
		c.CookiePath = defaultCookiePath
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{scopeOpenID, scopeProfile, scopeEmail}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	// Discovery retry: zero-value opts in to the default 90s budget.
	// Set explicitly to a negative value to disable retries entirely
	// (we treat <=0 as disabled at the call site).
	if c.DiscoveryRetryBudget == 0 {
		c.DiscoveryRetryBudget = DiscoveryRetryBudgetDefault
	}
	// Lowercase the email-domain rule once so runtime comparisons are
	// plain equality. Empty stays empty.
	if c.RequireEmailDomain != "" {
		c.RequireEmailDomain = strings.ToLower(c.RequireEmailDomain)
	}
}

// validate checks that all required fields are set and the session secret is valid.
// Returns a descriptive error wrapping ErrInvalidConfig or ErrSessionKeyInvalid.
func (c *Config) validate() ([]byte, error) {
	// Required string fields. The discovery source is either the generic
	// IssuerURL or the Keycloak convenience path (KeycloakURL + Realm):
	// when IssuerURL is empty, both Keycloak parts are required. The
	// remaining fields are always required.
	type reqField struct{ value, name string }
	required := []reqField{
		{c.ClientID, "ClientID"},
		{c.ClientSecret, "ClientSecret"},
		{c.CallbackURL, "CallbackURL"},
		{c.SessionSecret, "SessionSecret"},
	}
	if c.IssuerURL == "" {
		required = append(required,
			reqField{c.KeycloakURL, "KeycloakURL (or set IssuerURL)"},
			reqField{c.Realm, "Realm (or set IssuerURL)"},
		)
	}
	for _, check := range required {
		if check.value == "" {
			return nil, fmt.Errorf("%s is required: %w", check.name, ErrInvalidConfig)
		}
	}

	// Decode and validate session key.
	key, err := base64.StdEncoding.DecodeString(c.SessionSecret)
	if err != nil {
		return nil, fmt.Errorf("SessionSecret is not valid base64: %w", ErrSessionKeyInvalid)
	}
	if len(key) != aesKeyLength {
		return nil, fmt.Errorf("SessionSecret decodes to %d bytes, need %d: %w", len(key), aesKeyLength, ErrSessionKeyInvalid)
	}

	// Validate RequireEmailDomain shape: a domain must not contain
	// `@` (would imply a full email was set in error) and must not
	// contain whitespace (would imply a config-rendering bug).
	if c.RequireEmailDomain != "" {
		if strings.ContainsAny(c.RequireEmailDomain, requireEmailDomainForbiddenRunes) {
			return nil, fmt.Errorf("RequireEmailDomain must not contain '@' or whitespace, got %q: %w",
				c.RequireEmailDomain, ErrInvalidConfig)
		}
	}

	// Warn on insecure config (http callback without InsecureCookie).
	if !c.InsecureCookie && strings.HasPrefix(c.CallbackURL, "http://") {
		c.Logger.Warn("CallbackURL uses http:// but InsecureCookie is false — cookies will not be sent; set InsecureCookie=true for non-HTTPS",
			slog.String(logKeyComponent, logComponent),
			slog.String("callback_url", c.CallbackURL),
		)
	}

	return key, nil
}
