package vaioidc

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Config holds the configuration for OIDC authentication.
// Required fields must be set; optional fields have sensible defaults applied by New().
type Config struct {
	// Required: Keycloak connection.
	KeycloakURL  string // Base URL, e.g. "https://keycloak.example.com"
	Realm        string // Realm name, e.g. "vaudience"
	ClientID     string // OIDC client ID registered in Keycloak
	ClientSecret string // OIDC client secret from K8s secret

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

	// Optional: Observability.
	Logger *slog.Logger // Structured logger (default: slog.Default())
}

// secureCookie returns true if cookies should have the Secure flag.
func (c *Config) secureCookie() bool {
	return !c.InsecureCookie
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
}

// validate checks that all required fields are set and the session secret is valid.
// Returns a descriptive error wrapping ErrInvalidConfig or ErrSessionKeyInvalid.
func (c *Config) validate() ([]byte, error) {
	// Required string fields.
	for _, check := range []struct {
		value, name string
	}{
		{c.KeycloakURL, "KeycloakURL"},
		{c.Realm, "Realm"},
		{c.ClientID, "ClientID"},
		{c.ClientSecret, "ClientSecret"},
		{c.CallbackURL, "CallbackURL"},
		{c.SessionSecret, "SessionSecret"},
	} {
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

	// Warn on insecure config (http callback without InsecureCookie).
	if !c.InsecureCookie && strings.HasPrefix(c.CallbackURL, "http://") {
		c.Logger.Warn("CallbackURL uses http:// but InsecureCookie is false — cookies will not be sent; set InsecureCookie=true for non-HTTPS",
			slog.String(logKeyComponent, logComponent),
			slog.String("callback_url", c.CallbackURL),
		)
	}

	return key, nil
}
