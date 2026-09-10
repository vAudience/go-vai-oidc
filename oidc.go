package vaioidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcProvider wraps go-oidc and oauth2 for Keycloak OIDC operations.
type oidcProvider struct {
	provider      *gooidc.Provider
	verifier      *gooidc.IDTokenVerifier
	oauth2Cfg     oauth2.Config
	endSessionURL string // extracted from OIDC discovery claims
}

// discover performs OIDC discovery against discoveryURL (the resolved
// issuer — either a generic Config.IssuerURL or the Keycloak
// convenience composition; see Config.discoveryURL) and returns a
// configured provider. When `issuerOverride` is non-empty, the
// override is treated as the canonical issuer —
// `InsecureIssuerURLContext` propagates the expected issuer into
// go-oidc's verifier so subsequent ID-token `iss` checks compare
// against the override. See Config.IssuerURLOverride for the
// kubernetes-native rationale.
func discover(ctx context.Context, discoveryURL, clientID, clientSecret, callbackURL, issuerOverride string, scopes []string) (*oidcProvider, error) {
	if issuerOverride != "" {
		ctx = gooidc.InsecureIssuerURLContext(ctx, issuerOverride)
	}

	provider, err := gooidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("discover issuer %q: %w", discoveryURL, errors.Join(ErrDiscoveryFailed, err))
	}

	verifier := provider.Verifier(&gooidc.Config{
		ClientID: clientID,
	})

	oauth2Cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       scopes,
	}

	// Extract end_session_endpoint from discovery claims (Keycloak provides this).
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&claims) // non-fatal if missing

	return &oidcProvider{
		provider:      provider,
		verifier:      verifier,
		oauth2Cfg:     oauth2Cfg,
		endSessionURL: claims.EndSessionEndpoint,
	}, nil
}

// authCodeURL generates the Keycloak authorization URL with state and
// PKCE challenge. `extra` carries arbitrary additional query
// parameters the consumer wants forwarded to Keycloak's authorize
// endpoint — typically `kc_idp_hint=google` to skip Keycloak's own
// login page and federate straight to the named IdP, or
// `prompt=login` to force a fresh credential prompt. Empty `extra`
// preserves the pre-v0.5.0 behaviour exactly.
func (p *oidcProvider) authCodeURL(state, challenge string, extra map[string]string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", pkceChallengeMethod),
	}
	for k, v := range extra {
		if k == "" || v == "" {
			continue
		}
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return p.oauth2Cfg.AuthCodeURL(state, opts...)
}

// exchange trades the authorization code and PKCE verifier for tokens.
// Returns the full OAuth2 token (access+refresh+expiry, retained only when
// Config.RetainTokens is set), the raw ID token string (needed
// for logout hint), and the verified IDToken.
func (p *oidcProvider) exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, string, *gooidc.IDToken, error) {
	token, err := p.oauth2Cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("exchange code: %w", errors.Join(ErrTokenExchange, err))
	}

	rawIDToken, ok := token.Extra(extraIDToken).(string)
	if !ok || rawIDToken == "" {
		return nil, "", nil, fmt.Errorf("missing id_token in token response: %w", ErrTokenExchange)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", nil, fmt.Errorf("verify id_token: %w", errors.Join(ErrTokenVerification, err))
	}

	return token, rawIDToken, idToken, nil
}

// refreshedToken returns a currently-valid OAuth2 token derived from the
// stored access/refresh tokens, transparently refreshing against Keycloak when
// the access token has expired. A non-expired token is returned as-is with no
// network call (oauth2.TokenSource semantics) (v0.12.0).
func (p *oidcProvider) refreshedToken(ctx context.Context, accessToken, refreshToken string, accessExp int64) (*oauth2.Token, error) {
	stored := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Unix(accessExp, 0),
	}
	fresh, err := p.oauth2Cfg.TokenSource(ctx, stored).Token()
	if err != nil {
		return nil, fmt.Errorf("refresh access token: %w", errors.Join(ErrTokenRefreshFailed, err))
	}
	return fresh, nil
}

// forcedRefresh performs a `refresh_token` grant against the IdP UNCONDITIONALLY
// and returns the resulting token set (v0.19.0).
//
// ⛔ IT EXISTS BECAUSE refreshedToken() CANNOT BE USED FOR REVALIDATION. That
// function hands the stored access token to oauth2.TokenSource, whose documented
// semantics are to return a still-valid token AS-IS WITH NO NETWORK CALL. Built
// on it, a "revalidation" would answer "still signed in" from a purely local
// expiry check for as long as the access token lives — which is exactly the
// self-deceiving ping the design forbids: one that keeps the product session
// alive while the IdP session dies underneath it, WIDENING the divergence it was
// added to close.
//
// The mechanism is deliberate rather than incidental: an oauth2.Token whose
// AccessToken is empty is never Valid(), so TokenSource always takes the refresh
// path. The stored access token is not passed in at all — it is an output of
// this call, never an input to it.
//
// The error is returned wrapped in ErrTokenRefreshFailed, with the underlying
// *oauth2.RetrieveError still reachable via errors.As so the caller can tell an
// IdP verdict from an IdP outage.
func (p *oidcProvider) forcedRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("forced refresh: session carries no refresh token: %w", ErrTokenRefreshFailed)
	}
	fresh, err := p.oauth2Cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("forced refresh: %w", errors.Join(ErrTokenRefreshFailed, err))
	}
	return fresh, nil
}

// extractUser reads identity claims from a verified ID token.
// Missing claims result in empty fields. Claims extraction failure is logged at debug level.
// extraClaims specifies additional claim names to extract into User.Claims.
func (p *oidcProvider) extractUser(idToken *gooidc.IDToken, logger *slog.Logger, extraClaims []string) *User {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		logger.Debug("failed to extract ID token claims",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, err.Error()),
		)
	}

	user := &User{Sub: idToken.Subject}

	if email, ok := claims[claimEmail].(string); ok {
		user.Email = email
	}
	if name, ok := claims[claimName].(string); ok {
		user.Name = name
	}
	user.RealmRoles = extractRealmRoles(claims)

	// Extract extra claims into User.Claims map.
	if len(extraClaims) > 0 && len(claims) > 0 {
		user.Claims = make(map[string]string, len(extraClaims))
		for _, key := range extraClaims {
			if v, ok := claims[key]; ok {
				switch tv := v.(type) {
				case string:
					user.Claims[key] = tv
				default:
					// Non-string values (arrays, objects, numbers) are JSON-serialized.
					if b, err := json.Marshal(tv); err == nil {
						user.Claims[key] = string(b)
					}
				}
			}
		}
	}

	return user
}

// extractRealmRoles reads Keycloak's standard `realm_access.roles` ID-token
// claim. Returns nil if the claim is absent or shaped unexpectedly (a token
// from a differently-configured realm/IdP simply carries no realm roles,
// which is not an error condition here).
func extractRealmRoles(claims map[string]interface{}) []string {
	realmAccess, ok := claims[claimRealmAccess].(map[string]interface{})
	if !ok {
		return nil
	}
	rawRoles, ok := realmAccess[claimRealmAccessRoles].([]interface{})
	if !ok {
		return nil
	}
	roles := make([]string, 0, len(rawRoles))
	for _, r := range rawRoles {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}
	if len(roles) == 0 {
		return nil
	}
	return roles
}

// generatePKCE creates a PKCE verifier and its S256 challenge.
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, pkceVerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate PKCE verifier: %w", err)
	}

	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}

// generateState creates a cryptographic random state parameter (hex-encoded).
func generateState() (string, error) {
	b := make([]byte, stateBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return hex.EncodeToString(b), nil
}
