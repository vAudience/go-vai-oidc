package vaioidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Auth provides OIDC browser login for a single Keycloak client.
// Create with New(), mount Routes(), protect handlers with RequireSession().
type Auth struct {
	provider   *oidcProvider
	sessionKey []byte
	cfg        Config
	logger     *slog.Logger
}

// New creates an Auth instance by performing OIDC discovery against Keycloak.
// The provided context controls the discovery HTTP call timeout.
// Returns a descriptive error wrapping ErrInvalidConfig or ErrDiscoveryFailed on failure.
// Never panics. Starts no goroutines.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	cfg.applyDefaults()

	key, err := cfg.validate()
	if err != nil {
		return nil, err
	}

	provider, err := discover(ctx, cfg.KeycloakURL, cfg.Realm, cfg.ClientID, cfg.ClientSecret, cfg.CallbackURL, cfg.IssuerURLOverride, cfg.Scopes)
	if err != nil {
		return nil, err // discover() already wraps with ErrDiscoveryFailed
	}

	cfg.Logger.Info("vai-oidc initialized",
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyIssuer, fmt.Sprintf(keycloakIssuerTemplate, cfg.KeycloakURL, cfg.Realm)),
		slog.String(logKeyClientID, cfg.ClientID),
	)

	return &Auth{
		provider:   provider,
		sessionKey: key,
		cfg:        cfg,
		logger:     cfg.Logger,
	}, nil
}

// Routes returns a chi.Router with login, callback, and logout handlers.
// Mount at your preferred prefix: r.Mount("/auth", auth.Routes())
func (a *Auth) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get(pathLogin, a.handleLogin)
	r.Get(pathCallback, a.handleCallback)
	r.Get(pathLogout, a.handleLogout)
	r.Post(pathLogout, a.handleLogout)
	return r
}

// RequireSession returns middleware that requires a valid session.
// If no valid session: redirects browsers to the login page, or returns 401 JSON for API clients.
func (a *Auth) RequireSession() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
			if err != nil {
				a.logger.Warn("session validation failed",
					slog.String(logKeyComponent, logComponent),
					slog.String(logKeyPath, r.URL.Path),
					slog.String(logKeyReason, unwrapReason(err)),
				)
				if wantsBrowser(r) {
					http.Redirect(w, r, a.cfg.LoginPath, http.StatusFound)
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}

			ctx := contextWithUser(r.Context(), payload.toUser())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalSession returns middleware that sets User in context if a valid session exists,
// but does not block the request if there is no session.
func (a *Auth) OptionalSession() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
			if err == nil {
				ctx := contextWithUser(r.Context(), payload.toUser())
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SkipPaths returns the auth route paths that should bypass charonmw.
// Use with charonmw: append(mySkipPaths, auth.SkipPaths()...)
func (a *Auth) SkipPaths() []string {
	return []string{pathLogin, pathCallback, pathLogout}
}

// SkipPathsWithPrefix returns the auth route paths prefixed with the given mount path.
// Use when mounting at a custom prefix: auth.SkipPathsWithPrefix("/auth")
func (a *Auth) SkipPathsWithPrefix(prefix string) []string {
	return []string{
		prefix + pathLogin,
		prefix + pathCallback,
		prefix + pathLogout,
	}
}

// UpdateSession reads the current session, applies the mutation function to the User,
// and writes the updated session back as a new cookie. IDToken and Exp are preserved.
// Use this for org selection (setting OrgID after login) or updating Claims.
func (a *Auth) UpdateSession(w http.ResponseWriter, r *http.Request, mutate func(*User)) error {
	if mutate == nil {
		return nil
	}
	payload, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	if err != nil {
		return err
	}
	user := payload.toUser()
	mutate(user)
	payload.fromUser(user)
	return setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleLogin initiates the OIDC Authorization Code Flow with PKCE.
func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		a.logger.Error("failed to generate OIDC state",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, err.Error()),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		a.logger.Error("failed to generate PKCE",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, err.Error()),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	// Capture and validate redirect param.
	redirect := r.URL.Query().Get(queryParamRedirect)
	if !isValidRedirect(redirect) {
		redirect = ""
	}

	// Store state + redirect in one cookie (pipe-delimited).
	stateValue := state
	if redirect != "" {
		stateValue = state + stateCookieDelimiter + redirect
	}

	setOIDCCookie(w, cookieOIDCState, stateValue, a.cfg.CookiePath, a.cfg.secureCookie())
	setOIDCCookie(w, cookiePKCEVerifier, verifier, a.cfg.CookiePath, a.cfg.secureCookie())

	// v0.5.0: forward selected query params from /auth/login to
	// Keycloak's authorize endpoint. `kc_idp_hint` skips Keycloak's
	// own login page and federates directly to the named IdP
	// (typical use: kc_idp_hint=google). `prompt` forces a fresh
	// credential prompt. Other unknown params are dropped — only
	// the IdP whitelist below is forwarded so a malicious caller
	// cannot inject arbitrary OAuth params.
	extra := authCodeExtras(r)
	authURL := a.provider.authCodeURL(state, challenge, extra)

	a.logger.Debug("OIDC login redirect",
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyClientIP, clientIP(r)),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// authCodeExtras returns the whitelisted /auth/login query params
// to forward to the authorize endpoint. v0.5.0 ships kc_idp_hint
// + prompt; future cycles may extend (e.g. login_hint) — each
// addition is a deliberate decision so unknown params can't slip
// through silently.
func authCodeExtras(r *http.Request) map[string]string {
	out := map[string]string{}
	q := r.URL.Query()
	for _, k := range []string{"kc_idp_hint", "prompt"} {
		if v := q.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

// handleCallback processes the OIDC callback from Keycloak.
func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Read and clear OIDC cookies immediately.
	stateCookie, err := r.Cookie(cookieOIDCState)
	if err != nil {
		a.logger.Warn("OIDC callback: missing state cookie",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	pkceCookie, err := r.Cookie(cookiePKCEVerifier)
	if err != nil {
		a.logger.Warn("OIDC callback: missing PKCE cookie",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	clearOIDCCookie(w, cookieOIDCState, a.cfg.CookiePath, a.cfg.secureCookie())
	clearOIDCCookie(w, cookiePKCEVerifier, a.cfg.CookiePath, a.cfg.secureCookie())

	// Parse state: "state" or "state|redirect".
	storedState, storedRedirect := parseStateCookie(stateCookie.Value)

	// Check for IdP error.
	if errParam := r.URL.Query().Get(queryParamError); errParam != "" {
		a.logger.Warn("OIDC callback: IdP returned error",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyReason, errParam),
			slog.String("error_description", r.URL.Query().Get(queryParamErrorDescription)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	// Validate state (constant-time comparison).
	queryState := r.URL.Query().Get(queryParamState)
	if queryState == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(storedState)) != 1 {
		a.logger.Warn("OIDC callback: state mismatch",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	// Get authorization code.
	code := r.URL.Query().Get(queryParamCode)
	if code == "" {
		a.logger.Warn("OIDC callback: missing code parameter",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	// Exchange code for tokens.
	rawIDToken, idToken, err := a.provider.exchange(r.Context(), code, pkceCookie.Value)
	if err != nil {
		a.logger.Warn("OIDC callback: token exchange failed",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, err.Error()),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	// Extract user claims.
	user := a.provider.extractUser(idToken, a.logger, a.cfg.ExtraClaims)

	// Call UserResolver if configured.
	if a.cfg.UserResolver != nil {
		resolved, resolveErr := a.cfg.UserResolver(r.Context(), user)
		if resolveErr != nil {
			a.logger.Warn("OIDC callback: UserResolver rejected login",
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeyError, resolveErr.Error()),
				slog.String(logKeySub, user.Sub),
				slog.String(logKeyClientIP, clientIP(r)),
			)
			http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
			return
		}
		if resolved == nil {
			a.logger.Warn("OIDC callback: UserResolver returned nil user",
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeySub, user.Sub),
				slog.String(logKeyClientIP, clientIP(r)),
			)
			http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
			return
		}
		user = resolved
	}

	// Create and encrypt session.
	payload := &sessionPayload{
		Sub:     user.Sub,
		Email:   user.Email,
		Name:    user.Name,
		OrgID:   user.OrgID,
		Claims:  user.Claims,
		IDToken: rawIDToken,
		Exp:     time.Now().UTC().Add(a.cfg.SessionTTL).Unix(),
	}

	if err := setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie()); err != nil {
		a.logger.Error("OIDC callback: failed to set session cookie",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, err.Error()),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

	a.logger.Info("login successful",
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeySub, user.Sub),
		slog.String(logKeyEmail, user.Email),
		slog.String(logKeyClientIP, clientIP(r)),
	)

	// Redirect to stored redirect or root.
	target := "/"
	if storedRedirect != "" {
		target = storedRedirect
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handleLogout clears the session and redirects to Keycloak's end-session endpoint.
func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Try to read session for ID token hint before clearing.
	var idTokenHint string
	if payload, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName); err == nil {
		idTokenHint = payload.IDToken
		a.logger.Info("logout",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, payload.Sub),
			slog.String(logKeyClientIP, clientIP(r)),
		)
	} else {
		a.logger.Info("logout (no session)",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyClientIP, clientIP(r)),
		)
	}

	clearSessionCookie(w, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())

	// Redirect to Keycloak end-session endpoint if available (federated logout).
	if a.provider.endSessionURL != "" {
		logoutURL := buildLogoutURL(a.provider.endSessionURL, idTokenHint, a.cfg.LogoutRedirect)
		http.Redirect(w, r, logoutURL, http.StatusFound)
		return
	}

	// Fallback: local logout only.
	http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseStateCookie splits "state|redirect" into components.
func parseStateCookie(value string) (state, redirect string) {
	parts := strings.SplitN(value, stateCookieDelimiter, 2)
	state = parts[0]
	if len(parts) > 1 {
		redirect = parts[1]
	}
	return
}

// isValidRedirect checks that the redirect is a safe relative path.
// Rejects absolute URLs, protocol-relative URLs, and empty strings.
func isValidRedirect(redirect string) bool {
	if redirect == "" {
		return false
	}
	if !strings.HasPrefix(redirect, "/") {
		return false
	}
	if strings.HasPrefix(redirect, "//") {
		return false
	}
	if strings.Contains(redirect, "://") {
		return false
	}
	// Block backslashes — some browsers normalize \/ to // (open redirect).
	if strings.ContainsAny(redirect, "\\") {
		return false
	}
	return true
}

// buildLogoutURL constructs the Keycloak RP-Initiated Logout URL.
func buildLogoutURL(endSessionURL, idTokenHint, postLogoutRedirect string) string {
	u, err := url.Parse(endSessionURL)
	if err != nil {
		return postLogoutRedirect
	}
	q := u.Query()
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// wantsBrowser returns true if the request likely comes from a browser (Accept: text/html).
func wantsBrowser(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP extracts the client IP from the request (X-Real-IP, X-Forwarded-For, or RemoteAddr).
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i > 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return fwd
	}
	return r.RemoteAddr
}

// unwrapReason extracts the innermost error message for log output.
func unwrapReason(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err.Error()
		}
		err = inner
	}
}
