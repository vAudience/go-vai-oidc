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

	// Both discovery sources populated is a config smell: IssuerURL wins and the
	// Keycloak convenience fields are silently ignored (see Config.discoveryURL).
	// Warn loudly rather than authenticate against a provider the operator may
	// not have intended.
	if cfg.IssuerURL != "" && (cfg.KeycloakURL != "" || cfg.Realm != "") {
		cfg.Logger.Warn("both IssuerURL and KeycloakURL/Realm are set; IssuerURL wins and the Keycloak fields are ignored",
			slog.String(logKeyComponent, logComponent))
	}

	// v0.8.0: wrap discover() in a jittered retry
	// budget so a cold-boot keycloak-not-yet-reachable race no longer
	// produces a permanently-broken consumer pod. Set
	// `Config.DiscoveryRetryBudget = -1` (or any negative) to opt out
	// and preserve the pre-v0.8.0 single-shot semantics.
	provider, err := discoverWithRetry(ctx, cfg.Logger, cfg.DiscoveryRetryBudget,
		cfg.discoveryURL(), cfg.ClientID, cfg.ClientSecret, cfg.CallbackURL, cfg.IssuerURLOverride, cfg.Scopes)
	if err != nil {
		return nil, err // discover() already wraps with ErrDiscoveryFailed
	}

	cfg.Logger.Info("go-vai-oidc initialized",
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyIssuer, cfg.discoveryURL()),
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
					// ⚠️ THE DEEP LINK IS CARRIED, AND BEFORE v0.18.0 IT WAS SILENTLY
					// DISCARDED HERE. This refusal is the ONLY place a signed-out
					// browser request to a gated page is turned into a login, so a
					// static LoginPath meant every deep link — a shared admin URL, a
					// bookmarked report, a link in a ticket — sent the person to the
					// login screen and then to the service root, with no way for the
					// consumer to fix it: the wanted path exists only inside this
					// middleware. Two consumer repositories were surveyed with exactly
					// this defect and neither could have repaired it from its own side.
					//
					// The value is r.URL.RequestURI() — the request's OWN path and query,
					// so it is same-origin by construction rather than by validation —
					// and handleLogin re-validates it through isValidRedirect anyway,
					// which is the check that matters for the round trip through the
					// state cookie.
					target := a.cfg.LoginPath
					if rt := r.URL.RequestURI(); isValidRedirect(rt) {
						target = appendQueryParam(target, queryParamRedirect, rt)
					}
					http.Redirect(w, r, target, http.StatusFound)
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
	return setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger)
}

// VerifyIDToken cryptographically verifies a raw Keycloak ID-token JWT
// against the OIDC provider's published JWKS and returns the extracted
// User. v0.11.0+.
//
// Intended for consumers that obtain an ID token via an alternate
// Keycloak grant (most commonly Resource Owner Password Credentials —
// ROPC — backing an inline-login form) and need the SAME trust guarantee
// the Authorization Code flow provides: the token was signed by Keycloak
// (RS256/ES256 via JWKS), the issuer matches the configured realm, the
// audience matches the configured ClientID, and the token has not
// expired. Reuses the same `*gooidc.IDTokenVerifier` that `handleCallback`
// uses — kept in lockstep with the standard flow.
//
// On success returns a *User identical in shape to the one produced by
// the callback path (Sub/Email/Name/Claims populated from id_token
// claims per Config.ExtraClaims).
//
// On any verification failure (bad signature, wrong audience, expired,
// malformed) returns an error wrapping ErrTokenVerification. Callers
// can detect via errors.Is(err, ErrTokenVerification).
//
// Never panics. No goroutines.
func (a *Auth) VerifyIDToken(ctx context.Context, rawIDToken string) (*User, error) {
	if rawIDToken == "" {
		return nil, fmt.Errorf("verify id_token: empty token: %w", ErrTokenVerification)
	}
	idToken, err := a.provider.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", errors.Join(ErrTokenVerification, err))
	}
	return a.provider.extractUser(idToken, a.logger, a.cfg.ExtraClaims), nil
}

// IssueSession writes a vai-oidc session cookie for the given user WITHOUT
// going through the Authorization Code redirect flow. v0.10.0+.
//
// Intended for consumers that obtain the user's identity through an
// alternate Keycloak grant (most commonly Resource Owner Password
// Credentials — ROPC — for an inline credential form on the consumer's
// own /login surface). The caller is responsible for:
//
//   - Performing the credential exchange against Keycloak (e.g. POST to
//     `<issuer>/protocol/openid-connect/token` with `grant_type=password`).
//   - Validating the resulting ID token (signature, audience, expiry).
//   - Mapping the token claims to a `*User`.
//
// On success this cookie is INDISTINGUISHABLE from one issued by
// `handleCallback` — same payload shape, same encryption key, same TTL
// (cfg.SessionTTL), same cookie attributes. Downstream middleware
// (`RequireSession`, `OptionalSession`) treats the resulting session
// exactly as if the user had come through the standard flow.
//
// `rawIDToken` is stored in the encrypted payload so RP-Initiated Logout
// can hand it back to Keycloak as `id_token_hint`. Pass the empty string
// if the consumer doesn't have the raw JWT (logout falls back to the
// standard cookie clear without the federated step).
//
// Mirrors the encryption + cookie-writing path used at the end of
// `handleCallback` — kept in lockstep with that code path.
func (a *Auth) IssueSession(w http.ResponseWriter, r *http.Request, user *User, rawIDToken string) error {
	if user == nil {
		return ErrSessionInvalid
	}
	// Build the user-visible fields via fromUser so EVERY field that round-trips
	// through a User is persisted — kept in lockstep with handleCallback. A
	// hand-rolled literal here silently dropped Mbs (v0.14.0) and Rls (v0.15.0),
	// leaving inline-login (ROPC) sessions without their membership set (multi-org
	// pickers broke) and without realm roles. IDToken + Exp are session-only (not
	// on User), so they are set directly and fromUser preserves them.
	payload := &sessionPayload{
		IDToken: rawIDToken,
		Exp:     time.Now().UTC().Add(a.cfg.SessionTTL).Unix(),
	}
	payload.fromUser(user)
	return setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger)
}

// AccessToken returns a currently-valid Keycloak access token for the
// logged-in user, refreshing it transparently via the stored refresh token
// when it has expired. v0.12.0+.
//
// Requires Config.RetainTokens=true AND a session created after retention was
// enabled; otherwise returns ErrTokensNotRetained. The returned token is the
// raw Keycloak access-token JWT, intended to be forwarded as
// `Authorization: Bearer <token>` to a downstream API that validates Keycloak
// access tokens directly (e.g. charon /api/v1/keys for self-service API-key
// minting). Note the downstream's audience requirement: the access token must
// carry an `aud` the downstream accepts (a Keycloak audience-mapper concern,
// not handled here — vai-oidc forwards the token opaquely).
//
// When a refresh occurs, the rotated access+refresh tokens are persisted back
// into the session cookie (hence the ResponseWriter); the session's own TTL
// (Exp) is preserved. A persist failure is non-fatal — the freshly-obtained
// valid token is still returned, with a logged warning.
//
// Errors: ErrNoSession / ErrSessionExpired / ErrSessionInvalid (no usable
// session), ErrTokensNotRetained (retention off or pre-retention session),
// ErrTokenRefreshFailed (access token expired and refresh failed → treat as
// re-authentication required). Never panics. No goroutines.
func (a *Auth) AccessToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if !a.cfg.RetainTokens {
		return "", ErrTokensNotRetained
	}
	payload, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	if err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		// Session predates retention (e.g. an IssueSession cookie) or tokens
		// were never stored — the caller must re-login to obtain them.
		return "", ErrTokensNotRetained
	}

	fresh, err := a.provider.refreshedToken(r.Context(), payload.AccessToken, payload.RefreshToken, payload.AccessTokenExp)
	if err != nil {
		return "", err // already wraps ErrTokenRefreshFailed
	}

	// Persist rotated tokens if the access token changed (Keycloak rotates
	// refresh tokens by default). Preserve the session Exp.
	if fresh.AccessToken != payload.AccessToken {
		payload.AccessToken = fresh.AccessToken
		payload.AccessTokenExp = fresh.Expiry.Unix()
		if fresh.RefreshToken != "" {
			payload.RefreshToken = fresh.RefreshToken
		}
		if writeErr := setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger); writeErr != nil {
			a.logger.Warn(logMsgTokenPersistFail,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeyError, writeErr.Error()),
			)
		} else {
			a.logger.Debug(logMsgTokenRefreshed,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeySub, payload.Sub),
			)
		}
	}

	return fresh.AccessToken, nil
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
	token, rawIDToken, idToken, err := a.provider.exchange(r.Context(), code, pkceCookie.Value)
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

	// Email-domain gate. Runs BEFORE UserResolver so a
	// custom resolver does not need to know about the rule and so the
	// rejection log line never carries resolver-side state. Empty
	// RequireEmailDomain skips the check (existing behaviour).
	if domainErr := enforceEmailDomain(user, a.cfg.RequireEmailDomain); domainErr != nil {
		// extractUser cannot return nil today, but enforceEmailDomain
		// is documented nil-tolerant and the gate sits before any
		// UserResolver call — guard the log site so a future
		// extractor change cannot crash the rejection log path.
		var sub, emailDomain string
		if user != nil {
			sub = user.Sub
			emailDomain = emailDomainOf(user.Email)
		}
		a.logger.Warn(logMsgEmailDomainRejected,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyReason, domainReason(domainErr)),
			slog.String(logKeySub, sub),
			slog.String(logKeyEmailDomain, emailDomain),
			slog.String(logKeyRequiredDomain, a.cfg.RequireEmailDomain),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return
	}

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

	// Create and encrypt session. Build the user-visible fields via fromUser so
	// EVERY field that round-trips through a User (incl. Memberships, v0.14.0)
	// is persisted — a hand-rolled literal here silently dropped Mbs in v0.14.0,
	// leaving multi-org pickers without their membership set. IDToken + Exp are
	// session-only (not on User), so they are set directly and fromUser preserves
	// them.
	payload := &sessionPayload{
		IDToken: rawIDToken,
		Exp:     time.Now().UTC().Add(a.cfg.SessionTTL).Unix(),
	}
	payload.fromUser(user)

	// Optionally retain the access+refresh tokens so the service
	// can later forward a valid Keycloak access token to a downstream API.
	if a.cfg.RetainTokens && token != nil {
		payload.AccessToken = token.AccessToken
		payload.RefreshToken = token.RefreshToken
		payload.AccessTokenExp = token.Expiry.Unix()
	}

	if err := setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger); err != nil {
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

	// Redirect to the stored deep link, else to where this service says a
	// successful login belongs.
	//
	// ⚠️ THAT SECOND HALF WAS A HARD-CODED "/" UNTIL v0.18.0, WITH NO CONFIG FIELD,
	// AND IT WAS BROKEN FOR EVERY CONSUMER WHOSE UI IS NOT AT THE ROOT — in two
	// different ways, one loud and one silent. A service that serves its UI under
	// a prefix and registers nothing at "/" answered **404 on every successful
	// login**; a service that serves a public marketing site at "/" landed every
	// signed-in administrator on the marketing homepage, with no error anywhere.
	// Neither could be fixed from the consumer side, because this line was not
	// configurable.
	target := a.postLoginTarget(storedRedirect)

	// ⚠️ THE IDENTITY BACKEND'S DECISION OVERRIDES THE CONSUMER'S DESTINATION,
	// AND ONLY HERE (v0.18.0).
	//
	// Before this arm existed, a first-time human had exactly two possible fates:
	// silently adopt whichever organization the backend listed first — which for
	// anyone who used a sibling product earlier is an auto-minted personal
	// workspace they cannot get off — or be bounced to a logout page. Neither is
	// onboarding, and there was no hook anywhere in this file where a third
	// answer could be given.
	//
	// ⚠️ THE VALUE IS DELIBERATELY NOT PASSED THROUGH isValidRedirect. That helper
	// enforces a same-origin RELATIVE path because the value it guards comes from
	// the BROWSER (`/auth/login?redirect=…`). A landing URL is the opposite kind
	// of value — absolute and cross-origin by construction, from the body of an
	// authenticated server-to-server response — so isValidRedirect would reject
	// every correct one. It is validated instead by the resolver that produced it,
	// which is the only component that knows which backend it is talking to; see
	// obolresolver.admitLanding for what is checked and why.
	//
	// ⚠️ EVERY ARM OF RedirectTarget FAILS TOWARDS `target`, never away from it: a
	// nil decision, an unrecognised one, and one that wants a redirect but names
	// no URL all leave this login ending exactly where it used to.
	if landingURL, ok := user.Landing.RedirectTarget(); ok {
		if returnTo := a.consumerReturnTo(target); returnTo != "" {
			landingURL = appendQueryParam(landingURL, queryParamConsumerReturnTo, returnTo)
		}
		a.logger.Info(logMsgLandingRedirect,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, user.Sub),
			slog.String(logKeyLandingDecision, user.Landing.Decision),
			slog.String(logKeyTarget, target),
		)
		http.Redirect(w, r, landingURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, target, http.StatusFound)
}

// postLoginTarget picks where a SUCCESSFUL login lands: the deep link the
// browser was heading to, else this service's configured destination.
//
// ⚠️ IT IS A FUNCTION SO IT CAN BE DRIVEN BY A TEST. handleCallback needs a full
// authorization-code exchange to reach its final redirect, so a decision left
// inline there is a decision nothing exercises — and a config field whose only
// reader is unreachable from any test READS AS BUILT while doing nothing.
func (a *Auth) postLoginTarget(storedRedirect string) string {
	if storedRedirect != "" {
		return storedRedirect
	}
	return a.cfg.PostLoginRedirect
}

// consumerReturnTo turns the consumer-side post-login target into an ABSOLUTE
// URL on this service's own origin, so the identity backend can send the person
// back once its flow finishes. Returns "" when there is nothing worth carrying.
//
// ⚠️ THE ORIGIN COMES FROM CallbackURL AND NOT FROM THE REQUEST. A request-derived
// scheme is wrong behind a TLS-terminating proxy — the commonest deployment here
// — and would emit an `http://` return address for an `https://` service.
// CallbackURL is configured, absolute, and already registered with the provider,
// so it is the authoritative statement of where this service lives.
//
// ⚠️ IT IS CARRIED UNDER ITS OWN PARAMETER NAME, NOT UNDER `return_to`, AND THE
// NAME IS THE SAFETY PROPERTY. `return_to` is a widely-used SAME-ORIGIN
// convention in these products, and obol's own login screen already refuses a
// value on it that is not a relative path. Handing a cross-origin absolute URL
// to that convention would either be silently dropped (harmless but confusing)
// or, the first time somebody widened the reader, become an open redirect on the
// identity backend. A distinct name means the value can only be consumed by code
// written knowing it is cross-origin — which must validate the origin against an
// allow-list before honouring it.
//
// ⚠️ AND NOTHING HONOURS IT YET, WHICH IS WHY IT IS RECORDED RATHER THAN RELIED
// ON: the information exists only here, at the moment the consumer knows both
// its own origin and where the person was heading, so dropping it would make a
// later resume impossible without changing this file again.
func (a *Auth) consumerReturnTo(target string) string {
	if target == "" || target == "/" {
		// Nothing was deep-linked; the person was heading to the service root,
		// which is where they will go anyway once the backend's flow finishes.
		return ""
	}
	if !isValidRedirect(target) {
		// Should be unreachable — `target` is either "/" or a value
		// isValidRedirect already admitted at /auth/login — but a caller-supplied
		// path that reaches here unvalidated must not be turned into an absolute
		// URL and handed to another origin.
		return ""
	}
	base, err := url.Parse(a.cfg.CallbackURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	return base.Scheme + "://" + base.Host + target
}

// appendQueryParam adds one query parameter to an absolute URL, preserving any
// the URL already carries.
func appendQueryParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
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
