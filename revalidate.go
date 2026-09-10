package vaioidc

// Session revalidation — the "one logout" floor (v0.19.0).
//
// # The gap this closes
//
// Before this file, a product session was an INDEPENDENT COPY of an
// authentication that happened once: RequireSession decrypted the cookie,
// checked its Exp, and never re-contacted the identity provider. Signing out of
// one product terminated the Keycloak SSO session and cleared that product's own
// cookie — and every SIBLING product kept serving the same person with full
// access until its own cookie expired, up to SessionTTL (24h by default), with
// every health signal green throughout.
//
// Nothing else in the stack closed it either: there is no session store to
// invalidate, cookies are host-only so no sibling can see them, and downstream
// authorization verifies tokens OFFLINE against cached JWKS with no
// introspection and no revocation list. Nothing anywhere re-asked the IdP
// whether the person was still signed in.
//
// # The mechanism
//
// Keycloak invalidates refresh tokens bound to an SSO session when that session
// ends. So a `refresh_token` grant is a QUESTION with a meaningful answer:
// success means the SSO session is alive, and an explicit `invalid_grant` means
// it is gone. Asking it on a floor — at most once per RevalidateInterval —
// converts the product session from an independent copy into something DERIVED
// from the IdP session, which is what "one login" means.
//
// # The three rules that make it safe rather than dangerous
//
//  1. ⛔ FAIL CLOSED ONLY ON AN EXPLICIT VERDICT. `invalid_grant` is the IdP
//     saying "this session ended". A transport error, a 5xx, or any other OAuth2
//     error code is the IdP failing to answer — and treating THAT as a sign-out
//     turns one Keycloak blip, or one rotated client secret, into a synchronized
//     fleet-wide logout. This mechanism can take down every product at once; the
//     classification is the thing that stops it.
//
//  2. ⛔ ASK THE IdP, NEVER THE LOCAL CLOCK. The refresh must be FORCED
//     (forcedRefresh), not routed through oauth2.TokenSource's expiry check,
//     which returns a still-valid token with no network call. A revalidation
//     that re-stamps the cookie without asking anyone is worse than none: it
//     keeps the product session alive while the IdP session dies underneath it,
//     widening the very divergence it was added to close.
//
//  3. ⚠️ AN UNREVALIDATABLE SESSION IS KEPT, NOT KILLED. A session issued before
//     token retention was enabled carries no refresh token, so there is no
//     question to ask. Killing it would mean a library upgrade signs out
//     everyone who is currently logged in. It is kept and expires on its own
//     Exp — a bounded transition window of at most one SessionTTL.
//
// # What this file does NOT do
//
// It sets no ceiling. The absolute bound on a session's life is the realm's
// `ssoSessionMaxLifespan`: past it a refresh grant fails regardless of what this
// library believes, and the failure arrives on the same `invalid_grant` path. A
// second ceiling here would be a second owner of one policy.

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// maybeRevalidate enforces the revalidation floor for one request.
//
// It returns the payload the caller should serve the request with — the same one
// when nothing was due, or a refreshed and re-stamped one when a grant
// succeeded — or ErrSessionRevoked when the IdP explicitly refused, in which
// case the session cookies have already been cleared on w and the caller must
// treat the request as unauthenticated.
//
// It never returns a nil payload with a nil error, and it never returns an error
// other than ErrSessionRevoked: every other outcome is a fail-open.
func (a *Auth) maybeRevalidate(w http.ResponseWriter, r *http.Request, payload *sessionPayload) (*sessionPayload, error) {
	if a.cfg.RevalidateInterval <= 0 || payload == nil {
		return payload, nil
	}

	now := time.Now().UTC()
	age := now.Sub(time.Unix(a.validationAnchor(payload), 0))
	if age < a.cfg.RevalidateInterval {
		return payload, nil
	}

	// A session with no refresh token cannot be asked about. Fail OPEN and say
	// so at DEBUG rather than WARN: on a fleet mid-upgrade this is the expected
	// state for every session issued before retention, and a warning per request
	// would bury the ones that matter.
	if payload.RefreshToken == "" {
		a.logger.Debug(logMsgRevalidateSkip,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, payload.Sub),
		)
		return payload, nil
	}

	fresh, err := a.provider.forcedRefresh(r.Context(), payload.RefreshToken)
	if err != nil {
		if isSessionRevoked(err) {
			a.logger.Info(logMsgSessionRevoked,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeySub, payload.Sub),
				slog.String(logKeyPath, r.URL.Path),
				slog.Float64(logKeyRevalidateAge, age.Seconds()),
			)
			clearSessionCookie(w, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())
			return nil, ErrSessionRevoked
		}

		// Fail OPEN — and back the anchor off, so an IdP outage does not turn
		// "retry on the next request" into "retry on EVERY request" against a
		// provider that is already unwell.
		a.logger.Warn(logMsgRevalidateSoft,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, payload.Sub),
			slog.String(logKeyOAuthErrorCode, oauthErrorCode(err)),
			slog.String(logKeyError, err.Error()),
		)
		a.persistBackoff(w, payload, now)
		return payload, nil
	}

	payload.AccessToken = fresh.AccessToken
	payload.AccessTokenExp = fresh.Expiry.Unix()
	// Keycloak MAY rotate the refresh token. Keep the old one when it does not:
	// overwriting with an empty string would leave the session unrevalidatable
	// from here on — which fails OPEN forever and is indistinguishable from
	// working, because every subsequent request takes the "no refresh token"
	// path and serves the session happily.
	//
	// ⚠️ THIS BRANCH IS CURRENTLY UNREACHABLE, AND A MUTATION REMOVING IT
	// SURVIVES THE SUITE. x/oauth2 already carries the previous refresh token
	// forward when a refresh response omits one (internal/token.go: "Don't
	// overwrite `RefreshToken` with an empty value if this was a token
	// refreshing request"), so `fresh.RefreshToken` is never empty here today
	// and no test driving a real TokenSource can tell the two versions apart.
	// It is kept deliberately: the invariant belongs to THIS code regardless of
	// which dependency happens to satisfy it, and the failure it prevents is
	// silent and permanent. Do not "simplify" it on the evidence that nothing
	// goes red — nothing can.
	if fresh.RefreshToken != "" {
		payload.RefreshToken = fresh.RefreshToken
	}
	payload.LastValidated = now.Unix()
	// The session becomes SLIDING here. Before v0.19.0 Exp was set once at login
	// and never moved, so a session was an absolute 24h grant; now an active
	// client keeps it and an abandoned one does not. The ceiling on this sliding
	// is the realm's ssoSessionMaxLifespan, enforced by the grant above failing.
	payload.Exp = now.Add(a.cfg.SessionTTL).Unix()

	if writeErr := setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger); writeErr != nil {
		// Non-fatal by the same reasoning AccessToken() uses: the IdP said this
		// person is signed in, and failing the request would be a worse answer
		// than serving it against a session whose stamp did not persist.
		a.logger.Warn(logMsgTokenPersistFail,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, writeErr.Error()),
		)
		return payload, nil
	}

	a.logger.Debug(logMsgRevalidated,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeySub, payload.Sub),
		slog.Float64(logKeyRevalidateAge, age.Seconds()),
	)
	return payload, nil
}

// validationAnchor returns the unix time the floor is measured from.
//
// ⛔ A ZERO LastValidated MUST NOT BE READ AS THE EPOCH. Every session issued
// before v0.19.0 carries zero, as does every IssueSession cookie, and treating
// those as "last validated in 1970" makes the floor overdue for all of them
// simultaneously — so the first request after a rolling upgrade fires a refresh
// grant for every logged-in user at once, against the IdP, at deploy time. The
// session's ISSUE time is the honest anchor for a session that has never been
// revalidated, and it is recoverable: Exp is issue time plus SessionTTL.
//
// ⚠️ The derivation uses the CURRENT SessionTTL. A consumer that shortens
// SessionTTL between issuing a session and reading it back computes an anchor
// LATER than the real issue time, which delays the first revalidation by the
// difference — it never brings it forward, so the failure direction is
// "revalidates a little late", never "stampedes".
func (a *Auth) validationAnchor(payload *sessionPayload) int64 {
	if payload.LastValidated > 0 {
		return payload.LastValidated
	}
	return payload.Exp - int64(a.cfg.SessionTTL.Seconds())
}

// persistBackoff moves the validation anchor forward so the next attempt happens
// no sooner than revalidateTransportBackoff from now, and writes the session back.
//
// It deliberately does NOT touch Exp: a session must not gain life from the IdP
// being unreachable. A write failure is ignored — the only cost is that the next
// request retries sooner, which is the behaviour this exists to soften, not to
// guarantee.
func (a *Auth) persistBackoff(w http.ResponseWriter, payload *sessionPayload, now time.Time) {
	backoff := revalidateTransportBackoff
	// A backoff at or beyond the interval would push the anchor into the future
	// and suppress revalidation for longer than the configured floor. Under a
	// short interval, half of it is the most that can be borrowed.
	if backoff >= a.cfg.RevalidateInterval {
		backoff = a.cfg.RevalidateInterval / 2
	}
	payload.LastValidated = now.Add(backoff - a.cfg.RevalidateInterval).Unix()
	_ = setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger)
}

// isSessionRevoked reports whether err is the IdP's explicit verdict that this
// session has ended, as opposed to the IdP failing to answer.
//
// ⛔ ONLY `invalid_grant` QUALIFIES, and the narrowness is the point:
//
//   - a transport error produces no *oauth2.RetrieveError at all — the IdP was
//     never reached, so it said nothing;
//   - a 5xx says the IdP is unwell, not that the person left;
//   - `invalid_client` is a ROTATED OR WRONG CLIENT SECRET. Failing closed on it
//     would sign out every user of the service at the moment of a credential
//     rotation, and the symptom — everyone logged out at once — reads as a
//     security incident rather than as a config error.
//
// Each of those fails OPEN, and the caller logs them loudly instead.
func isSessionRevoked(err error) bool {
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) {
		return false
	}
	return retrieve.ErrorCode == oauthErrorInvalidGrant
}

// oauthErrorCode extracts RFC 6749's `error` parameter for logging, or "" when
// the failure never reached the token endpoint. It exists so an operator reading
// a fail-open warning can tell "Keycloak is down" from "Keycloak refused us for
// a reason we deliberately do not act on".
func oauthErrorCode(err error) string {
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) {
		return retrieve.ErrorCode
	}
	return ""
}
