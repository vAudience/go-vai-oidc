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
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
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
//
// v0.30.0 (go-vai-oidc#19): two kinds of work can be due. The IdP floor
// (LastValidated + RevalidateInterval) runs the grant and, when configured, the
// re-resolution; a pending resolver retry (ResolveRetryAt) re-asks ONLY the
// resolver. Both run through a.flights, so concurrent requests carrying one
// cookie share one grant and one resolver call.
func (a *Auth) maybeRevalidate(w http.ResponseWriter, r *http.Request, payload *sessionPayload) (*sessionPayload, error) {
	if a.cfg.RevalidateInterval <= 0 || payload == nil {
		return payload, nil
	}

	now := a.clock()
	age := now.Sub(time.Unix(a.validationAnchor(payload), 0))
	if age >= a.cfg.RevalidateInterval {
		return a.revalidateAtIdP(w, r, payload, now, age)
	}
	if a.resolveRetryDue(payload, now) {
		return a.retryResolution(w, r, payload, now)
	}
	return payload, nil
}

// revalidateAtIdP asks the IdP (a forced refresh grant) and, when configured,
// the resolver, and applies the shared answers to payload.
func (a *Auth) revalidateAtIdP(w http.ResponseWriter, r *http.Request, payload *sessionPayload, now time.Time, age time.Duration) (*sessionPayload, error) {
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

	// ⛔ The key is the refresh token the cookie carries (with the subject):
	// every request holding that token is asking the SAME question, and under
	// rotation only the first may ask it. The validation anchor is part of the
	// key so a retained answer can only ever serve the SAME due revalidation —
	// never a later one whose cookie happens to carry an unrotated token (with a
	// short interval, that would answer from memory instead of asking the IdP).
	// The leader's payload is the input; each caller applies the answers to its
	// own payload below.
	leader := *payload
	key := flightKey(flightKindGrant, payload.Sub, payload.RefreshToken,
		strconv.FormatInt(payload.LastValidated, 10), strconv.FormatInt(payload.Exp, 10))
	shared := a.flights.do(r.Context(), key, a.clock, func() revalShared {
		ctx, cancel := sharedContext(r)
		defer cancel()
		fresh, err := a.provider.forcedRefresh(ctx, leader.RefreshToken)
		if err != nil {
			return revalShared{grantErr: err}
		}
		out := revalShared{fresh: fresh, aut: a.refreshedAuthTime(ctx, &leader, fresh)}
		// v0.25.0: re-ask the identity backend too, when configured. It runs
		// only on a SUCCESSFUL grant — the IdP has just said this person is
		// signed in, so the remaining question is what they may now hold.
		if a.cfg.ReresolveOnRevalidate {
			out.reresolved = true
			out.outcome, out.resolved = a.reresolve(ctx, r.URL.Path, &leader, fresh)
		}
		return out
	})

	if err := shared.grantErr; err != nil {
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

	fresh := shared.fresh
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

	// v0.28.0: a refresh is not an authentication. auth_time from a verified
	// refreshed ID token may FILL an unknown or move EARLIER, never later.
	payload.Aut = mergeRefreshedAuthTime(payload.Aut, shared.aut)

	if shared.reresolved {
		switch shared.outcome {
		case reresolveEnded:
			clearSessionCookie(w, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())
			return nil, ErrSessionRevoked
		case reresolveSoft:
			// Fail OPEN: keep the old resolved fields and persist the
			// refreshed tokens (a rotated refresh token must not be lost).
			//
			// ⛔ v0.30.0 (go-vai-oidc#19): the IdP check SUCCEEDED, so it is
			// RECORDED — LastValidated = now — and only the RESOLVER is retried,
			// on its own anchor. Backing off LastValidated instead (v0.25.0 …
			// v0.29.0) made the retry re-run the Keycloak grant every 30 s per
			// session for as long as the identity backend was down.
			//
			// Exp still does NOT slide: a session must not gain life while its
			// resolution cannot be re-derived. The retry slides it to what this
			// IdP check allowed (LastValidated + SessionTTL) once it succeeds.
			payload.LastValidated = now.Unix()
			payload.ResolveRetryAt = now.Add(a.transportBackoff()).Unix()
			a.writeSession(w, payload)
			return payload, nil
		case reresolveApplied:
			a.applyResolution(payload, shared.resolved)
		}
	}
	payload.ResolveRetryAt = 0
	payload.LastValidated = now.Unix()
	// The session becomes SLIDING here. Before v0.19.0 Exp was set once at login
	// and never moved, so a session was an absolute 24h grant; now an active
	// client keeps it and an abandoned one does not. The ceiling on this sliding
	// is the realm's ssoSessionMaxLifespan, enforced by the grant above failing.
	payload.Exp = now.Add(a.cfg.SessionTTL).Unix()

	if !a.writeSession(w, payload) {
		return payload, nil
	}

	a.logger.Debug(logMsgRevalidated,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeySub, payload.Sub),
		slog.Float64(logKeyRevalidateAge, age.Seconds()),
	)
	return payload, nil
}

// resolveRetryDue reports whether a soft-failed re-resolution is due to be
// retried. A retry recorded under ReresolveOnRevalidate is ignored once the flag
// is off; the next full revalidation clears it.
func (a *Auth) resolveRetryDue(payload *sessionPayload, now time.Time) bool {
	return a.cfg.ReresolveOnRevalidate && payload.ResolveRetryAt > 0 && now.Unix() >= payload.ResolveRetryAt
}

// retryResolution re-asks ONLY the resolver, after a re-resolution soft-failed
// on a revalidation whose IdP grant succeeded (v0.30.0, go-vai-oidc#19). The IdP
// is not asked: its last answer is LastValidated, and its floor is unchanged.
//
// The resolver's input is the identity the session stores — there is no fresh
// ID token, because there was no grant.
func (a *Auth) retryResolution(w http.ResponseWriter, r *http.Request, payload *sessionPayload, now time.Time) (*sessionPayload, error) {
	leader := *payload
	key := flightKey(flightKindResolve, payload.Sub, payload.RefreshToken,
		strconv.FormatInt(payload.LastValidated, 10), strconv.FormatInt(payload.ResolveRetryAt, 10))
	shared := a.flights.do(r.Context(), key, a.clock, func() revalShared {
		ctx, cancel := sharedContext(r)
		defer cancel()
		out := revalShared{reresolved: true}
		out.outcome, out.resolved = a.reresolve(ctx, r.URL.Path, &leader, nil)
		return out
	})
	if shared.grantErr != nil {
		// The shared work was abandoned (a panic, or this request's own
		// cancellation): fail open, change nothing, retry on a later request.
		return payload, nil
	}

	switch shared.outcome {
	case reresolveEnded:
		clearSessionCookie(w, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())
		return nil, ErrSessionRevoked
	case reresolveSoft:
		payload.ResolveRetryAt = now.Add(a.transportBackoff()).Unix()
		a.writeSession(w, payload)
		return payload, nil
	case reresolveApplied:
	}
	a.applyResolution(payload, shared.resolved)
	payload.ResolveRetryAt = 0
	// Slide Exp to what the last IdP check allowed — exactly what a grant that
	// had re-resolved successfully at LastValidated would have stamped — and
	// never shorten it.
	if allowed := payload.LastValidated + int64(a.cfg.SessionTTL.Seconds()); allowed > payload.Exp {
		payload.Exp = allowed
	}
	a.writeSession(w, payload)
	return payload, nil
}

// writeSession writes payload back as the session cookie and reports whether it
// persisted.
//
// A failure is non-fatal by the same reasoning AccessToken() uses: the IdP said
// this person is signed in, and failing the request would be a worse answer
// than serving it against a session whose stamp did not persist.
func (a *Auth) writeSession(w http.ResponseWriter, payload *sessionPayload) bool {
	if err := setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger); err != nil {
		a.logger.Warn(logMsgTokenPersistFail,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, err.Error()),
		)
		return false
	}
	return true
}

// refreshedAuthTime returns the auth_time (unix seconds) of the refreshed ID
// token when the grant returned one that verifies for this session's subject,
// else 0. A token that does not verify is not evidence of anything.
func (a *Auth) refreshedAuthTime(ctx context.Context, payload *sessionPayload, fresh *oauth2.Token) int64 {
	raw, ok := fresh.Extra(extraIDToken).(string)
	if !ok || raw == "" || a.provider.verifier == nil {
		return 0
	}
	user, err := a.VerifyIDToken(ctx, raw)
	if err != nil || user.Sub != payload.Sub {
		return 0
	}
	return unixOrZero(user.AuthTime)
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
	payload.LastValidated = now.Add(a.transportBackoff() - a.cfg.RevalidateInterval).Unix()
	_ = setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger)
}

// transportBackoff is how long a fail-open outcome waits before its retry.
//
// A backoff at or beyond the interval would push the anchor into the future and
// suppress revalidation for longer than the configured floor. Under a short
// interval, half of it is the most that can be borrowed.
func (a *Auth) transportBackoff() time.Duration {
	if revalidateTransportBackoff >= a.cfg.RevalidateInterval {
		return a.cfg.RevalidateInterval / 2
	}
	return revalidateTransportBackoff
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
