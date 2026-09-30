package vaioidc

// Re-resolution on revalidation (v0.25.0) — Config.ReresolveOnRevalidate.
//
// # The gap this closes
//
// UserResolver runs at the login callback and nowhere else, and revalidation
// (revalidate.go) refreshes tokens without re-asking it. So a session's OrgID,
// Memberships, role and resolver-set claims were a SNAPSHOT of the identity
// backend taken at login and kept for the whole SSO session — which, since
// v0.19.0 made sessions sliding, has no upper bound short of the realm's
// ssoSessionMaxLifespan. A person demoted or removed in the backend kept the
// login-time answer.
//
// # Why this is not session sync's reasoning
//
// handleSyncCallback deliberately skips the resolver: it runs on a timer in
// every browser tab, and it can only confirm or destroy a session, never grant
// one. Revalidation is different on both counts — it runs server-side at most
// once per RevalidateInterval per session, and it already RE-STAMPS the session
// (a grant of more life), so the question "may this person still hold what the
// cookie says?" belongs exactly here.
//
// # The rules
//
//  1. ONE ADMISSION FUNCTION. The gates and the resolver run through
//     admitIdentity, the function the callback calls, so a gate added to login
//     is re-checked here without a second copy.
//  2. ⛔ A RESOLVER ERROR FAILS OPEN; A RESOLVER ANSWER DOES NOT. An error is
//     the backend failing to answer — ending sessions on it would turn one obol
//     blip into a fleet-wide logout, the exact failure revalidate.go's
//     classification exists to prevent. (nil, nil), a gate refusal, and an
//     empty answer whose landing would redirect are ANSWERS, and a session the
//     login would not grant is ended.
//  3. THE INPUT IS WHAT THE CALLBACK WOULD SEE. The refreshed ID token when the
//     IdP returned one and it verifies for the same subject; otherwise the
//     identity stored in the session, stripped of everything a resolver sets.

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"slices"

	"golang.org/x/oauth2"
)

// reresolveOutcome is what maybeRevalidate must do after a re-resolution.
type reresolveOutcome int

const (
	// reresolveApplied: the payload now carries the new answer; stamp it.
	reresolveApplied reresolveOutcome = iota
	// reresolveSoft: the resolver erred; the payload keeps its old resolved
	// fields and the caller backs off (fail-open).
	reresolveSoft
	// reresolveEnded: the answer no longer admits a session; sign out.
	reresolveEnded
)

// reresolve re-runs admission for the session in payload after the refresh
// grant that produced fresh, and applies a successful answer to payload.
func (a *Auth) reresolve(r *http.Request, payload *sessionPayload, fresh *oauth2.Token) reresolveOutcome {
	identity, source := a.revalidationIdentity(r.Context(), payload, fresh)

	resolved, err := a.admitIdentity(r.Context(), AdmissionRevalidation, identity)
	if err != nil {
		reason := admissionReason(err)
		if reason == logReasonResolverFailed {
			a.logger.Warn(logMsgReresolveSoft,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeySub, payload.Sub),
				slog.String(logKeyIdentitySource, source),
				slog.String(logKeyError, resolverError(err).Error()),
			)
			return reresolveSoft
		}
		a.logger.Info(logMsgReresolveEnded,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, payload.Sub),
			slog.String(logKeyReason, reason),
			slog.String(logKeyIdentitySource, source),
			slog.String(logKeyPath, r.URL.Path),
		)
		return reresolveEnded
	}

	// ⛔ An org-less answer whose landing redirects is, at login, a trip to the
	// backend's funnel — the browser never serves a request on that session.
	// Revalidation cannot navigate, so keeping the org-less session would serve
	// requests the login never would (several fleet services read an empty
	// OrgID as ALL TENANTS). End it; the next login takes the person there.
	if hasNoOrg(resolved) {
		if _, redirects := resolved.Landing.RedirectTarget(); redirects {
			a.logger.Info(logMsgReresolveEnded,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeySub, payload.Sub),
				slog.String(logKeyReason, logReasonLandingRedirect),
				slog.String(logKeyIdentitySource, source),
				slog.String(logKeyPath, r.URL.Path),
			)
			return reresolveEnded
		}
	}

	previousOrg := payload.OrgID
	payload.fromUser(resolved)
	// The one deviation from the callback: an org the person picked after
	// login (UpdateSession) survives while it is still one of theirs. The
	// callback resets it because a login is a fresh start; a revalidation is
	// not, and resetting a picker's choice every interval would be a defect.
	if previousOrg != "" && previousOrg != payload.OrgID && isMemberOf(resolved.Memberships, previousOrg) {
		payload.OrgID = previousOrg
	}

	a.logger.Debug(logMsgReresolved,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeySub, payload.Sub),
		slog.String(logKeyIdentitySource, source),
	)
	return reresolveApplied
}

// revalidationIdentity builds the resolver's input: the refreshed ID token's
// identity when there is one that verifies for this session's subject, else the
// session's stored identity. It also reports which one it used.
func (a *Auth) revalidationIdentity(ctx context.Context, payload *sessionPayload, fresh *oauth2.Token) (*User, string) {
	if raw, ok := fresh.Extra(extraIDToken).(string); ok && raw != "" && a.provider.verifier != nil {
		// VerifyIDToken is the callback's verifier and extractor, unchanged.
		user, err := a.VerifyIDToken(ctx, raw)
		if err == nil && user.Sub == payload.Sub {
			return user, identitySourceRefreshedIDToken
		}
		// A token that does not verify is not evidence of anything; neither is
		// one naming another subject, which a refresh bound to this session
		// cannot legitimately produce. Neither ends the session (that is the
		// IdP's verdict to give, via invalid_grant), and the resolver still
		// runs — on the identity the session already holds.
		a.logger.Warn(logMsgReresolveIDToken,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, payload.Sub),
		)
	}
	return storedIdentity(payload), identitySourceSession
}

// storedIdentity recovers, from the session, the identity extractUser produced
// at login: the ID-token fields, without anything a resolver sets (OrgID,
// Memberships, Landing). Slices and maps are copied so a resolver mutating its
// input cannot write through into the payload.
func storedIdentity(p *sessionPayload) *User {
	return &User{
		Sub:           p.Sub,
		Email:         p.Email,
		EmailVerified: p.Ev,
		Name:          p.Name,
		Claims:        maps.Clone(p.Claims),
		RealmRoles:    slices.Clone(p.Rls),
		SessionID:     p.Sid,
	}
}

// hasNoOrg reports whether an answer places the person in no organization.
func hasNoOrg(u *User) bool {
	return u.OrgID == "" && len(u.Memberships) == 0
}

// isMemberOf reports whether orgID is one of the memberships.
func isMemberOf(memberships []Membership, orgID string) bool {
	return slices.ContainsFunc(memberships, func(m Membership) bool { return m.OrgID == orgID })
}
