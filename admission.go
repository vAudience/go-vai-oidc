package vaioidc

// Admission — the login gates and the UserResolver as ONE function (v0.25.0).
//
// Until v0.25.0 this sequence lived inline in handleLoginCallback, which was
// fine while the callback was its only caller. Revalidation's re-resolution
// (Config.ReresolveOnRevalidate) asks the same question — "may this identity
// hold a session, and with which org and memberships?" — so it calls the same
// function instead of carrying a second copy that would drift the first time a
// gate is added to one and not the other.
//
// ⚠️ admitIdentity DOES NOT LOG. Each caller logs its own refusal, because the
// same verdict means different things at the two call sites (a login that is
// refused vs. a live session that is ended), and the callback's log lines are
// kept byte-identical to v0.24.0 so no consumer's log-based alerting moves.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

var (
	// errResolverFailed marks a UserResolver that returned an ERROR. The
	// callback refuses the login on it; revalidation fails OPEN on it, because
	// an error is the identity backend failing to answer, not answering "no".
	errResolverFailed = errors.New("vai-oidc: UserResolver returned an error")

	// errResolverNoUser marks a UserResolver that returned (nil, nil): the
	// resolver's explicit "no session for this person" (obolresolver answers
	// it for a person with no membership and no redirecting landing). Both the
	// callback and revalidation treat it as a refusal.
	errResolverNoUser = errors.New("vai-oidc: UserResolver returned no user")
)

// admitIdentity runs the login gates, in the callback's order, and then the
// UserResolver, over an identity extracted from a verified ID token (or, at
// revalidation, recovered from the session).
//
// It returns the user the session should hold, or one of:
//
//   - ErrEmailNotVerified — Config.RequireEmailVerified and the identity is not
//     verified. Runs first: an unverified address makes the domain gate's
//     verdict meaningless, and the rejection must not depend on which domain
//     the (unproven) address claims.
//   - ErrEmailClaimMissing / ErrEmailDomainMismatch — Config.RequireEmailDomain.
//     Runs BEFORE UserResolver so a custom resolver does not need to know about
//     the rule and so the rejection never carries resolver-side state.
//   - errResolverFailed (wrapping the resolver's error) — the resolver erred.
//   - errResolverNoUser — the resolver returned (nil, nil).
//
// With no UserResolver configured the identity is returned as-is.
func (a *Auth) admitIdentity(ctx context.Context, kind Admission, user *User) (*User, error) {
	ctx = context.WithValue(ctx, admissionKey{}, kind)
	if a.cfg.RequireEmailVerified && (user == nil || !user.EmailVerified) {
		return nil, ErrEmailNotVerified
	}
	if domainErr := enforceEmailDomain(user, a.cfg.RequireEmailDomain); domainErr != nil {
		return nil, domainErr
	}
	if a.cfg.UserResolver == nil {
		return user, nil
	}
	resolved, resolveErr := a.cfg.UserResolver(ctx, user)
	if resolveErr != nil {
		return nil, errors.Join(errResolverFailed, resolveErr)
	}
	if resolved == nil {
		return nil, errResolverNoUser
	}
	return resolved, nil
}

// Admission names why the UserResolver is being asked (v0.26.0). A resolver
// with side effects that belong to a SIGN-IN — an audit row, a "last login"
// stamp, invite acceptance — reads it with AdmissionFromContext and performs
// them on AdmissionLogin only. Without it, ReresolveOnRevalidate turned every
// revalidation interval into a second, fabricated sign-in.
type Admission string

const (
	// AdmissionLogin: the login callback, after a fresh authorization-code
	// exchange. A person signed in.
	AdmissionLogin Admission = "login"
	// AdmissionRevalidation: Config.ReresolveOnRevalidate re-asking the
	// resolver for a LIVE session after a successful refresh grant. Nobody
	// signed in; the question is only whether the org/role answer changed.
	AdmissionRevalidation Admission = "revalidation"
)

type admissionKey struct{}

// AdmissionFromContext reports why the UserResolver was called. It answers ""
// for a context the library did not build — a resolver invoked directly by a
// consumer's own code or test — which a resolver must treat as neither kind
// rather than guess.
func AdmissionFromContext(ctx context.Context) Admission {
	if ctx == nil {
		return ""
	}
	kind, _ := ctx.Value(admissionKey{}).(Admission)
	return kind
}

// admissionReason names a refusal from admitIdentity for a log line.
func admissionReason(err error) string {
	switch {
	case errors.Is(err, ErrEmailNotVerified):
		return logReasonEmailUnverified
	case errors.Is(err, ErrEmailDomainMismatch), errors.Is(err, ErrEmailClaimMissing):
		return domainReason(err)
	case errors.Is(err, errResolverNoUser):
		return logReasonResolverNoUser
	case errors.Is(err, errResolverFailed):
		return logReasonResolverFailed
	default:
		return err.Error()
	}
}

// logLoginRefusal writes the callback's refusal log line for err, exactly as
// handleLoginCallback wrote it inline before v0.25.0.
func (a *Auth) logLoginRefusal(r *http.Request, user *User, err error) {
	// extractUser cannot return nil today, but the gates are documented
	// nil-tolerant and sit before any UserResolver call — guard the log sites
	// so a future extractor change cannot crash the rejection log path.
	var sub, emailDomain string
	if user != nil {
		sub = user.Sub
		emailDomain = emailDomainOf(user.Email)
	}
	switch {
	case errors.Is(err, ErrEmailNotVerified):
		a.logger.Warn(logMsgEmailUnverifiedRejected,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyReason, logReasonEmailUnverified),
			slog.String(logKeySub, sub),
			slog.String(logKeyClientIP, clientIP(r)),
		)
	case errors.Is(err, ErrEmailDomainMismatch), errors.Is(err, ErrEmailClaimMissing):
		a.logger.Warn(logMsgEmailDomainRejected,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyReason, domainReason(err)),
			slog.String(logKeySub, sub),
			slog.String(logKeyEmailDomain, emailDomain),
			slog.String(logKeyRequiredDomain, a.cfg.RequireEmailDomain),
			slog.String(logKeyClientIP, clientIP(r)),
		)
	case errors.Is(err, errResolverNoUser):
		a.logger.Warn(logMsgResolverNoUser,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySub, sub),
			slog.String(logKeyClientIP, clientIP(r)),
		)
	default:
		// errResolverFailed: the message is the resolver's own error, as before.
		a.logger.Warn(logMsgResolverRejected,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, resolverError(err).Error()),
			slog.String(logKeySub, sub),
			slog.String(logKeyClientIP, clientIP(r)),
		)
	}
}

// resolverError unwraps the resolver's own error from errResolverFailed, so a
// log line carries what the resolver said and not the library's marker.
func resolverError(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if !errors.Is(e, errResolverFailed) {
				return e
			}
		}
	}
	return err
}
