package vaioidc

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
)

// StaffPolicy is the ONE staff predicate (v0.24.0): an authenticated user is
// staff when ALL of the following hold —
//
//	email_verified AND the parsed email's domain equals Domain (case-insensitive)
//	AND the user holds at least one of Roles (Keycloak realm roles, exact match)
//
// ⛔ IT EXISTS SO THREE REPOSITORIES DO NOT EACH HAND-ROLL A SECURITY PREDICATE.
// obol `/console`, the vaisite admin and the conduit admin all gate on the same
// rule (operator ruling D2, 2026-09-28); three copies drift, and the drift is a
// privilege boundary. Use VAIStaffPolicy() rather than restating the values.
//
// ⚠️ The domain match is EXACT on the parsed address: `evilvaudience.ai` and
// `x.vaudience.ai` both fail a `vaudience.ai` policy, and so does an address
// carrying a display name or any shape net/mail does not parse as a bare
// addr-spec.
type StaffPolicy struct {
	// Domain is the required email domain, e.g. "vaudience.ai". A leading "@"
	// is tolerated. Required.
	Domain string

	// Roles are the realm roles of which the user must hold AT LEAST ONE.
	// Required (non-empty).
	Roles []string

	// Forbidden, when set, answers an authenticated user the policy refuses.
	// Default: HTTP 403 with a JSON body {"error":"staff access required"}.
	// A request with no session is never passed here — it gets RequireSession's
	// answer (login redirect for a browser, 401 JSON otherwise).
	Forbidden http.Handler
}

// VAIStaffPolicy returns operator ruling D2's predicate: a verified
// @vaudience.ai address holding obol-system-admin OR vai-business-manager.
func VAIStaffPolicy() StaffPolicy {
	return StaffPolicy{
		Domain: StaffDomainVAudience,
		Roles:  []string{RealmRoleObolSystemAdmin, RealmRoleVAIBusinessManager},
	}
}

// normalizedDomain returns the lowercased domain without a leading "@".
func (p StaffPolicy) normalizedDomain() string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(p.Domain), emailAtSeparator))
}

// Validate reports whether the policy can be evaluated. An invalid policy
// refuses everyone (Check returns ErrStaffPolicyInvalid) — it never admits.
func (p StaffPolicy) Validate() error {
	d := p.normalizedDomain()
	if d == "" || strings.ContainsAny(d, requireEmailDomainForbiddenRunes) || !strings.Contains(d, ".") {
		return fmt.Errorf("staff policy domain %q: %w", p.Domain, ErrStaffPolicyInvalid)
	}
	hasRole := false
	for _, r := range p.Roles {
		if strings.TrimSpace(r) != "" {
			hasRole = true
			break
		}
	}
	if !hasRole {
		return fmt.Errorf("staff policy names no realm role: %w", ErrStaffPolicyInvalid)
	}
	return nil
}

// Check evaluates the policy against a user. nil means staff. Every refusal
// wraps ErrNotStaff together with its cause, except a nil user (ErrNoSession)
// and an invalid policy (ErrStaffPolicyInvalid).
func (p StaffPolicy) Check(u *User) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if u == nil {
		return ErrNoSession
	}
	if !u.EmailVerified {
		return errors.Join(ErrNotStaff, ErrEmailNotVerified)
	}
	domain, ok := strictEmailDomain(u.Email)
	if !ok {
		return errors.Join(ErrNotStaff, ErrEmailClaimMissing)
	}
	if domain != p.normalizedDomain() {
		return errors.Join(ErrNotStaff, ErrEmailDomainMismatch)
	}
	for _, role := range p.Roles {
		if role != "" && u.HasRealmRole(role) {
			return nil
		}
	}
	return errors.Join(ErrNotStaff, ErrStaffRoleMissing)
}

// IsStaff reports whether the user satisfies the policy.
func (u *User) IsStaff(p StaffPolicy) bool {
	return p.Check(u) == nil
}

// strictEmailDomain parses email as a bare RFC 5322 addr-spec and returns its
// lowercased domain. It refuses a display-name form ("Eve <a@b>"), surrounding
// whitespace, and anything net/mail cannot parse — the staff gate compares a
// security boundary, so an address it cannot read unambiguously is not staff.
func strictEmailDomain(email string) (string, bool) {
	if email == "" || email != strings.TrimSpace(email) {
		return "", false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Name != "" || !strings.EqualFold(addr.Address, email) {
		return "", false
	}
	domain := emailDomainOf(addr.Address)
	if domain == "" {
		return "", false
	}
	return domain, true
}

// staffReason maps a Check error to a stable log reason.
func staffReason(err error) string {
	switch {
	case errors.Is(err, ErrStaffPolicyInvalid):
		return staffReasonPolicy
	case errors.Is(err, ErrNoSession):
		return staffReasonNoSession
	case errors.Is(err, ErrEmailNotVerified):
		return staffReasonUnverified
	case errors.Is(err, ErrEmailClaimMissing):
		return staffReasonEmail
	case errors.Is(err, ErrEmailDomainMismatch):
		return staffReasonDomain
	case errors.Is(err, ErrStaffRoleMissing):
		return staffReasonRole
	default:
		return err.Error()
	}
}

// RequireStaff returns middleware that admits only users the policy accepts
// (v0.24.0). It INCLUDES RequireSession: a request with no valid session gets
// exactly RequireSession's answer (login redirect carrying the deep link for a
// browser, 401 JSON otherwise), and an authenticated non-staff user gets
// p.Forbidden (default 403 JSON). Do not stack RequireSession in front of it.
//
// ⚠️ An invalid policy is detected here, logged once at ERROR, and then
// refuses EVERY request with 403 — a misconfigured admin surface must be
// closed, never open.
//
// ⚠️ Realm roles are read from the SESSION, which captured them at login.
// Revoking a role in Keycloak takes effect at the person's next login (or when
// revalidation ends the SSO session), not on the next request.
func (a *Auth) RequireStaff(p StaffPolicy) func(http.Handler) http.Handler {
	policyErr := p.Validate()
	if policyErr != nil {
		a.logger.Error(logMsgStaffPolicyInvalid,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, policyErr.Error()),
		)
	}
	forbidden := p.Forbidden
	if forbidden == nil {
		forbidden = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": staffForbiddenErrorMsg})
		})
	}
	session := a.RequireSession()
	return func(next http.Handler) http.Handler {
		gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			err := p.Check(user)
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}
			var sub string
			if user != nil {
				sub = user.Sub
			}
			a.logger.Warn(logMsgStaffRefused,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeyStaffReason, staffReason(err)),
				slog.String(logKeySub, sub),
				slog.String(logKeyPath, r.URL.Path),
				slog.String(logKeyClientIP, clientIP(r)),
			)
			forbidden.ServeHTTP(w, r)
		})
		return session(gate)
	}
}
