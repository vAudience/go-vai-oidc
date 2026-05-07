package vaioidc

import (
	"errors"
	"strings"
)

// enforceEmailDomain checks the user's email claim against the
// configured required domain. Empty requiredDomain disables the
// check (returns nil). Comparison is case-insensitive; the caller
// is expected to have lowercased requiredDomain via applyDefaults().
//
// Returns ErrEmailClaimMissing when the gate is active and the
// email claim is empty or has no `@` separator. Returns
// ErrEmailDomainMismatch when the parsed domain does not equal
// requiredDomain.
func enforceEmailDomain(user *User, requiredDomain string) error {
	if requiredDomain == "" {
		return nil
	}
	if user == nil {
		return ErrEmailClaimMissing
	}
	domain := emailDomainOf(user.Email)
	if domain == "" {
		return ErrEmailClaimMissing
	}
	if !strings.EqualFold(domain, requiredDomain) {
		return ErrEmailDomainMismatch
	}
	return nil
}

// emailDomainOf returns the lowercased domain part of an email
// address, or "" if no `@` separator is present, OR if the `@` is
// the last rune (`"foo@"` — empty domain). Last-`@`-split
// semantics match how mail servers parse RFC-5321 quoted-local-
// part addresses (e.g. `"a@b"@example.com` → `example.com`).
func emailDomainOf(email string) string {
	if email == "" {
		return ""
	}
	idx := strings.LastIndex(email, emailAtSeparator)
	if idx < 0 || idx == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[idx+1:])
}

// domainReason maps a gate error to a stable reason-string for
// structured logs. Unknown errors fall through to the error's text.
func domainReason(err error) string {
	switch {
	case errors.Is(err, ErrEmailDomainMismatch):
		return logReasonEmailDomainMismatch
	case errors.Is(err, ErrEmailClaimMissing):
		return logReasonEmailDomainMissingClaim
	default:
		return err.Error()
	}
}
