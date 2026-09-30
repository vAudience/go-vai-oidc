package vaioidc

// Step-up — recent authentication (v0.28.0).
//
// # The gap this closes
//
// A sliding session (v0.19.0) proves the person is STILL signed in; it says
// nothing about WHEN they last proved who they are. A browser left unlocked
// for a day keeps a perfectly valid session, and a consumer that wants a
// dangerous write (a platform credential, a payout target) to demand a fresh
// authentication had no way to ask for one or to check that it happened:
// `/auth/login` dropped `max_age`, `User` carried no `auth_time`, and nothing
// compared the two.
//
// # The pieces
//
//  1. `/auth/login?max_age=N` — forwarded to the authorization request (OIDC
//     Core §3.1.2.1). `max_age=0` forces re-authentication. A malformed value is
//     REFUSED with 400, never dropped: silently dropping a security-strengthening
//     parameter turns a step-up into a plain login.
//  2. The callback VERIFIES `auth_time` when `max_age` was requested (§3.1.3.7
//     rule 13): the claim is then REQUIRED, and must not predate the login's
//     start minus `max_age` (and a small clock skew). A failure is refused like
//     every other callback failure — redirect to LogoutRedirect, no session.
//  3. `User.AuthTime`, persisted in the session, filled from the verified ID
//     token. ⛔ A REFRESH NEVER ADVANCES IT (see mergeRefreshedAuthTime).
//  4. `RecentlyAuthenticated` and `Auth.StepUpLoginURL` for the write door.
//
// ⚠️ THE CALLBACK CHECK IS DEFENCE IN DEPTH; THE DOOR'S CHECK IS THE GUARD. The
// requested max_age travels in a cookie this library set, but the value the
// write door decides on is AuthTime — which comes only from a signature-verified
// ID token. Stripping the cookie can at most skip the callback's refusal; it
// cannot make an old authentication look recent to RecentlyAuthenticated.

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// queryParamMaxAge is the /auth/login parameter, and the authorization
	// request parameter it is forwarded as (OIDC Core §3.1.2.1).
	queryParamMaxAge = "max_age"

	// cookieOIDCMaxAge carries the requested max_age and the login's start time
	// across the round trip, as "<max_age>.<start unix seconds>". Absent when no
	// max_age was requested, which is every login before v0.28.0.
	cookieOIDCMaxAge         = "vai_oidc_max_age"
	maxAgeCookieDelimiter    = "."
	maxAgeMaxSeconds         = math.MaxInt32
	maxAgeMaxDigits          = 10
	stepUpMaxAgeForceReauth  = "0"
	errBodyInvalidMaxAge     = "invalid max_age: must be a non-negative integer number of seconds"
	logMsgMaxAgeInvalid      = "OIDC login: invalid max_age refused"
	logMsgAuthTimeRefused    = "OIDC callback: auth_time does not satisfy the requested max_age"
	logReasonAuthTimeMissing = "auth_time_missing"
	logReasonAuthTimeStale   = "auth_time_stale"
	logReasonMaxAgeCookieBad = "max_age_cookie_malformed"
	logKeyMaxAge             = "max_age"
	logKeyAuthTime           = "auth_time"
	logKeyLoginStartedAt     = "login_started_at"
	claimAuthTime            = "auth_time"
)

// AuthTimeSkew is the clock skew tolerated between the identity provider and
// this service when comparing `auth_time`: at the callback's max_age check, and
// for an AuthTime slightly in the future in RecentlyAuthenticated.
const AuthTimeSkew = 30 * time.Second

// RecentlyAuthenticated reports whether u authenticated at the identity
// provider within window of now.
//
// It is false for a nil user, for a zero AuthTime (unknown: a session minted
// before v0.28.0, an IssueSession caller that supplied none, or an IdP that
// does not issue the claim), and for a non-positive window. An AuthTime in the
// future is accepted only within AuthTimeSkew; beyond that it fails closed.
//
// A write door that requires a step-up answers a false here with 401 and the
// URL from Auth.StepUpLoginURL.
func RecentlyAuthenticated(u *User, window time.Duration, now time.Time) bool {
	if u == nil || u.AuthTime.IsZero() || window <= 0 {
		return false
	}
	age := now.Sub(u.AuthTime)
	if age < -AuthTimeSkew {
		return false
	}
	return age <= window
}

// StepUpLoginURL returns the login URL that forces a fresh authentication and
// then returns the browser to returnTo: `<LoginPath>?max_age=0&redirect=<returnTo>`.
//
// returnTo must be a same-origin relative path (e.g. "/app/credentials"); the
// same validation /auth/login applies to `redirect`, so an absolute,
// protocol-relative or backslash URL is refused with ErrInvalidReturnPath. An
// empty returnTo is allowed and omits `redirect` (the login then lands on
// PostLoginRedirect).
//
// ⚠️ The browser must reach it by a FULL-PAGE navigation, never an XHR: it is a
// redirect chain through the identity provider's login page.
func (a *Auth) StepUpLoginURL(returnTo string) (string, error) {
	target := appendQueryParam(a.cfg.LoginPath, queryParamMaxAge, stepUpMaxAgeForceReauth)
	if returnTo == "" {
		return target, nil
	}
	if !isValidRedirect(returnTo) {
		return "", ErrInvalidReturnPath
	}
	return appendQueryParam(target, queryParamRedirect, returnTo), nil
}

// parseMaxAge validates a /auth/login max_age value. present is false when the
// parameter is absent or empty; ok is false for a malformed value.
func parseMaxAge(raw string) (seconds int64, present, ok bool) {
	if raw == "" {
		return 0, false, true
	}
	if len(raw) > maxAgeMaxDigits {
		return 0, true, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, true, false
		}
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 || v > maxAgeMaxSeconds {
		return 0, true, false
	}
	return v, true, true
}

// maxAgeCookieValue encodes the requested max_age and the login's start.
func maxAgeCookieValue(maxAge int64, startedAt time.Time) string {
	return strconv.FormatInt(maxAge, 10) + maxAgeCookieDelimiter + strconv.FormatInt(startedAt.Unix(), 10)
}

// parseMaxAgeCookie decodes maxAgeCookieValue's output.
func parseMaxAgeCookie(v string) (maxAge int64, startedAt time.Time, ok bool) {
	ageRaw, startRaw, found := strings.Cut(v, maxAgeCookieDelimiter)
	if !found {
		return 0, time.Time{}, false
	}
	maxAge, _, ageOK := parseMaxAge(ageRaw)
	if !ageOK || ageRaw == "" {
		return 0, time.Time{}, false
	}
	start, err := strconv.ParseInt(startRaw, 10, 64)
	if err != nil || start <= 0 {
		return 0, time.Time{}, false
	}
	return maxAge, time.Unix(start, 0).UTC(), true
}

// checkAuthTime enforces OIDC Core §3.1.3.7 rule 13 for a login that requested
// max_age: auth_time is REQUIRED, and the authentication must not predate the
// login's start by more than maxAge (plus AuthTimeSkew). It returns "" when the
// token satisfies the request, else the refusal reason.
//
// ⚠️ The bound is measured from when the LOGIN STARTED, not from the callback:
// with max_age=0 the person may take minutes at the password prompt, and an
// authentication performed after the request was made is exactly what the
// request asked for.
func checkAuthTime(authTime time.Time, maxAge int64, startedAt time.Time) string {
	if authTime.IsZero() {
		return logReasonAuthTimeMissing
	}
	earliest := startedAt.Add(-time.Duration(maxAge) * time.Second).Add(-AuthTimeSkew)
	if authTime.Before(earliest) {
		return logReasonAuthTimeStale
	}
	return ""
}

// verifyRequestedMaxAge runs the callback's max_age check when the login asked
// for one. It returns false (and logs) when the login must be refused.
func (a *Auth) verifyRequestedMaxAge(r *http.Request, authTime time.Time) bool {
	c, err := r.Cookie(cookieOIDCMaxAge)
	if err != nil || c.Value == "" {
		return true // no max_age requested: nothing to verify (every pre-v0.28.0 login)
	}
	maxAge, startedAt, ok := parseMaxAgeCookie(c.Value)
	reason := logReasonMaxAgeCookieBad
	if ok {
		reason = checkAuthTime(authTime, maxAge, startedAt)
	}
	if reason == "" {
		return true
	}
	attrs := []any{
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyReason, reason),
		slog.String(logKeyClientIP, clientIP(r)),
	}
	if ok {
		attrs = append(attrs, slog.Int64(logKeyMaxAge, maxAge), slog.Int64(logKeyLoginStartedAt, startedAt.Unix()))
	}
	if !authTime.IsZero() {
		attrs = append(attrs, slog.Int64(logKeyAuthTime, authTime.Unix()))
	}
	a.logger.Warn(logMsgAuthTimeRefused, attrs...)
	return false
}

// extractAuthTime reads the standard `auth_time` claim (seconds since the
// epoch, OIDC Core §2). Anything but a positive number reads as unknown.
func extractAuthTime(claims map[string]interface{}) time.Time {
	v, ok := claims[claimAuthTime].(float64)
	if !ok || v <= 0 || v > math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}

// unixOrZero stores a time as unix seconds, zero for the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// timeOrZero is unixOrZero's inverse.
func timeOrZero(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// mergeRefreshedAuthTime decides the session's auth_time after a refresh grant.
//
// ⛔ A REFRESH NEVER ADVANCES AUTH_TIME. A refresh token grant is not an
// authentication; if the stored value moved forward on it, every sliding
// session would look freshly authenticated once per RevalidateInterval and a
// step-up would be satisfied by an idle browser. Keycloak's refreshed ID token
// carries the user session's authentication time, so it is ADOPTED only when it
// fills an unknown (a session minted before v0.28.0) or is EARLIER than the
// stored one (strictly more conservative). A later value — possible when the
// person re-authenticated in the same SSO session through another client — is
// ignored: the step-up in THIS service goes through its own callback, which
// records it.
func mergeRefreshedAuthTime(stored, refreshed int64) int64 {
	if refreshed <= 0 {
		return stored
	}
	if stored <= 0 || refreshed < stored {
		return refreshed
	}
	return stored
}
