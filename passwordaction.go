package vaioidc

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
)

// Keycloak application-initiated actions (v0.38.0): set or change a password
// from the app.
//
// `/auth/login?kc_action=UPDATE_PASSWORD` forwards `kc_action` to the
// authorization request. Keycloak authenticates the person if needed (SSO
// usually answers without a prompt), shows its own password form, and returns
// to the callback with `kc_action_status=success|cancelled|error`. A person
// who signed in through a Google or Microsoft broker and has no password yet
// gets the same form and sets their first one.
//
// ⛔ ONLY `UPDATE_PASSWORD` AND (v0.39.0) `CONFIGURE_TOTP` ARE ACCEPTED, AND ANY
// OTHER VALUE IS REFUSED WITH
// 400, NEVER DROPPED. A dropped value silently turns the request into an
// ordinary login: the person returns signed in, with no password form ever
// shown and no status to say so. An unlisted action (delete_account, …) is a
// decision of its own and is not forwarded on a caller's say-so.
//
// # What Keycloak sends back (read from its source, keycloak/keycloak main
// and tags 21.1.2 … 26.0.0)
//
//   - success, cancelled and the ordinary error cases (action not configured,
//     disabled, or not initiable) CONTINUE the login: AuthenticationManager /
//     LoginActionsService set the `kc_action_status` client note and call
//     nextActionAfterAuthentication, and OIDCLoginProtocol.authenticated adds
//     `kc_action_status` NEXT TO a normal `code`. Those callbacks are ordinary
//     logins plus a status.
//   - a required action that ends in FAILURE goes through sendError
//     (Error.CONSENT_DENIED): `error=access_denied`, NO code and NO
//     `kc_action_status` (buildErrorRedirectUri adds neither).
//   - Keycloak ≤ 20 answered a cancelled AIA through sendError(CANCELLED_AIA):
//     `error=access_denied` and no code; CANCELLED_AIA_SILENT sent neither an
//     error nor a code.
//
// So a kc_action callback CAN arrive without a code. Treating that as a failed
// login would send a signed-in person who merely pressed "Cancel" to
// LogoutRedirect. A kc_action flow therefore answers a code-less callback by
// returning to the stored target with a status, minting nothing and leaving
// the existing session as it was.

const (
	// KCActionUpdatePassword is a Keycloak application-initiated action
	// /auth/login forwards: set (first time) or change the password.
	KCActionUpdatePassword = "UPDATE_PASSWORD"
	// KCActionConfigureTOTP (v0.39.0) is the other one: add an authenticator
	// app (a time-based one-time code) as a second factor. Keycloak shows its
	// own QR-code form; the outcome comes back exactly as for the password.
	KCActionConfigureTOTP = "CONFIGURE_TOTP"

	// KCActionStatusSuccess, KCActionStatusCancelled and KCActionStatusError
	// are the values the post-login target may carry as `kc_action_status`
	// after a kc_action login. Nothing else is ever echoed.
	KCActionStatusSuccess   = "success"
	KCActionStatusCancelled = "cancelled"
	KCActionStatusError     = "error"

	// queryParamKCAction is the /auth/login and authorize parameter;
	// queryParamKCActionStatus is Keycloak's callback parameter and the one
	// appended to the post-login target.
	queryParamKCAction       = "kc_action"
	queryParamKCActionStatus = "kc_action_status"

	// cookieOIDCKCAction marks a flow as a kc_action flow; its value is the
	// requested action. Per flow (flowcookies.go), like the max_age marker.
	cookieOIDCKCAction = "vai_oidc_kc_action"

	// oauthErrorAccessDenied is the OAuth error Keycloak sends for a refused
	// or cancelled action.
	oauthErrorAccessDenied = "access_denied"

	errBodyInvalidKCAction = "invalid kc_action: only " + KCActionUpdatePassword + " and " + KCActionConfigureTOTP + " are supported"
	logMsgKCActionInvalid  = "OIDC login: unsupported kc_action refused"
	logMsgKCActionNoCode   = "OIDC callback: application-initiated action returned without a code"
	logKeyKCActionStatus   = "kc_action_status"
)

// parseKCAction validates a /auth/login kc_action value. present is false when
// the parameter is absent or empty; ok is false for any value but
// KCActionUpdatePassword and KCActionConfigureTOTP (matched exactly —
// Keycloak's aliases are case-sensitive).
func parseKCAction(raw string) (action string, present, ok bool) {
	switch raw {
	case "":
		return "", false, true
	case KCActionUpdatePassword, KCActionConfigureTOTP:
		return raw, true, true
	}
	return "", true, false
}

// recognisedKCActionStatus returns raw when it is one of the three statuses
// Keycloak defines, else "".
func recognisedKCActionStatus(raw string) string {
	switch raw {
	case KCActionStatusSuccess, KCActionStatusCancelled, KCActionStatusError:
		return raw
	}
	return ""
}

// PasswordActionURL returns the login URL that asks Keycloak to let the person
// set or change their password, then returns the browser to returnTo:
// `<LoginPath>?kc_action=UPDATE_PASSWORD&redirect=<returnTo>`. The landing URL
// carries `kc_action_status=success|cancelled|error`.
//
// returnTo is validated exactly as StepUpLoginURL validates it: a same-origin
// relative path, else ErrInvalidReturnPath. An empty returnTo omits `redirect`
// (the browser then lands on PostLoginRedirect).
//
// ⚠️ Reach it by a FULL-PAGE navigation, never an XHR: it is a redirect chain
// through the identity provider.
func (a *Auth) PasswordActionURL(returnTo string) (string, error) {
	return a.KCActionURL(KCActionUpdatePassword, returnTo)
}

// KCActionURL (v0.39.0) is PasswordActionURL for any accepted action:
// `<LoginPath>?kc_action=<action>&redirect=<returnTo>`. An action parseKCAction
// does not accept is ErrInvalidKCAction; returnTo is validated as
// PasswordActionURL validates it.
func (a *Auth) KCActionURL(action, returnTo string) (string, error) {
	if got, present, ok := parseKCAction(action); !present || !ok || got == "" {
		return "", ErrInvalidKCAction
	}
	target := appendQueryParam(a.cfg.LoginPath, queryParamKCAction, action)
	if returnTo == "" {
		return target, nil
	}
	if !isValidRedirect(returnTo) {
		return "", ErrInvalidReturnPath
	}
	return appendQueryParam(target, queryParamRedirect, returnTo), nil
}

// ErrInvalidKCAction is KCActionURL's answer for an action /auth/login would
// refuse.
var ErrInvalidKCAction = errors.New("vaioidc: unsupported kc_action")

// kcActionFlow reports whether the callback's flow started as a kc_action
// login. err is errDuplicateCookie for a tossed duplicate marker.
func (a *Auth) kcActionFlow(r *http.Request, flow string) (bool, error) {
	c, err := uniqueCookie(r, a.cfg.flowCookie(cookieOIDCKCAction, flow))
	if errors.Is(err, errDuplicateCookie) {
		return false, err
	}
	return err == nil && c.Value != "", nil
}

// kcActionCallbackStatus is the status a kc_action flow's callback reports:
// Keycloak's own when recognised; for a code-less callback without one, the
// OAuth error decides — access_denied (the person cancelled or refused) is
// `cancelled`, anything else `error`.
func kcActionCallbackStatus(r *http.Request, codeless bool) string {
	q := r.URL.Query()
	if s := recognisedKCActionStatus(q.Get(queryParamKCActionStatus)); s != "" {
		return s
	}
	if !codeless {
		return ""
	}
	errParam := q.Get(queryParamError)
	if errParam == "" || errParam == oauthErrorAccessDenied {
		// No error at all is Keycloak ≤ 20's CANCELLED_AIA_SILENT.
		return KCActionStatusCancelled
	}
	return KCActionStatusError
}

// handleKCActionWithoutCode ends a kc_action flow whose callback carries no
// code: after the state check, it returns to the stored target with a status
// and mints nothing — the session the person already holds is untouched.
// Returns false when the callback carries a code (an ordinary login follows).
func (a *Auth) handleKCActionWithoutCode(w http.ResponseWriter, r *http.Request, storedState, storedRedirect string) bool {
	q := r.URL.Query()
	if q.Get(queryParamCode) != "" {
		return false
	}
	queryState := q.Get(queryParamState)
	if queryState == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(storedState)) != 1 {
		a.logger.Warn("OIDC callback: state mismatch",
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		http.Redirect(w, r, a.cfg.LogoutRedirect, http.StatusFound)
		return true
	}
	status := kcActionCallbackStatus(r, true)
	a.logger.Info(logMsgKCActionNoCode,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyKCActionStatus, status),
		slog.String(logKeyReason, q.Get(queryParamError)),
		slog.String(logKeyClientIP, clientIP(r)),
	)
	target := appendQueryParam(a.postLoginTarget(storedRedirect), queryParamKCActionStatus, status)
	http.Redirect(w, r, target, http.StatusFound)
	return true
}
