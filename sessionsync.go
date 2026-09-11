package vaioidc

// Session sync — the identity half of "one logout" (v0.20.0).
//
// # The gap this closes, and why v0.19.0 could not close it
//
// v0.19.0 made a product session DERIVED from the IdP session by asking the
// token endpoint, on a floor, whether the session behind the cookie was still
// alive. That answers LIVENESS. It cannot answer IDENTITY, and the difference
// is what an operator's live walk found on 2026-09-11:
//
//	sign in as A on one product, then sign in as B at Keycloak, and the first
//	product keeps serving A — with revalidation enabled, passing, and correct.
//
// The refresh grant is bound to A's SSO session. Signing in as B mints a NEW
// Keycloak session and swaps the browser's identity cookie; it does not
// terminate A's, which survives to its own idle timeout. So the floor asks "is
// A alive?", Keycloak truthfully answers "yes", and the refreshed tokens come
// back carrying A's `sub`. ⛔ NO INTERVAL FIXES THIS. Polling faster asks the
// same question more often and gets the same answer; the axis is the QUESTION,
// not the frequency.
//
// # The mechanism
//
// Only a request that travels through the BROWSER carries the browser's
// Keycloak cookie. An OIDC authorization request with `prompt=none` is exactly
// that: Keycloak answers from the browser's current SSO session or refuses with
// an explicit error, and never renders a login form. Compare the `sid`/`sub` it
// returns with the ones in this product's own cookie and there are three
// verdicts — unchanged, switched, signed out — of which the middle one was
// previously unrepresentable anywhere in the fleet.
//
// ⭐ THE SUBDOMAIN DECISION IS WHAT MAKES THIS AFFORDABLE HERE. Every product
// and the IdP sit under one registrable domain, so the hidden iframe is
// SAME-SITE. Third-party-cookie blocking — the reason silent renewal is dying
// on the open web — does not apply. Had the fleet chosen an apex per product,
// this option would not exist.
//
// # The rules that make it safe rather than dangerous
//
//  1. ⛔ FAIL CLOSED ONLY ON AN EXPLICIT VERDICT — the same rule the revalidation
//     floor lives by, and for the same reason: this mechanism can sign out every
//     user of every product at once. `login_required` and its siblings are the
//     IdP saying "there is no session here". A transport failure, a 5xx, a state
//     mismatch or any other error code is the IdP failing to answer, and each
//     leaves the session untouched.
//
//  2. ⛔ A MISMATCH CLEARS, IT NEVER RE-MINTS. Operator decision 2026-09-11: a
//     tab must not change owner underneath unsaved work. The strictness costs
//     the user nothing — the browser still holds the new SSO session, so their
//     next sign-in click returns without a credential prompt.
//
//  3. ⛔ AN EMPTY STORED `sid` IS NOT A MISMATCH. Every session minted before
//     v0.20.0 carries none. Treating absent as different would sign out every
//     logged-in user the moment a consumer upgrades — a library bump presenting
//     as a fleet-wide logout, which is the single worst failure this file could
//     have. Absent `sid` falls back to comparing `sub` alone.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"time"
)

// handleSessionSync starts one silent identity reconciliation.
//
// It is loaded by the browser in a hidden SAME-ORIGIN iframe. It redirects that
// iframe to the IdP with `prompt=none`; the IdP redirects it back to this
// consumer's ordinary callback URL, where handleSyncCallback reaches the verdict
// and renders it.
func (a *Auth) handleSessionSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)

	if !a.cfg.SessionSyncEnabled {
		a.writeSyncResult(w, SessionSyncDisabled)
		return
	}

	// Nothing to reconcile. ⛔ Deliberately NOT a silent sign-in: this endpoint's
	// contract is to compare an existing session against the browser, and a
	// version that also minted sessions would let any page on this origin create
	// one as a side effect of being loaded in a frame.
	if _, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName); err != nil {
		a.writeSyncResult(w, SessionSyncNoSession)
		return
	}

	state, err := generateState()
	if err != nil {
		a.syncFailOpen(w, "state generation failed", err)
		return
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		a.syncFailOpen(w, "PKCE generation failed", err)
		return
	}

	setOIDCCookie(w, cookieOIDCState, state, a.cfg.CookiePath, a.cfg.secureCookie())
	setOIDCCookie(w, cookiePKCEVerifier, verifier, a.cfg.CookiePath, a.cfg.secureCookie())
	setOIDCCookie(w, cookieOIDCSync, cookieSyncMarkerValue, a.cfg.CookiePath, a.cfg.secureCookie())

	// ⛔ `prompt=none` is the whole safety property of running this in an iframe.
	// Without it Keycloak renders its login page into a frame the user cannot
	// see, and the reconciliation becomes an invisible dead end that reports
	// nothing. ⚠️ No `kc_idp_hint` is sent for the same reason: a hint can send
	// the frame off to an external IdP's interactive page.
	authURL := a.provider.authCodeURL(state, challenge, map[string]string{queryParamPrompt: promptNone})

	a.logger.Debug(logMsgSyncStart,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyClientIP, clientIP(r)),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleSyncCallback reaches the verdict for one silent reconciliation.
//
// ⛔ IT MINTS NO SESSION, EVER, and that is why it deliberately skips the
// email-domain gate, the UserResolver and the landing decision that the login
// callback runs. Those gates decide whether somebody may be GRANTED a session;
// this path can only confirm or destroy one that already passed them. Running
// a UserResolver here would also put a network call to the identity backend on
// a timer in every browser tab.
func (a *Auth) handleSyncCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)

	stateCookie, stateErr := r.Cookie(cookieOIDCState)
	pkceCookie, pkceErr := r.Cookie(cookiePKCEVerifier)

	clearOIDCCookie(w, cookieOIDCState, a.cfg.CookiePath, a.cfg.secureCookie())
	clearOIDCCookie(w, cookiePKCEVerifier, a.cfg.CookiePath, a.cfg.secureCookie())
	clearOIDCCookie(w, cookieOIDCSync, a.cfg.CookiePath, a.cfg.secureCookie())

	if stateErr != nil || pkceErr != nil {
		a.syncFailOpen(w, "sync callback: missing state or PKCE cookie", nil)
		return
	}

	// The session may have been cleared by another request between the start of
	// this round trip and now. There is then nothing to reconcile, and clearing
	// an already-absent session is not an outcome worth reporting as a change.
	payload, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	if err != nil {
		a.writeSyncResult(w, SessionSyncNoSession)
		return
	}

	if errParam := r.URL.Query().Get(queryParamError); errParam != "" {
		if isSyncNoSessionError(errParam) {
			a.logger.Info(logMsgSyncSignedOut,
				slog.String(logKeyComponent, logComponent),
				slog.String(logKeySub, payload.Sub),
				slog.String(logKeyOAuthErrorCode, errParam),
			)
			clearSessionCookie(w, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())
			a.writeSyncResult(w, SessionSyncSignedOut)
			return
		}
		// ⛔ Any other IdP error is the IdP failing to answer, not a verdict.
		// `invalid_client` from a rotated secret arrives here, and failing closed
		// on it would sign out every user of this service at the moment of a
		// credential rotation.
		a.syncFailOpenCode(w, "sync callback: IdP returned a non-verdict error", errParam)
		return
	}

	storedState, _ := parseStateCookie(stateCookie.Value)
	queryState := r.URL.Query().Get(queryParamState)
	if queryState == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(storedState)) != 1 {
		a.syncFailOpen(w, "sync callback: state mismatch", nil)
		return
	}

	code := r.URL.Query().Get(queryParamCode)
	if code == "" {
		a.syncFailOpen(w, "sync callback: missing code parameter", nil)
		return
	}

	token, _, idToken, err := a.provider.exchange(r.Context(), code, pkceCookie.Value)
	if err != nil {
		a.syncFailOpen(w, "sync callback: token exchange failed", err)
		return
	}

	browser := a.provider.extractUser(idToken, a.logger, a.cfg.ExtraClaims)
	if browser == nil || browser.Sub == "" {
		a.syncFailOpen(w, "sync callback: the ID token carried no subject", nil)
		return
	}

	if !sameIdentity(payload, browser) {
		a.logger.Info(logMsgSyncSwitched,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeySyncPriorSub, payload.Sub),
			slog.String(logKeySyncBrowserSub, browser.Sub),
			slog.String(logKeyClientIP, clientIP(r)),
		)
		clearSessionCookie(w, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie())
		a.writeSyncResult(w, SessionSyncSwitched)
		return
	}

	// Same person, same sign-in. This round trip WAS an IdP interaction, so it
	// carries the same weight a successful revalidation does: the anchor moves,
	// the session slides, and retained tokens are refreshed from the exchange we
	// have already paid for. ⚠️ A failure to persist is not fatal — the IdP said
	// this person is signed in, and the verdict stands whether or not the stamp
	// was written.
	now := time.Now().UTC()
	payload.LastValidated = now.Unix()
	payload.Exp = now.Add(a.cfg.SessionTTL).Unix()
	if a.cfg.RetainTokens && token != nil {
		payload.AccessToken = token.AccessToken
		payload.AccessTokenExp = token.Expiry.Unix()
		if token.RefreshToken != "" {
			payload.RefreshToken = token.RefreshToken
		}
	}
	// A session minted before v0.20.0 carries no `sid`; record it now so the
	// NEXT sync can compare on the sign-in rather than only on the person.
	if payload.Sid == "" {
		payload.Sid = browser.SessionID
	}
	if writeErr := setSessionCookie(w, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, a.cfg.secureCookie(), a.logger); writeErr != nil {
		a.logger.Warn(logMsgTokenPersistFail,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyError, writeErr.Error()),
		)
	}

	a.logger.Debug(logMsgSyncUnchanged,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeySub, payload.Sub),
	)
	a.writeSyncResult(w, SessionSyncUnchanged)
}

// sameIdentity reports whether the browser's current IdP identity is the one
// this product's session was minted from.
//
// ⛔ THE `sid` COMPARISON IS CONDITIONAL ON BOTH SIDES BEING PRESENT, AND THAT IS
// NOT DEFENSIVENESS, IT IS THE UPGRADE PATH. Every session issued before
// v0.20.0 carries an empty Sid; comparing it against a live one would report
// SWITCHED for every logged-in user on the first sync after a deploy — a
// library upgrade that signs out the entire fleet. When either side is empty the
// comparison degrades to `sub`, which is exactly the pre-v0.20.0 amount of
// information, and the session self-heals its Sid on that first sync.
func sameIdentity(payload *sessionPayload, browser *User) bool {
	if payload == nil || browser == nil {
		return false
	}
	if payload.Sub != browser.Sub {
		return false
	}
	if payload.Sid != "" && browser.SessionID != "" {
		return payload.Sid == browser.SessionID
	}
	return true
}

// isSyncNoSessionError reports whether an IdP error code is the EXPLICIT verdict
// that `prompt=none` cannot be satisfied because the browser holds no usable
// session — as opposed to the IdP failing to answer.
//
// ⛔ The list is an ENUMERATION of RFC 6749 §3.1.2.6 / OIDC Core §3.1.2.6 codes
// that all mean "user interaction would be required", and it is deliberately
// closed: a default-closed rule ("anything that is not a known transport
// failure means signed out") would turn every future Keycloak error code into a
// fleet-wide logout.
func isSyncNoSessionError(code string) bool {
	switch code {
	case oauthErrorLoginRequired,
		oauthErrorInteractionRequired,
		oauthErrorConsentRequired,
		oauthErrorAccountSelectionRequired:
		return true
	default:
		return false
	}
}

// syncFailOpen logs a non-verdict and renders `error`. The session is untouched.
func (a *Auth) syncFailOpen(w http.ResponseWriter, reason string, err error) {
	attrs := []any{
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyReason, reason),
	}
	if err != nil {
		attrs = append(attrs, slog.String(logKeyError, err.Error()))
	}
	a.logger.Warn(logMsgSyncSoft, attrs...)
	a.writeSyncResult(w, SessionSyncError)
}

// syncFailOpenCode is syncFailOpen for a refusal that carried an OAuth error code.
func (a *Auth) syncFailOpenCode(w http.ResponseWriter, reason, code string) {
	a.logger.Warn(logMsgSyncSoft,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyReason, reason),
		slog.String(logKeyOAuthErrorCode, code),
	)
	a.writeSyncResult(w, SessionSyncError)
}

// writeSyncResult renders the verdict document the hidden iframe becomes.
//
// It reports the result TWICE, on purpose:
//
//   - a postMessage to window.parent, which is the mechanism, and
//   - <html data-vaioidc-sync-result="…">, which a SAME-ORIGIN parent can read
//     through iframe.contentDocument.
//
// ⚠️ THE FALLBACK IS NOT REDUNDANCY FOR ITS OWN SAKE. The postMessage needs an
// inline script, and an inline script needs a CSP that permits it. This document
// serves its own policy with its own nonce, but a consumer whose middleware
// OVERWRITES Content-Security-Policy on every response silently strips that —
// and a CSP violation is reported to a browser console and NOWHERE ELSE, so the
// failure would be invisible on exactly the product with the strictest policy.
// The data attribute survives that, because it needs no script at all.
func (a *Auth) writeSyncResult(w http.ResponseWriter, result SessionSyncResult) {
	nonce, err := syncNonce()
	if err != nil {
		// Without a nonce the inline script cannot be permitted by our own
		// policy. Serve the attribute-only document rather than a script the
		// browser will refuse: a silently-blocked script is worse than an
		// honestly-absent one.
		a.logger.Warn(logMsgSyncSoft,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyReason, "sync result: nonce generation failed"),
			slog.String(logKeyError, err.Error()),
		)
		nonce = ""
	}

	w.Header().Set(headerCacheControl, cacheControlNoStore)
	if nonce != "" {
		w.Header().Set(headerCSP, fmt.Sprintf(syncCSPTemplate, nonce))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	safe := html.EscapeString(string(result))
	body := "<!doctype html><html " + syncResultDataAttr + "=\"" + safe + "\"><head><meta charset=\"utf-8\"><title>session sync</title>"
	if nonce != "" {
		// ⚠️ The target origin is window.location.origin, NOT "*". The frame is
		// same-origin with its parent by construction, so its own origin IS the
		// parent's — which means the correct target needs no configuration and
		// cannot be widened by a consumer getting it wrong.
		body += "<script nonce=\"" + html.EscapeString(nonce) + "\">" +
			"try{window.parent.postMessage({source:\"" + syncMessageSource + "\",type:\"" + syncMessageType + "\",result:\"" + safe + "\"},window.location.origin);}catch(e){}" +
			"</script>"
	}
	body += "</head><body></body></html>"
	_, _ = w.Write([]byte(body))
}

// syncNonce mints one per-response CSP nonce.
func syncNonce() (string, error) {
	b := make([]byte, syncNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
