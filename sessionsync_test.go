package vaioidc

// Behaviour tests for the v0.20.0 session-sync (identity reconciliation) path.
//
// ⚠️ THE WEIGHTING IS DELIBERATE AND MIRRORS revalidate_test.go's. This mechanism
// can sign every user of every product out at once, so most of these assert that
// a session SURVIVES something, not that it dies. The dangerous defect here is
// not "a switched identity lingers for one interval" — it is "a library upgrade,
// or one rotated client secret, logs the fleet out simultaneously".

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	syncTestCookie   = "vai_sync_test"
	syncTestTTL      = 2 * time.Hour
	syncTestSubA     = "user-sync-a"
	syncTestSubB     = "user-sync-b"
	syncTestSidOne   = "sid-one"
	syncTestSidTwo   = "sid-two"
	syncTokenPath    = "/protocol/openid-connect/token"
	syncTestState    = "state-sync-fixed"
	syncTestVerifier = "verifier-sync-fixed-0123456789abcdef"
)

// syncKeycloak is a controllable IdP: discovery + JWKS + a token endpoint whose
// response the test chooses per case.
type syncKeycloak struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string
	// token is the token-endpoint handler the current test wants.
	token func(w http.ResponseWriter, r *http.Request)
}

func newSyncKeycloak(t *testing.T) *syncKeycloak {
	t.Helper()
	kc := &syncKeycloak{}
	_, key := newTestKeycloak(t) // reuse only the RSA key generator's shape
	kc.key = key

	mux := http.NewServeMux()
	mux.HandleFunc(testIssuerPath+wellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		base := kc.issuer
		_, _ = fmt.Fprintf(w, validDiscoveryDocTemplate, base, base, base, base, base, base)
	})
	mux.HandleFunc(testIssuerPath+jwksRoutePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc(kc.key))
	})
	mux.HandleFunc(testIssuerPath+syncTokenPath, func(w http.ResponseWriter, r *http.Request) {
		if kc.token == nil {
			http.Error(w, "no token handler configured", http.StatusInternalServerError)
			return
		}
		kc.token(w, r)
	})

	kc.srv = httptest.NewServer(mux)
	t.Cleanup(kc.srv.Close)
	kc.issuer = kc.srv.URL + testIssuerPath
	return kc
}

// idTokenFor mints a verifiable ID token for sub/sid.
func (kc *syncKeycloak) idTokenFor(t *testing.T, sub, sid string) string {
	t.Helper()
	extra := map[string]any{}
	if sid != "" {
		extra[claimSid] = sid
	}
	return signRS256(t, kc.key, tokenHeader(),
		tokenPayload(kc.issuer, testClientID, sub, time.Now().Add(verifyTestTokenTTL), extra), false)
}

// respondWithIdentity makes the token endpoint answer a code exchange with an ID
// token for sub/sid.
func (kc *syncKeycloak) respondWithIdentity(t *testing.T, sub, sid string) {
	t.Helper()
	kc.token = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-from-sync",
			"refresh_token": "refresh-from-sync",
			"token_type":    "Bearer",
			"expires_in":    300,
			"id_token":      kc.idTokenFor(t, sub, sid),
		})
	}
}

func newSyncAuth(t *testing.T, kc *syncKeycloak, enabled bool) *Auth {
	t.Helper()
	a, err := New(context.Background(), Config{
		KeycloakURL:        kc.srv.URL,
		Realm:              testRealm,
		ClientID:           testClientID,
		ClientSecret:       "irrelevant",
		CallbackURL:        kc.srv.URL + testCallback,
		SessionSecret:      base64.StdEncoding.EncodeToString(bytes32()),
		CookieName:         syncTestCookie,
		SessionTTL:         syncTestTTL,
		SessionSyncEnabled: enabled,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		InsecureCookie:     true,
	})
	require.NoError(t, err)
	return a
}

// seedSession writes a session cookie for sub/sid onto a request.
func seedSession(t *testing.T, a *Auth, r *http.Request, sub, sid string) {
	t.Helper()
	payload := &sessionPayload{
		Sub:           sub,
		Sid:           sid,
		Exp:           time.Now().Add(syncTestTTL).Unix(),
		LastValidated: time.Now().Add(-time.Hour).Unix(),
	}
	rec := httptest.NewRecorder()
	require.NoError(t, setSessionCookie(rec, payload, a.sessionKey, a.cfg.CookieName, a.cfg.CookiePath, false, a.logger))
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
}

// syncCallbackRequest builds a callback request carrying the sync marker plus a
// seeded session, as the browser would present it.
func syncCallbackRequest(t *testing.T, a *Auth, query string, sub, sid string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, testCallback+"?"+query, nil)
	seedSession(t, a, r, sub, sid)
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: syncTestState})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: syncTestVerifier})
	r.AddCookie(&http.Cookie{Name: cookieOIDCSync, Value: cookieSyncMarkerValue})
	return r
}

// sessionCleared reports whether the response tells the browser to drop the
// session cookie. ⚠️ Checked by MaxAge, not by presence: every sync response
// clears the three short-lived OIDC cookies, so "a Set-Cookie was written" says
// nothing about the session.
func sessionCleared(t *testing.T, rec *httptest.ResponseRecorder, name string) bool {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func resultOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body := rec.Body.String()
	marker := syncResultDataAttr + `="`
	i := strings.Index(body, marker)
	require.GreaterOrEqual(t, i, 0, "the sync document must carry the result as a data attribute; body=%q", body)
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	require.GreaterOrEqual(t, j, 0)
	return rest[:j]
}

// --- the start endpoint -----------------------------------------------------

func TestSessionSync_DisabledAnswersDisabledRatherThan404(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)

	r := httptest.NewRequest(http.MethodGet, pathSessionSync, nil)
	seedSession(t, a, r, syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleSessionSync(rec, r)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, string(SessionSyncDisabled), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie),
		"a disabled feature must never touch a session")
}

func TestSessionSync_NoSessionMakesNoAuthorizationRequest(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	r := httptest.NewRequest(http.MethodGet, pathSessionSync, nil)
	rec := httptest.NewRecorder()
	a.handleSessionSync(rec, r)

	assert.Equal(t, http.StatusOK, rec.Code, "no session means nothing to reconcile, not a redirect")
	assert.Equal(t, string(SessionSyncNoSession), resultOf(t, rec))
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, cookieOIDCSync, c.Name, "no round trip was started, so no marker may be set")
	}
}

// TestSessionSync_StartRequestsPromptNone pins the parameter the whole design
// rests on. ⛔ Without prompt=none Keycloak renders its login page INTO A HIDDEN
// IFRAME: the reconciliation becomes an invisible dead end that reports nothing
// and the user sees no error anywhere.
func TestSessionSync_StartRequestsPromptNone(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	r := httptest.NewRequest(http.MethodGet, pathSessionSync, nil)
	seedSession(t, a, r, syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleSessionSync(rec, r)

	require.Equal(t, http.StatusFound, rec.Code)
	loc := rec.Header().Get("Location")
	assert.Contains(t, loc, queryParamPrompt+"="+promptNone)
	assert.Contains(t, loc, "code_challenge=", "the silent request must still use PKCE")
	assert.NotContains(t, loc, "kc_idp_hint",
		"an IdP hint can send a hidden frame to an external interactive login page")

	names := map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		names[c.Name] = true
	}
	assert.True(t, names[cookieOIDCSync], "the callback distinguishes the two round trips by this cookie alone")
	assert.True(t, names[cookieOIDCState])
	assert.True(t, names[cookiePKCEVerifier])
}

// --- the verdict ------------------------------------------------------------

func TestSyncCallback_LoginRequiredClearsTheSession(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	r := syncCallbackRequest(t, a, queryParamError+"="+oauthErrorLoginRequired, syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncSignedOut), resultOf(t, rec))
	assert.True(t, sessionCleared(t, rec, syncTestCookie))
}

// TestSyncCallback_NonVerdictErrorsKeepTheSession is the most important test in
// this file. ⛔ `invalid_client` is a ROTATED CLIENT SECRET: failing closed on it
// signs out every user of the service at the moment of a credential rotation,
// which reads as a security incident rather than as a config error.
func TestSyncCallback_NonVerdictErrorsKeepTheSession(t *testing.T) {
	for _, code := range []string{"invalid_client", "server_error", "temporarily_unavailable", "invalid_request"} {
		t.Run(code, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			a := newSyncAuth(t, kc, true)

			r := syncCallbackRequest(t, a, queryParamError+"="+code, syncTestSubA, syncTestSidOne)
			rec := httptest.NewRecorder()
			a.handleCallback(rec, r)

			assert.Equal(t, string(SessionSyncError), resultOf(t, rec))
			assert.False(t, sessionCleared(t, rec, syncTestCookie),
				"%s is the IdP failing to answer, not a verdict that the person left", code)
		})
	}
}

func TestSyncCallback_SameIdentityIsUnchangedAndSlides(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubA, syncTestSidOne)

	r := syncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncUnchanged), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie))

	// The round trip WAS an IdP interaction, so the anchor must have moved.
	replay := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		replay.AddCookie(c)
	}
	got, err := readSessionCookie(replay, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), got.LastValidated, 5,
		"a successful sync is an IdP interaction and must re-anchor the session")
}

func TestSyncCallback_DifferentSubjectClearsTheSession(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubB, syncTestSidTwo)

	r := syncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncSwitched), resultOf(t, rec))
	assert.True(t, sessionCleared(t, rec, syncTestCookie),
		"the operator's decision is CLEAR, never a silent re-mint as the new person")
}

// TestSyncCallback_SameSubjectNewSignInIsASwitch is the case `sub` alone cannot
// see: the same person signed out and back in, so every product still holding a
// cookie from the OLD sign-in holds a session the IdP no longer knows about.
func TestSyncCallback_SameSubjectNewSignInIsASwitch(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubA, syncTestSidTwo)

	r := syncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncSwitched), resultOf(t, rec))
	assert.True(t, sessionCleared(t, rec, syncTestCookie))
}

// TestSyncCallback_PreV020SessionIsNotASwitch guards the single worst failure
// this file could have. ⛔ Every session minted before v0.20.0 carries an empty
// Sid; if an absent Sid counted as a mismatch, the FIRST sync after a consumer
// upgrade would sign out every logged-in user at once — a library bump
// presenting as a fleet-wide logout.
func TestSyncCallback_PreV020SessionIsNotASwitch(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubA, syncTestSidOne)

	r := syncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, "")
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncUnchanged), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie))

	replay := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		replay.AddCookie(c)
	}
	got, err := readSessionCookie(replay, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err)
	assert.Equal(t, syncTestSidOne, got.Sid,
		"the session must self-heal its Sid so the NEXT sync can compare on the sign-in")
}

func TestSyncCallback_StateMismatchFailsOpen(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubB, syncTestSidTwo)

	r := syncCallbackRequest(t, a,
		queryParamState+"=not-the-stored-state&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncError), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie),
		"a forged or stale callback must never be able to sign somebody out")
}

func TestSyncCallback_TokenExchangeFailureFailsOpen(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.token = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream is unwell", http.StatusBadGateway)
	}

	r := syncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncError), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie))
}

// --- the document -----------------------------------------------------------

// TestSyncResultDocument_ReportsTwice pins the belt-and-braces reporting. The
// postMessage needs an inline script and therefore a CSP that permits it; a
// consumer whose middleware overwrites Content-Security-Policy strips that
// SILENTLY, because a CSP violation is reported to a browser console and nowhere
// else. The data attribute needs no script and survives it.
func TestSyncResultDocument_ReportsTwice(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	rec := httptest.NewRecorder()
	a.writeSyncResult(rec, SessionSyncSwitched)

	body := rec.Body.String()
	assert.Equal(t, string(SessionSyncSwitched), resultOf(t, rec))
	assert.Contains(t, body, "postMessage")
	assert.Contains(t, body, "window.location.origin",
		`the target origin must be derived, never "*" — a wildcard would broadcast the verdict`)
	assert.Contains(t, body, syncMessageSource)

	csp := rec.Header().Get(headerCSP)
	require.NotEmpty(t, csp, "the document must carry its own policy, not inherit the consumer's")
	assert.Contains(t, csp, "nonce-")
	assert.Contains(t, csp, "frame-ancestors 'self'")
	assert.Equal(t, cacheControlNoStore, rec.Header().Get(headerCacheControl),
		"a cached verdict is a stale answer to the only question this endpoint is asked")

	// The nonce in the header must be the one the script carries, or the browser
	// refuses the script and the postMessage never fires — silently.
	nonce := csp[strings.Index(csp, "nonce-")+len("nonce-"):]
	nonce = nonce[:strings.Index(nonce, "'")]
	assert.Contains(t, body, `nonce="`+nonce+`"`)
}

func TestSyncResultDocument_NonceIsPerResponse(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	first := httptest.NewRecorder()
	second := httptest.NewRecorder()
	a.writeSyncResult(first, SessionSyncUnchanged)
	a.writeSyncResult(second, SessionSyncUnchanged)

	assert.NotEqual(t, first.Header().Get(headerCSP), second.Header().Get(headerCSP),
		"a reused nonce is not a nonce")
}

// --- the login path must be untouched ---------------------------------------

// TestCallback_WithoutTheSyncMarkerTakesTheLoginPath is the regression guard for
// the dispatcher. ⛔ The two round trips share one URL because every realm client
// in this fleet registers an EXACT redirect URI; if the marker were ever read
// the wrong way round, a real login would render a sync document instead of
// minting a session — and the user would see a blank page at HTTP 200.
func TestCallback_WithoutTheSyncMarkerTakesTheLoginPath(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	r := httptest.NewRequest(http.MethodGet, testCallback+"?"+queryParamError+"="+oauthErrorLoginRequired, nil)
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: syncTestState})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: syncTestVerifier})
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, http.StatusFound, rec.Code,
		"a login callback redirects; only the sync path renders a document")
	assert.NotContains(t, rec.Body.String(), syncResultDataAttr)
}
