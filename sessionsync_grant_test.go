package vaioidc

// Guards for v0.22.0: session sync and sessions minted by IssueSession.
//
// ⛔ THE DEFECT: IssueSession mints from a SERVER-SIDE grant (ROPC / inline
// login), so the browser holds no provider SSO cookie by construction. With
// SessionSyncEnabled, `prompt=none` therefore answered `login_required`, sync
// read that as `signed_out`, and cleared every inline-login session on its first
// focus tick. These tests pin the fix AND its limits: a redirect-login session
// must still be signed out by the same answer, and a grant-minted session must
// still be cleared by a browser signed in as somebody else.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedGrantSession mints the session through the REAL IssueSession, so the test
// fails if IssueSession ever stops marking what it mints.
func seedGrantSession(t *testing.T, a *Auth, r *http.Request, sub, sid string) {
	t.Helper()
	rec := httptest.NewRecorder()
	require.NoError(t, a.IssueSession(rec, httptest.NewRequest(http.MethodPost, "/login", nil),
		&User{Sub: sub, SessionID: sid}, ""))
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
}

func grantSyncCallbackRequest(t *testing.T, a *Auth, query, sub, sid string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, testCallback+"?"+query, nil)
	seedGrantSession(t, a, r, sub, sid)
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: syncTestState})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: syncTestVerifier})
	r.AddCookie(&http.Cookie{Name: cookieOIDCSync, Value: cookieSyncMarkerValue})
	return r
}

func replaySession(t *testing.T, a *Auth, rec *httptest.ResponseRecorder) *sessionPayload {
	t.Helper()
	replay := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		replay.AddCookie(c)
	}
	got, err := readSessionCookie(replay, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err)
	return got
}

func TestIssueSession_MarksTheSessionAsGrantMinted(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	seedGrantSession(t, a, r, syncTestSubA, syncTestSidOne)

	got, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err)
	assert.Equal(t, sessionSourceGrant, got.Src)
	assert.True(t, got.isGrantMinted())
}

// TestSyncCallback_GrantSessionWithoutBrowserSessionIsNotApplicable is the
// decisive test of v0.22.0. Its pair is TestSyncCallback_LoginRequiredClearsTheSession:
// the SAME IdP answer must still sign out a redirect-login session.
func TestSyncCallback_GrantSessionWithoutBrowserSessionIsNotApplicable(t *testing.T) {
	for _, code := range []string{
		oauthErrorLoginRequired,
		oauthErrorInteractionRequired,
		oauthErrorConsentRequired,
		oauthErrorAccountSelectionRequired,
	} {
		t.Run(code, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			a := newSyncAuth(t, kc, true)

			r := grantSyncCallbackRequest(t, a, queryParamError+"="+code, syncTestSubA, syncTestSidOne)
			rec := httptest.NewRecorder()
			a.handleCallback(rec, r)

			assert.Equal(t, string(SessionSyncNotApplicable), resultOf(t, rec))
			assert.False(t, sessionCleared(t, rec, syncTestCookie),
				"an inline-login browser never had a provider session to lose; %s is not a verdict about it", code)
		})
	}
}

// A grant-minted session must still fail open on a non-verdict, exactly as
// every other session does — the new branch must not swallow errors into
// not_applicable (which a consumer might one day act on differently).
func TestSyncCallback_GrantSessionNonVerdictIsStillError(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	r := grantSyncCallbackRequest(t, a, queryParamError+"=invalid_client", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncError), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie))
}

// ⛔ The limit of the fix: a browser signed in to the provider as SOMEBODY ELSE
// is real evidence that a different person is at this browser, whatever minted
// this product's session.
func TestSyncCallback_GrantSessionBrowserSignedInAsSomeoneElseIsASwitch(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubB, syncTestSidTwo)

	r := grantSyncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncSwitched), resultOf(t, rec))
	assert.True(t, sessionCleared(t, rec, syncTestCookie))
}

// ⛔ The grant's sid names a server-side session the browser never joined, so it
// can NEVER equal the browser's. Comparing it would turn the same person's own
// SSO sign-in into a `switched` and clear the session — the original defect in a
// different costume. And the session must not be re-bound to the browser's
// sign-in: no sid adoption, no token adoption, and it stays grant-minted.
func TestSyncCallback_GrantSessionSamePersonIsUnchangedAndNotRebound(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	a.cfg.RetainTokens = true
	kc.respondWithIdentity(t, syncTestSubA, syncTestSidTwo)

	r := grantSyncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, syncTestSidOne)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncUnchanged), resultOf(t, rec))
	assert.False(t, sessionCleared(t, rec, syncTestCookie))

	got := replaySession(t, a, rec)
	assert.Equal(t, syncTestSidOne, got.Sid, "a grant session must not adopt the browser's sid")
	assert.Empty(t, got.RefreshToken, "a grant session must not adopt the browser's refresh token")
	assert.Empty(t, got.AccessToken)
	assert.Equal(t, sessionSourceGrant, got.Src, "a re-stamp must not launder the session into a redirect one")
	assert.InDelta(t, time.Now().Unix(), got.LastValidated, 5)
}

// A grant session minted without a sid must not pick up the browser's either:
// the NEXT sync would then compare sids and call a same-person re-sign-in a switch.
func TestSyncCallback_SidlessGrantSessionDoesNotSelfHealFromTheBrowser(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)
	kc.respondWithIdentity(t, syncTestSubA, syncTestSidTwo)

	r := grantSyncCallbackRequest(t, a,
		queryParamState+"="+syncTestState+"&"+queryParamCode+"=abc", syncTestSubA, "")
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)

	assert.Equal(t, string(SessionSyncUnchanged), resultOf(t, rec))
	assert.Empty(t, replaySession(t, a, rec).Sid)
}

// encryptRawSession encrypts an arbitrary JSON document exactly as
// encryptSession would — so a cookie written by a PRE-v0.22.0 build (whose JSON
// has no "src" key at all) can be reproduced byte-for-byte in shape.
func encryptRawSession(t *testing.T, plaintext, key []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil))
}

// ⛔ The upgrade path. Every cookie alive at the moment a consumer bumps the pin
// was written without the field; it must decode, and behave exactly as it did —
// including being signed out by `login_required`, because a pre-v0.22.0 cookie
// cannot be told apart and was minted by the redirect flow in the common case.
func TestSyncCallback_PreV022CookieWithoutSrcBehavesAsBefore(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, true)

	raw, err := json.Marshal(map[string]any{
		"sub": syncTestSubA, "email": "", "name": "", "sid": syncTestSidOne,
		"idt": "", "exp": time.Now().Add(syncTestTTL).Unix(),
	})
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"src"`)

	r := httptest.NewRequest(http.MethodGet, testCallback+"?"+queryParamError+"="+oauthErrorLoginRequired, nil)
	r.AddCookie(&http.Cookie{Name: a.cfg.CookieName, Value: encryptRawSession(t, raw, a.sessionKey)})
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: syncTestState})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: syncTestVerifier})
	r.AddCookie(&http.Cookie{Name: cookieOIDCSync, Value: cookieSyncMarkerValue})

	got, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName)
	require.NoError(t, err, "a pre-v0.22.0 cookie must still decode")
	assert.False(t, got.isGrantMinted())

	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	assert.Equal(t, string(SessionSyncSignedOut), resultOf(t, rec))
	assert.True(t, sessionCleared(t, rec, syncTestCookie))
}

// A redirect-login session's wire shape must not change: the field is omitempty,
// so no "src" key is written for it and the cookie is what a pre-v0.22.0 build
// wrote.
func TestSessionPayload_SrcIsAbsentOnTheWireForRedirectSessions(t *testing.T) {
	raw, err := json.Marshal(&sessionPayload{Sub: syncTestSubA, Exp: 1})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"src"`)

	raw, err = json.Marshal(&sessionPayload{Sub: syncTestSubA, Exp: 1, Src: sessionSourceGrant})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"src":"grant"`)
}

// TestSessionSyncScript_NotApplicableNeverReloads guards the browser half.
//
// ⛔ A reload on `not_applicable` would flash every inline-login page on every
// focus; a stop() would make the later `switched` verdict unreachable for the
// life of the page. The branch must sit BEFORE the reload branch inside act()
// and do nothing but return.
func TestSessionSyncScript_NotApplicableNeverReloads(t *testing.T) {
	src := sessionSyncScriptSource
	start := strings.Index(src, "function act(result) {")
	end := strings.Index(src, "function sync() {")
	require.Positive(t, start)
	require.Greater(t, end, start)
	act := src[start:end]

	branch := `if (result === "` + string(SessionSyncNotApplicable) + `") {`
	i := strings.Index(act, branch)
	require.GreaterOrEqual(t, i, 0, "act() must handle the %q verdict explicitly", SessionSyncNotApplicable)
	reload := strings.Index(act, "window.location.reload()")
	require.GreaterOrEqual(t, reload, 0)
	assert.Less(t, i, reload, "the not_applicable branch must be decided before the reload branch")

	body := act[i+len(branch):]
	body = body[:strings.Index(body, "}")]
	assert.Equal(t, "return;", strings.TrimSpace(body),
		"the not_applicable branch must return and do nothing else — no reload, no stop()")
}
