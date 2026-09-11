package vaioidc

// Guards for the library-owned browser half (v0.21.0).
//
// ⚠️ THE WHOLE POINT OF THESE IS THAT THE THING THEY GUARD CANNOT REPORT ON
// ITSELF. Every failure of the served script is a browser-side failure: a 404
// loaded by a <script> tag, an unreplaced token, an endpoint pointing at a mount
// nobody uses. None of those reaches a server log, which is why the file is
// asserted THROUGH A REAL chi MOUNT at a prefix that is not "/auth" — a body
// containing a hardcoded "/auth" passes any test mounted at "/auth".

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptTestMount is deliberately NOT "/auth". The defect this guards against is
// a path transcribed rather than derived, and "/auth" is the value a
// transcription would have used.
const scriptTestMount = "/deliberately-not-auth"

func newScriptAuth(t *testing.T) *Auth {
	t.Helper()
	kc := newSyncKeycloak(t)
	a, err := New(context.Background(), Config{
		KeycloakURL:        kc.srv.URL,
		Realm:              testRealm,
		ClientID:           testClientID,
		ClientSecret:       "irrelevant",
		CallbackURL:        kc.srv.URL + testCallback,
		SessionSecret:      base64.StdEncoding.EncodeToString(bytes32()),
		CookieName:         syncTestCookie,
		SessionTTL:         syncTestTTL,
		SessionSyncEnabled: true,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		InsecureCookie:     true,
	})
	require.NoError(t, err)
	return a
}

func mountScript(t *testing.T, a *Auth) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Mount(scriptTestMount, a.Routes())
	return r
}

// TestSessionSyncScript_EndpointsAreDerivedFromTheMount is the load-bearing one.
//
// ⛔ It fails if the endpoints are hardcoded, if the mount is read from config
// instead of the request, or if the replacer stops running — three independent
// ways to ship a script that loads, runs, and reconciles nothing.
func TestSessionSyncScript_EndpointsAreDerivedFromTheMount(t *testing.T) {
	a := newScriptAuth(t)
	rec := httptest.NewRecorder()
	mountScript(t, a).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, scriptTestMount+pathSessionSyncScript, nil))

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `"`+scriptTestMount+pathSessionSync+`"`,
		"the sync endpoint must be the mount this router was actually mounted at")
	assert.Contains(t, body, `"`+scriptTestMount+pathSessionSyncBlocked+`"`,
		"the blocked-report endpoint must be derived from the same mount")

	// ⛔ A body still carrying a token is a script whose endpoints were never
	// filled in — a browser syntax error, reported in a console and nowhere else.
	assert.NotContains(t, body, scriptTokenSyncEndpoint)
	assert.NotContains(t, body, scriptTokenBlockedEndpoint)

	assert.Equal(t, contentTypeJavaScript, rec.Header().Get(headerContentType))
	assert.Equal(t, cacheControlNoStore, rec.Header().Get(headerCacheControl))
	assert.Equal(t, contentTypeOptionsNoSniff, rec.Header().Get(headerXContentTypeOptions))
}

// TestSessionSyncScript_ShippedAssetCarriesBothTokens asserts on the EMBEDDED
// FILE, not on a fixture.
//
// ⛔ WITHOUT THIS, EVERY OTHER TEST HERE IS VACUOUS IN ONE DIRECTION. Rename a
// token in constants.go and the replacer becomes a no-op; the served body then
// contains neither token (so the NotContains assertions above still pass) and no
// endpoint either. This is the test that notices.
func TestSessionSyncScript_ShippedAssetCarriesBothTokens(t *testing.T) {
	assert.Contains(t, sessionSyncScriptSource, scriptTokenSyncEndpoint,
		"the shipped script must contain the token the handler replaces")
	assert.Contains(t, sessionSyncScriptSource, scriptTokenBlockedEndpoint)
	// The script is useless if it never mounts a frame or never listens for the
	// verdict; these are the two halves of the mechanism.
	assert.Contains(t, sessionSyncScriptSource, "frame.src = ENDPOINT")
	assert.Contains(t, sessionSyncScriptSource, `d.source !== "vaioidc"`)
}

// TestSessionSyncScript_VerdictVocabularyMatchesTheServer.
//
// ⛔ THE SCRIPT AND THE SERVER AGREE ON A VOCABULARY THAT NOTHING ELSE COMPARES.
// Adding a verdict the script does not act on is a silent no-op in a browser;
// renaming one the script DOES act on turns a sign-out into nothing happening.
// Both sides are now read from the same constants.
func TestSessionSyncScript_VerdictVocabularyMatchesTheServer(t *testing.T) {
	for _, v := range []SessionSyncResult{SessionSyncSwitched, SessionSyncSignedOut, SessionSyncDisabled} {
		assert.Contains(t, sessionSyncScriptSource, `"`+string(v)+`"`,
			"the client script must act on the %q verdict the server can emit", v)
	}
}

func TestMountFromScriptPath(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		mount string
		ok    bool
	}{
		{"ordinary mount", "/auth" + pathSessionSyncScript, "/auth", true},
		{"nested mount", "/api/v1/auth" + pathSessionSyncScript, "/api/v1/auth", true},
		// ⛔ Root is legitimate and its mount is EMPTY, which is why the bool is
		// separate from the string. Collapsing them into an emptiness check turns
		// a root mount into a 500.
		{"root mount", pathSessionSyncScript, "", true},
		{"wrong suffix", "/auth/session/sync", "", false},
		{"quote in prefix", `/a"uth` + pathSessionSyncScript, "", false},
		{"angle bracket in prefix", "/a<uth" + pathSessionSyncScript, "", false},
		{"newline in prefix", "/a\nuth" + pathSessionSyncScript, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mount, ok := mountFromScriptPath(c.path)
			assert.Equal(t, c.ok, ok)
			assert.Equal(t, c.mount, mount)
		})
	}
}

func TestJSStringLiteral_EscapesEveryBreakout(t *testing.T) {
	// ⚠️ Asserted as an EXACT rendering, not as "the raw character is absent":
	// the escape for a backslash contains a backslash, so an absence check
	// reports a false failure there and would have been "fixed" by dropping the
	// one case that matters most.
	cases := map[string]string{
		`"`:      `"/a\u0022b"`,
		`\`:      `"/a\u005Cb"`,
		"<":      `"/a\u003Cb"`,
		">":      `"/a\u003Eb"`,
		"&":      `"/a\u0026b"`,
		"\n":     `"/a\u000Ab"`,
		"\r":     `"/a\u000Db"`,
		"\u2028": `"/a\u2028b"`,
		"\u2029": `"/a\u2029b"`,
	}
	for in, want := range cases {
		assert.Equal(t, want, jsStringLiteral("/a"+in+"b"), "input %q", in)
	}
	assert.Equal(t, `"/auth/session/sync"`, jsStringLiteral("/auth/session/sync"))
}

// TestSessionSyncBlocked_RequiresASessionToLog.
//
// ⛔ An unauthenticated POST that writes a WARN line is a log-flooding primitive
// any page on the internet can aim at this origin. ⚠️ And the status code must
// NOT discriminate: a 401 here tells an unauthenticated caller whether a cookie
// it holds is valid.
func TestSessionSyncBlocked_RequiresASessionToLog(t *testing.T) {
	a := newScriptAuth(t)
	h := mountScript(t, a)

	var logged strings.Builder
	a.logger = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))

	anon := httptest.NewRecorder()
	h.ServeHTTP(anon, httptest.NewRequest(http.MethodPost, scriptTestMount+pathSessionSyncBlocked, nil))
	assert.Equal(t, http.StatusNoContent, anon.Code)
	assert.NotContains(t, logged.String(), logMsgSyncBlocked,
		"an anonymous caller must not be able to write a log line")

	signed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, scriptTestMount+pathSessionSyncBlocked, nil)
	seedSession(t, a, req, syncTestSubA, syncTestSidOne)
	h.ServeHTTP(signed, req)
	assert.Equal(t, http.StatusNoContent, signed.Code,
		"the status must not discriminate between a session and no session")
	assert.Contains(t, logged.String(), logMsgSyncBlocked,
		"a signed-in browser that reached no verdict is the one thing this endpoint exists to report")
}

// TestSessionSyncScriptRoutes_AreSkippedByCharon.
//
// ⛔ THE RECORDED LESSON, RE-APPLIED: an auth route charonmw does not skip is an
// auth route nobody can reach, and the symptom is indistinguishable from the
// feature simply not working.
func TestSessionSyncScriptRoutes_AreSkippedByCharon(t *testing.T) {
	a := newScriptAuth(t)
	skip := a.SkipPaths()
	assert.Contains(t, skip, pathSessionSyncScript)
	assert.Contains(t, skip, pathSessionSyncBlocked)

	prefixed := a.SkipPathsWithPrefix(scriptTestMount)
	assert.Contains(t, prefixed, scriptTestMount+pathSessionSyncScript)
	assert.Contains(t, prefixed, scriptTestMount+pathSessionSyncBlocked)
}

// TestSessionSyncScriptSuffix_IsTheRouteItself keeps the exported constant and
// the registered route from drifting apart — a consumer composing its <script>
// tag from the export would otherwise point at a 404.
func TestSessionSyncScriptSuffix_IsTheRouteItself(t *testing.T) {
	assert.Equal(t, pathSessionSyncScript, SessionSyncScriptSuffix)
}
