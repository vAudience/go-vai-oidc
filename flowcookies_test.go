package vaioidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cookieJar is the browser's view: one value per name, Set-Cookie applied in
// order, a negative Max-Age deleting.
type cookieJar map[string]string

func (j cookieJar) apply(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(j, c.Name)
			continue
		}
		j[c.Name] = c.Value
	}
}

func (j cookieJar) attach(r *http.Request) {
	for n, v := range j {
		r.AddCookie(&http.Cookie{Name: n, Value: v})
	}
}

func stateOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	return loc.Query().Get(queryParamState)
}

// TestLogin_TwoFlowsInterleavedBothSignIn is v0.37.0's reason to exist
// (atlas#1084): two tabs start a login, then both callbacks land. With one
// fixed cookie name per instance the second start overwrote the first and the
// first callback cleared the survivor — both failed. Revert-check: make
// flowSuffix return "" and both arms go red.
func TestLogin_TwoFlowsInterleavedBothSignIn(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)

	// The token endpoint checks that each code arrives with the verifier of
	// the flow that started it — PKCE is per flow, not per browser.
	var mu sync.Mutex
	verifierFor := map[string]string{}
	kc.token = func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		mu.Lock()
		want := verifierFor[r.PostForm.Get("code")]
		mu.Unlock()
		if want == "" || r.PostForm.Get("code_verifier") != want {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "a", "refresh_token": "r", "token_type": "Bearer", "expires_in": 300,
			"id_token": kc.idTokenFor(t, syncTestSubA, syncTestSidOne),
		})
	}

	jar := cookieJar{}
	start := func() (string, string) {
		r := httptest.NewRequest(http.MethodGet, testLoginPathForStepUp, nil)
		jar.attach(r)
		rec := httptest.NewRecorder()
		a.handleLogin(rec, r)
		require.Equal(t, http.StatusFound, rec.Code)
		jar.apply(rec)
		state := stateOf(t, rec)
		verifier := jar[cookiePKCEVerifier+flowSuffix(state)]
		return state, verifier
	}
	stateA, verA := start() // tab A
	stateB, verB := start() // tab B, before A's callback
	require.NotEqual(t, stateA, stateB)
	mu.Lock()
	verifierFor["code-a"], verifierFor["code-b"] = verA, verB
	mu.Unlock()

	callback := func(state, code string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, testCallback+"?state="+url.QueryEscape(state)+"&code="+code, nil)
		jar.attach(r)
		rec := httptest.NewRecorder()
		a.handleCallback(rec, r)
		jar.apply(rec)
		return rec
	}
	recA := callback(stateA, "code-a")
	assert.NotNil(t, sessionCookieFrom(recA, syncTestCookie), "tab A signs in")
	_, aLeft := jar[cookieOIDCState+flowSuffix(stateA)]
	assert.False(t, aLeft, "A's callback clears A's flow")
	_, bLeft := jar[cookieOIDCState+flowSuffix(stateB)]
	assert.True(t, bLeft, "A's callback leaves B's flow intact")

	recB := callback(stateB, "code-b")
	assert.NotNil(t, sessionCookieFrom(recB, syncTestCookie), "tab B signs in too")
}

// A forged state that names no flow of this browser finds no cookie: it is
// refused as a missing state, and nobody's flow is cleared.
func TestCallback_UnknownStateClearsNoOtherFlow(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)
	start := httptest.NewRecorder()
	a.handleLogin(start, httptest.NewRequest(http.MethodGet, testLoginPathForStepUp, nil))
	jar := cookieJar{}
	jar.apply(start)

	r := httptest.NewRequest(http.MethodGet, testCallback+"?state=forged&code=x", nil)
	jar.attach(r)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	assert.Nil(t, sessionCookieFrom(rec, syncTestCookie))
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, cookieOIDCState+flowSuffix(stateOf(t, start)), c.Name, "the pending flow is untouched")
	}
}

// A browser holding maxConcurrentFlows pending flows has them all cleared
// before a new one is set, so the Cookie header cannot grow without bound.
func TestLogin_ConcurrentFlowsAreCapped(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)
	jar := cookieJar{}
	var states []string
	for i := 0; i < maxConcurrentFlows+1; i++ {
		r := httptest.NewRequest(http.MethodGet, testLoginPathForStepUp, nil)
		jar.attach(r)
		rec := httptest.NewRecorder()
		a.handleLogin(rec, r)
		jar.apply(rec)
		states = append(states, stateOf(t, rec))
	}
	pending := 0
	for n := range jar {
		if len(n) > len(cookieOIDCState) && n[:len(cookieOIDCState)+1] == cookieOIDCState+flowSuffixSep {
			pending++
		}
	}
	assert.Equal(t, 1, pending, "the start past the cap cleared the older flows")
	_, newest := jar[cookieOIDCState+flowSuffix(states[len(states)-1])]
	assert.True(t, newest, "the newest flow survives")
	assert.LessOrEqual(t, pending, maxConcurrentFlows)
}
