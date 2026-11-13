package vaioidc

// v0.38.0: Keycloak application-initiated actions (kc_action=UPDATE_PASSWORD).

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pwTestReturn = "/app/settings/account"

func TestLogin_KCAction(t *testing.T) {
	for name, tc := range map[string]struct {
		query      string
		wantStatus int
		wantAction string // "" = not forwarded
	}{
		"absent: not forwarded":              {"", http.StatusFound, ""},
		"empty value reads as absent":        {"kc_action=", http.StatusFound, ""},
		"UPDATE_PASSWORD forwarded":          {"kc_action=UPDATE_PASSWORD", http.StatusFound, KCActionUpdatePassword},
		"alongside redirect and max_age":     {"kc_action=UPDATE_PASSWORD&redirect=/app/x&max_age=0", http.StatusFound, KCActionUpdatePassword},
		"lower case refused":                 {"kc_action=update_password", http.StatusBadRequest, ""},
		"another action refused":             {"kc_action=delete_account", http.StatusBadRequest, ""},
		"CONFIGURE_TOTP refused":             {"kc_action=CONFIGURE_TOTP", http.StatusBadRequest, ""},
		"padded value refused":               {"kc_action=UPDATE_PASSWORD%20", http.StatusBadRequest, ""},
		"injection attempt refused":          {"kc_action=UPDATE_PASSWORD%26prompt%3Dnone", http.StatusBadRequest, ""},
		"refused even beside a good max_age": {"kc_action=x&max_age=0", http.StatusBadRequest, ""},
	} {
		t.Run(name, func(t *testing.T) {
			kc := newSyncKeycloak(t)
			a := newSyncAuth(t, kc, false)
			rec := startLogin(t, a, tc.query)
			require.Equal(t, tc.wantStatus, rec.Code)

			if tc.wantStatus == http.StatusBadRequest {
				assert.Empty(t, rec.Header().Get("Location"), "an unsupported kc_action must not start a login")
				assert.Empty(t, rec.Result().Cookies(), "no state may be minted for a refused login")
				assert.Contains(t, rec.Body.String(), errBodyInvalidKCAction)
				return
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			marker := flowCookieOf(t, rec, cookieOIDCKCAction)
			if tc.wantAction == "" {
				assert.False(t, loc.Query().Has(queryParamKCAction))
				assert.Nil(t, marker, "an ordinary login writes no kc_action marker")
				return
			}
			assert.Equal(t, tc.wantAction, loc.Query().Get(queryParamKCAction))
			require.NotNil(t, marker, "a kc_action login marks its flow")
			assert.Equal(t, tc.wantAction, marker.Value)
		})
	}
}

// kcActionRoundTrip starts a login with startQuery, then lands the callback
// with callbackQuery (state is added) and a token endpoint answering for
// syncTestSubA. Returns the callback's response and how many code exchanges ran.
func kcActionRoundTrip(t *testing.T, startQuery, callbackQuery string) (*httptest.ResponseRecorder, *int) {
	t.Helper()
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)
	exchanges := 0
	kc.respondWithIdentity(t, syncTestSubA, syncTestSidOne)
	inner := kc.token
	kc.token = func(w http.ResponseWriter, r *http.Request) { exchanges++; inner(w, r) }

	jar := cookieJar{}
	start := startLogin(t, a, startQuery)
	require.Equal(t, http.StatusFound, start.Code)
	jar.apply(start)

	target := testCallback + "?state=" + url.QueryEscape(stateOf(t, start))
	if callbackQuery != "" {
		target += "&" + callbackQuery
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	jar.attach(r)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	return rec, &exchanges
}

func TestCallback_KCActionStatus(t *testing.T) {
	kcStart := "kc_action=UPDATE_PASSWORD&redirect=" + url.QueryEscape(pwTestReturn)
	plainStart := "redirect=" + url.QueryEscape(pwTestReturn)
	for name, tc := range map[string]struct {
		start, callback string
		wantSession     bool
		wantLocation    string
	}{
		"success with a code: signed in, status appended": {
			kcStart, "code=c&kc_action_status=success", true, pwTestReturn + "?kc_action_status=success"},
		"cancelled with a code (Keycloak 21+): signed in, status appended": {
			kcStart, "code=c&kc_action=UPDATE_PASSWORD&kc_action_status=cancelled", true, pwTestReturn + "?kc_action_status=cancelled"},
		"error with a code: signed in, status appended": {
			kcStart, "code=c&kc_action_status=error", true, pwTestReturn + "?kc_action_status=error"},
		"unknown status is never echoed": {
			kcStart, "code=c&kc_action_status=%3Cscript%3E", true, pwTestReturn},
		"status in a different case is not recognised": {
			kcStart, "code=c&kc_action_status=SUCCESS", true, pwTestReturn},
		"code without any status: plain landing": {
			kcStart, "code=c", true, pwTestReturn},
		"a non-kc_action flow ignores the status": {
			plainStart, "code=c&kc_action_status=success", true, pwTestReturn},
		"a non-kc_action flow without a code still fails to LogoutRedirect": {
			plainStart, "error=access_denied&kc_action_status=cancelled", false, "/"},
	} {
		t.Run(name, func(t *testing.T) {
			rec, exchanges := kcActionRoundTrip(t, tc.start, tc.callback)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, tc.wantLocation, rec.Header().Get("Location"))
			if tc.wantSession {
				assert.NotNil(t, sessionCookieFrom(rec, syncTestCookie), "a code is an ordinary login")
				assert.Equal(t, 1, *exchanges)
			} else {
				assert.Nil(t, sessionCookieFrom(rec, syncTestCookie))
			}
		})
	}
}

// Keycloak answers a FAILED required action (and, before 21, a cancelled AIA)
// with no code. A kc_action flow returns to its target with a status, mints
// nothing, clears no session, and never visits LogoutRedirect.
func TestCallback_KCActionWithoutCode(t *testing.T) {
	kcStart := "kc_action=UPDATE_PASSWORD&redirect=" + url.QueryEscape(pwTestReturn)
	for name, tc := range map[string]struct {
		callback   string
		wantStatus string
	}{
		"access_denied (cancel/refused)":           {"error=access_denied&error_description=User+cancelled", KCActionStatusCancelled},
		"no error, no code (CANCELLED_AIA_SILENT)": {"", KCActionStatusCancelled},
		"another OAuth error":                      {"error=server_error", KCActionStatusError},
		"Keycloak's own status wins":               {"error=access_denied&kc_action_status=error", KCActionStatusError},
		"unknown status falls back to the error":   {"error=access_denied&kc_action_status=evil", KCActionStatusCancelled},
	} {
		t.Run(name, func(t *testing.T) {
			rec, exchanges := kcActionRoundTrip(t, kcStart, tc.callback)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, pwTestReturn+"?kc_action_status="+tc.wantStatus, rec.Header().Get("Location"))
			assert.Zero(t, *exchanges, "nothing to exchange")
			for _, c := range rec.Result().Cookies() {
				assert.NotEqual(t, syncTestCookie, c.Name, "the existing session is neither minted nor cleared")
			}
		})
	}
}

// A code-less kc_action callback still has to name its own flow's state.
func TestCallback_KCActionWithoutCode_StateMismatchRefused(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)
	jar := cookieJar{}
	start := startLogin(t, a, "kc_action=UPDATE_PASSWORD&redirect="+url.QueryEscape(pwTestReturn))
	jar.apply(start)
	state := stateOf(t, start)

	// A request naming the flow's cookie suffix but carrying a different state
	// cannot exist (the suffix is derived from it), so plant the flow's cookies
	// under the legacy fixed names and send a mismatching state.
	r := httptest.NewRequest(http.MethodGet, testCallback+"?state=forged&error=access_denied", nil)
	r.AddCookie(&http.Cookie{Name: cookieOIDCState, Value: jar[cookieOIDCState+flowSuffix(state)]})
	r.AddCookie(&http.Cookie{Name: cookiePKCEVerifier, Value: "v"})
	r.AddCookie(&http.Cookie{Name: cookieOIDCKCAction, Value: KCActionUpdatePassword})
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	assert.Equal(t, "/", rec.Header().Get("Location"), "a mismatching state is refused")
}

func TestCallback_KCActionDuplicateMarkerRefused(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)
	jar := cookieJar{}
	start := startLogin(t, a, "kc_action=UPDATE_PASSWORD&redirect="+url.QueryEscape(pwTestReturn))
	jar.apply(start)
	state := stateOf(t, start)

	r := httptest.NewRequest(http.MethodGet, testCallback+"?state="+url.QueryEscape(state)+"&error=access_denied", nil)
	jar.attach(r)
	r.AddCookie(&http.Cookie{Name: cookieOIDCKCAction + flowSuffix(state), Value: KCActionUpdatePassword})
	rec := httptest.NewRecorder()
	a.handleCallback(rec, r)
	assert.Equal(t, "/", rec.Header().Get("Location"), "a tossed duplicate marker is refused")
}

func TestPasswordActionURL(t *testing.T) {
	kc := newSyncKeycloak(t)
	a := newSyncAuth(t, kc, false)

	for name, tc := range map[string]struct {
		returnTo string
		wantErr  bool
		wantRed  string
	}{
		"same-origin path":        {"/app/settings", false, "/app/settings"},
		"path with query":         {"/app/settings?tab=account", false, "/app/settings?tab=account"},
		"empty: no redirect":      {"", false, ""},
		"absolute URL refused":    {"https://evil.example/x", true, ""},
		"protocol-relative":       {"//evil.example/x", true, ""},
		"backslash trick":         {"/\\evil.example", true, ""},
		"relative without slash":  {"app/settings", true, ""},
		"control character":       {"/\t/evil.example", true, ""},
		"javascript scheme":       {"javascript:alert(1)", true, ""},
		"embedded scheme no path": {"http://evil.example", true, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := a.PasswordActionURL(tc.returnTo)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidReturnPath)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			u, perr := url.Parse(got)
			require.NoError(t, perr)
			assert.Equal(t, a.cfg.LoginPath, u.Path)
			assert.Equal(t, KCActionUpdatePassword, u.Query().Get(queryParamKCAction))
			assert.Equal(t, tc.wantRed, u.Query().Get(queryParamRedirect))

			// And the URL drives the real login into a kc_action flow.
			rec := startLogin(t, a, u.RawQuery)
			require.Equal(t, http.StatusFound, rec.Code)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			assert.Equal(t, KCActionUpdatePassword, loc.Query().Get(queryParamKCAction))
		})
	}
}
