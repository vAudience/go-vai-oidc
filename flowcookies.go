package vaioidc

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// Per-flow cookie names (v0.37.0).
//
// ⛔ ONE FIXED NAME PER INSTANCE MEANT ONE LOGIN IN FLIGHT PER BROWSER. Before
// v0.37.0 the state, PKCE verifier, max_age marker and sync marker were written
// under fixed names, so two tabs starting a login at once overwrote each other's
// cookies, and the first callback to land then cleared the survivor: BOTH
// failed. atlas#1084 (a signed-out visit redirects straight to the login) made
// that the ordinary case — a browser restoring two expired tabs starts two
// flows. Each flow's cookies now carry a suffix derived from its OWN `state`,
// and the callback reads (and clears) only the cookies its `state` names.
//
// ⚠ The suffix is a truncated SHA-256 of the state, never the state itself: a
// cookie name is not secret, the state is a CSRF value, and the callback still
// compares the full state in constant time against the cookie's VALUE.
//
// ⚠ A flow started by a pre-v0.37.0 instance (a rolling deploy) wrote the fixed
// names; the callback falls back to them when no per-flow cookie matches, so a
// login in flight across the upgrade still completes.

const (
	// flowSuffixBytes is how much of the state's SHA-256 names a flow: 48 bits,
	// so two concurrent flows in one browser never collide in practice.
	flowSuffixBytes = 6
	// maxConcurrentFlows bounds how many login/sync flows one browser may hold
	// cookies for. A new flow beyond it clears the older ones first: a browser
	// cannot grow its Cookie header without bound by opening /auth/login in a
	// loop, and five minutes (oidcCookieMaxAge) retires them anyway.
	maxConcurrentFlows = 4
	flowSuffixSep      = "_"
)

// flowSuffix names the cookies of the flow whose OAuth `state` is state.
func flowSuffix(state string) string {
	sum := sha256.Sum256([]byte(state))
	return flowSuffixSep + hex.EncodeToString(sum[:flowSuffixBytes])
}

// flowCookie is the name the flow cookie base is written under for the flow
// with suffix flow ("" = the fixed pre-v0.37.0 name).
func (c *Config) flowCookie(base, flow string) string {
	return c.flowCookieName(base) + flow
}

// callbackFlow resolves which flow a callback belongs to: the per-flow suffix
// its `state` names when that flow's state cookie is present, else "" (a
// pre-v0.37.0 flow, or no flow at all — the fixed-name reads then answer).
func (a *Auth) callbackFlow(r *http.Request) string {
	state := r.URL.Query().Get(queryParamState)
	if state == "" {
		return ""
	}
	flow := flowSuffix(state)
	if len(r.CookiesNamed(a.cfg.flowCookie(cookieOIDCState, flow))) > 0 {
		return flow
	}
	return ""
}

// clearFlowCookies removes every cookie of one flow.
func (a *Auth) clearFlowCookies(w http.ResponseWriter, flow string) {
	for _, base := range []string{cookieOIDCState, cookiePKCEVerifier, cookieOIDCMaxAge, cookieOIDCSync} {
		clearOIDCCookie(w, a.cfg.flowCookie(base, flow), a.cfg.CookiePath, a.cfg.secureCookie())
	}
}

// makeRoomForFlow enforces maxConcurrentFlows before a new flow's cookies are
// set: when the browser already holds that many per-flow state cookies, every
// one of those flows is cleared (the newest request is the one the person is
// waiting on).
func (a *Auth) makeRoomForFlow(w http.ResponseWriter, r *http.Request) {
	prefix := a.cfg.flowCookieName(cookieOIDCState) + flowSuffixSep
	var flows []string
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			flows = append(flows, c.Name[len(prefix)-len(flowSuffixSep):])
		}
	}
	if len(flows) < maxConcurrentFlows {
		return
	}
	for _, flow := range flows {
		a.clearFlowCookies(w, flow)
	}
}
