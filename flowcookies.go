package vaioidc

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
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
	// flowStartSep separates a per-flow state cookie's start time (base-36 Unix
	// milliseconds) from the state: `<start>~<state>[|<redirect>]`. The state is
	// hex, so it never contains it; a pre-v0.37.0 value carries no start.
	flowStartSep = "~"
	// maxFlowRedirectBytes bounds the redirect a flow's state cookie stores. Four
	// pending flows with long return paths would otherwise push the Cookie header
	// past an ingress's 8 KiB request-header buffer; a longer one is dropped (the
	// login then lands on PostLoginRedirect).
	maxFlowRedirectBytes = 1024
)

// flowStateValue is a per-flow state cookie's value: the start time, the state
// and the (bounded) redirect.
func flowStateValue(startedAtMs int64, state, redirect string) string {
	v := strconv.FormatInt(startedAtMs, 36) + flowStartSep + state
	if redirect != "" && len(redirect) <= maxFlowRedirectBytes {
		v += stateCookieDelimiter + redirect
	}
	return v
}

// splitFlowStart strips a per-flow state value's start time; 0 when absent.
func splitFlowStart(value string) (startedAtMs int64, rest string) {
	head, tail, ok := strings.Cut(value, flowStartSep)
	if !ok || strings.Contains(head, stateCookieDelimiter) {
		return 0, value
	}
	ms, err := strconv.ParseInt(head, 36, 64)
	if err != nil {
		return 0, value
	}
	return ms, tail
}

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
	for _, base := range []string{cookieOIDCState, cookiePKCEVerifier, cookieOIDCMaxAge, cookieOIDCSync, cookieOIDCKCAction} {
		clearOIDCCookie(w, a.cfg.flowCookie(base, flow), a.cfg.CookiePath, a.cfg.secureCookie())
	}
}

// makeRoomForFlow enforces maxConcurrentFlows before a new flow's cookies are
// set: when the browser already holds that many per-flow state cookies, the
// OLDEST are cleared — just enough to leave room for the new one — so the
// flows a person started most recently (other tabs) still complete. A flow
// whose value carries no start time sorts as the oldest.
func (a *Auth) makeRoomForFlow(w http.ResponseWriter, r *http.Request) {
	prefix := a.cfg.flowCookieName(cookieOIDCState) + flowSuffixSep
	type pending struct {
		flow    string
		started int64
	}
	var flows []pending
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			started, _ := splitFlowStart(c.Value)
			flows = append(flows, pending{c.Name[len(prefix)-len(flowSuffixSep):], started})
		}
	}
	excess := len(flows) - (maxConcurrentFlows - 1)
	if excess <= 0 {
		return
	}
	sort.SliceStable(flows, func(i, j int) bool { return flows[i].started < flows[j].started })
	for _, p := range flows[:excess] {
		a.clearFlowCookies(w, p.flow)
	}
}
