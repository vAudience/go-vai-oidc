package vaioidc

// Cookie-tossing hardening (v0.32.0).
//
// # The attack
//
// Cookies are scoped by SITE, not origin. A login host at auth.example.com
// whose parent domain is not on the Public Suffix List shares a site with every
// sibling host (alice.example.com, mallory.example.com), and any sibling can set
// a cookie with Domain=example.com that the browser then sends to the login
// host. This package's flow cookies (state, PKCE verifier) are what tie a
// callback to the browser that started the login, so a sibling that plants its
// OWN state + verifier and navigates the victim to
// /callback?code=<attacker's code>&state=<attacker's state> signs the victim
// into the attacker's account (login CSRF). The state cookie also carries the
// post-login redirect.
//
// # The controls, strongest first
//
//  1. Config.CookieHostPrefix — `__Host-` cookies cannot be set with a Domain
//     attribute, so a sibling cannot plant them at all. THE fix.
//  2. Duplicate refusal (always on) — a tossed cookie with the same name as a
//     genuine one arrives as a SECOND cookie of that name; which one a server
//     reads first is the attacker's choice (a longer Path sorts first). A
//     callback carrying two state, verifier or max_age cookies is refused.
//     This does not stop an attacker who tosses into a browser with no login
//     in flight; only (1) does.
//  3. Config.RejectSameSiteCallback — the browser's own Sec-Fetch-Site
//     verdict. Defence in depth; a cross-site redirector launders it.
//
// # Why the state is not additionally MAC-bound to the verifier
//
// The IdP already binds them: the code it issues is bound to the PKCE
// challenge sent with that authorization request, so a verifier from another
// login cannot redeem it; and the state cookie is compared to the query state
// in constant time. A server-side MAC over (state, verifier) would only stop a
// mix-and-match pair, and a cookie-tossing attacker never needs one — it runs
// /auth/login itself and plants the genuine pair it was handed. The defence
// against a planted pair is (1).

import (
	"errors"
	"fmt"
	"net/http"
)

// Cookie-guard names (v0.32.0).
const (
	// cookieHostPrefix is the RFC 6265bis cookie-name prefix a browser accepts
	// only on a Secure, Path=/, Domain-less cookie.
	cookieHostPrefix = "__Host-"

	headerSecFetchSite     = "Sec-Fetch-Site"
	secFetchSiteSameSite   = "same-site"
	secFetchSiteSameOrigin = "same-origin"

	logKeyCookieName = "cookie_name"

	logMsgFlowCookieDuplicate         = "OIDC callback: duplicate flow cookie (cookie tossing?); refused"
	logMsgSameSiteCallback            = "OIDC callback: same-site navigation refused (RejectSameSiteCallback)"
	logMsgHostPrefixNameUnsatisfiable = "CookieName carries the __Host- prefix but InsecureCookie or a CookiePath other than \"/\" is set; browsers will drop the session cookie — use CookieHostPrefix"
	logReasonSyncFlowCookieDuplicate  = "sync callback: duplicate state or PKCE cookie (cookie tossing?)"
	logReasonSyncSameSiteCallback     = "sync callback: same-site navigation refused (RejectSameSiteCallback)"
	logReasonMaxAgeCookieDuplicate    = "max_age_cookie_duplicate"
	logKeySecFetchSite                = "sec_fetch_site"
)

// errDuplicateCookie reports that a request carried more than one cookie with
// a name this package reads exactly once.
var errDuplicateCookie = errors.New("vai-oidc: duplicate cookie")

// uniqueCookie returns the ONLY cookie named name. It returns http.ErrNoCookie
// when there is none and an error wrapping errDuplicateCookie when there is
// more than one — never "the first", because which duplicate a browser sends
// first is the planting party's choice.
func uniqueCookie(r *http.Request, name string) (*http.Cookie, error) {
	cs := r.CookiesNamed(name)
	switch len(cs) {
	case 0:
		return nil, http.ErrNoCookie
	case 1:
		return cs[0], nil
	default:
		return nil, fmt.Errorf("%d cookies named %q: %w", len(cs), name, errDuplicateCookie)
	}
}

// isSameSiteNavigation reports whether the browser marked r as initiated from
// the same site or origin. An absent header (an older browser) is not.
func isSameSiteNavigation(r *http.Request) bool {
	switch r.Header.Get(headerSecFetchSite) {
	case secFetchSiteSameSite, secFetchSiteSameOrigin:
		return true
	default:
		return false
	}
}
