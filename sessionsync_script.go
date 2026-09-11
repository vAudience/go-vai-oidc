package vaioidc

// The browser half of session sync, owned by the library (v0.21.0).
//
// # Why this is here and not in each consumer
//
// v0.20.0 shipped the server half and left the client half to consumers. The
// first consumer wrote 158 lines of JavaScript; eight more doors were queued to
// receive a copy of it. ⛔ That is the shape this fleet has been burned by
// repeatedly (one value, N hand-written producers), and it is at its worst here:
// the browser half is precisely the half with NO SERVER-SIDE SIGNAL. A copy that
// drifts, or one that is never updated when a verdict is added, fails in a
// browser console and nowhere else — on the product with the strictest CSP,
// which is the one most likely to need the fix.
//
// So the library serves the script, and a consumer's whole browser-side opt-in
// becomes one <script src> tag pointing at its own auth mount.
//
// # What a consumer still owns, and cannot be given
//
// ⚠️ THE CSP. `frame-src 'self' <AuthorizationOrigin()>` lives on the consumer's
// own page, produced by the consumer's own middleware, and no library can write
// it. That is why the beacon below exists: it is the one mechanism that turns
// "the frame was blocked" from a console message into a server log line.

import (
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed sessionsync_script.js
var sessionSyncScriptSource string

// handleSessionSyncScript serves the client script, with both endpoint paths
// templated in from the mount this router was actually mounted at.
//
// ⭐ THE MOUNT IS DERIVED FROM THE REQUEST PATH, never configured and never
// assumed. The path the browser used to fetch this script is, by construction,
// the path that resolves to this router — so trimming the known suffix yields
// the consumer's real mount whatever prefix it chose. A configured mount would
// be a second producer of a value the router already knows, and the failure of
// getting it wrong is an iframe that loads a 404 and reports nothing.
//
// ⛔ THE DERIVED PREFIX IS VALIDATED BEFORE IT IS TEMPLATED INTO JAVASCRIPT.
// Everything reaching this point is a literal route match, so a hostile prefix
// is not reachable today — but "not reachable today" is the argument that makes
// the next refactor an injection. The charset refusal costs one function and
// removes the question.
//
// ⚠️ It assumes the browser-visible path equals the server-visible path. That
// holds on this fleet by decision (products are SUBDOMAINS, not paths, so no
// proxy rewrites a prefix away). A consumer behind a path-stripping proxy must
// not use this route.
func (a *Auth) handleSessionSyncScript(w http.ResponseWriter, r *http.Request) {
	mount, ok := mountFromScriptPath(r.URL.Path)
	if !ok {
		// Refusing is the only honest answer: a script whose endpoints were
		// guessed would load, run, and silently reconcile nothing.
		a.logger.Warn(logMsgSyncScriptPath,
			slog.String(logKeyComponent, logComponent),
			slog.String(logKeyPath, r.URL.Path),
		)
		http.Error(w, "session sync script: unusable mount path", http.StatusInternalServerError)
		return
	}

	body := strings.NewReplacer(
		scriptTokenSyncEndpoint, jsStringLiteral(mount+pathSessionSync),
		scriptTokenBlockedEndpoint, jsStringLiteral(mount+pathSessionSyncBlocked),
	).Replace(sessionSyncScriptSource)

	w.Header().Set(headerContentType, contentTypeJavaScript)
	// ⚠️ No-store rather than a long cache: the endpoints inside this body are
	// derived per request, and a cached copy of a body assembled for a different
	// mount is a script that reconciles against somebody else's routes. The file
	// is a few KB and is fetched once per page load.
	w.Header().Set(headerCacheControl, cacheControlNoStore)
	w.Header().Set(headerXContentTypeOptions, contentTypeOptionsNoSniff)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// mountFromScriptPath recovers the consumer's mount prefix from the path the
// script was requested at, and refuses anything it cannot vouch for.
//
// Returns ("", false) when the path does not end in the script suffix, or when
// the recovered prefix contains a character that has no business in a route
// prefix. An empty prefix (mounted at root) is legitimate and returns ("", true)
// — ⛔ which is why the bool is separate from the string and must not be
// collapsed into an emptiness check.
func mountFromScriptPath(p string) (string, bool) {
	if !strings.HasSuffix(p, pathSessionSyncScript) {
		return "", false
	}
	mount := strings.TrimSuffix(p, pathSessionSyncScript)
	for _, c := range mount {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '-', c == '_', c == '.':
		default:
			return "", false
		}
	}
	return mount, true
}

// jsStringLiteral renders s as a JavaScript string literal safe to substitute
// into a script body.
//
// ⚠️ It is belt AND braces: mountFromScriptPath has already refused every
// character this escapes. Both exist because the alternative is a comment
// asserting that the other one is enough.
func jsStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\', '\n', '\r', '<', '>', '&', '\u2028', '\u2029':
			// \uXXXX covers every case with one rule, including the two line
			// terminators that are newlines to a JavaScript parser and ordinary
			// characters to everything else.
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// handleSessionSyncBlocked records that a browser gave up on reconciliation
// without ever reaching a verdict.
//
// ⭐ THIS IS THE ONLY SERVER-SIDE SIGNAL THE BROWSER HALF HAS. Every way session
// sync can fail in a browser — a missing `frame-src` directive on the parent
// page, a consumer middleware that overwrites the sync document's CSP, an
// `X-Frame-Options` header that forbids the frame, a provider that renders
// instead of redirecting — is reported to a browser console and NOWHERE ELSE.
// The product then keeps serving the previous user with every server-side signal
// green, which is exactly the failure this whole feature exists to remove.
//
// ⛔ IT REQUIRES A SESSION, and that is not politeness. An unauthenticated POST
// that writes a WARN line is a log-flooding primitive any page on the internet
// can aim at this origin. Requiring the session bounds it to people who are
// signed in here, which is also the only population whose report means anything:
// a blocked frame matters because a SIGNED-IN person is not being reconciled.
//
// ⚠️ It always answers 204, session or not. The browser can do nothing with a
// refusal, and an endpoint that discriminates in its status code tells an
// unauthenticated caller whether a given cookie is valid.
func (a *Auth) handleSessionSyncBlocked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerCacheControl, cacheControlNoStore)

	if _, err := readSessionCookie(r, a.sessionKey, a.cfg.CookieName); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	a.logger.Warn(logMsgSyncBlocked,
		slog.String(logKeyComponent, logComponent),
		slog.String(logKeyClientIP, clientIP(r)),
		slog.String(logKeyReason, reasonSyncBlocked),
	)
	w.WriteHeader(http.StatusNoContent)
}
