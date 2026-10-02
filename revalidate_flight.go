package vaioidc

// In-process deduplication of revalidation work (v0.30.0, go-vai-oidc#19).
//
// # The gap this closes
//
// maybeRevalidate gates on the age of the cookie the REQUEST carried. An SPA
// that fires N requests in parallel once the floor has passed sends N copies of
// one cookie, so before v0.30.0 every one of them made its own refresh grant and
// its own resolver call. That is N× the IdP and identity-backend load at every
// interval boundary, for every session — and under refresh-token ROTATION
// (Keycloak's "Revoke Refresh Token") it is worse than load: the second use of
// the same refresh token is `invalid_grant`, which isSessionRevoked correctly
// reads as a sign-out. The session was ended by a race between its own requests.
//
// # The mechanism
//
// A flight group keyed on a hash of (subject, refresh token): the first request
// runs the grant and the re-resolution, every concurrent request with the same
// key waits for it and receives the SAME outcome. Each caller then applies that
// outcome to ITS OWN payload and writes its own cookie, so a cookie that differs
// in a picked org (UpdateSession) keeps it.
//
// The result is RETAINED for revalidateFlightRetention after it lands, because
// "concurrent" in a browser is not "overlapping in this process": a request sent
// a few hundred milliseconds after the first one still carries the OLD cookie if
// the first response has not arrived yet, and under rotation that straggler is
// exactly the one that would sign the session out.
//
// # What it does NOT do
//
// It is per process. Two replicas behind a load balancer can still race one
// session's grant. That case needs sticky sessions or a shared store, and is
// left to the deployment; this closes the common in-browser case.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// errRevalidationAbandoned is the outcome a revalidation reports when its shared
// work did not complete (the leader panicked, or the waiter's own request was
// cancelled). It is not an IdP verdict, so it fails OPEN like any other.
var errRevalidationAbandoned = errors.New("vai-oidc: shared revalidation did not complete")

// revalShared is the outcome of one revalidation's network work, shared by
// every request in its flight. It carries ANSWERS (from the IdP and the
// resolver), never a payload: each caller applies the answers to its own.
type revalShared struct {
	// fresh is the grant's token set; nil for a resolver-only retry.
	fresh *oauth2.Token
	// grantErr is the grant's failure, when it failed.
	grantErr error
	// aut is the refreshed ID token's verified auth_time, or 0.
	aut int64
	// reresolved reports whether the resolver ran.
	reresolved bool
	outcome    reresolveOutcome
	// resolved is the resolver's admitted answer when outcome is applied.
	resolved *User
}

type revalCall struct {
	done     chan struct{}
	res      revalShared
	finished time.Time
}

// revalFlights is a singleflight with short result retention. Its zero value is
// ready to use.
type revalFlights struct {
	mu    sync.Mutex
	calls map[string]*revalCall
}

// do runs fn once per key among concurrent (and recently completed) callers and
// returns its result to all of them. A waiter whose ctx ends first gets
// errRevalidationAbandoned rather than blocking on another request's work.
func (g *revalFlights) do(ctx context.Context, key string, now func() time.Time, fn func() revalShared) revalShared {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*revalCall)
	}
	g.pruneLocked(now())
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.res
		case <-ctx.Done():
			return revalShared{grantErr: errRevalidationAbandoned}
		}
	}
	c := &revalCall{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()

	completed := false
	defer func() {
		g.mu.Lock()
		if !completed {
			// fn panicked: release the waiters with a fail-open outcome and do
			// not retain it, so the next request tries again.
			c.res = revalShared{grantErr: errRevalidationAbandoned}
			delete(g.calls, key)
		}
		c.finished = now()
		close(c.done)
		g.mu.Unlock()
	}()
	res := fn()
	c.res = res
	completed = true
	return res
}

// pruneLocked drops completed calls older than the retention window.
func (g *revalFlights) pruneLocked(now time.Time) {
	for k, c := range g.calls {
		select {
		case <-c.done:
			if now.Sub(c.finished) >= revalidateFlightRetention {
				delete(g.calls, k)
			}
		default:
		}
	}
}

// flightKey derives a flight key from the parts that identify one session's
// revalidation. The refresh token never appears in the map in the clear.
func flightKey(kind string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return kind + ":" + hex.EncodeToString(h.Sum(nil))
}

// sharedContext is the context the shared work runs under. It is detached from
// the leader's cancellation — the work serves every waiter, and one browser tab
// closing must not fail the others — and bounded by revalidateSharedTimeout
// instead, so a hung IdP cannot pin it forever. Values (the oauth2 HTTP client,
// trace ids) are kept.
func sharedContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), revalidateSharedTimeout)
}

// clock returns the current time in UTC. Tests replace a.now.
func (a *Auth) clock() time.Time {
	if a.now != nil {
		return a.now().UTC()
	}
	return time.Now().UTC()
}
