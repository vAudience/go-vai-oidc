package vaioidc

// deferred.go — background (deferred-discovery) constructor (Layer B)
//
// NewBackground returns immediately with a DeferredAuth handle and
// performs OIDC discovery on a goroutine. Consumers can serve
// `/health` as soon as the HTTP listener binds and use Ready() in
// `/ready` to gate Kubernetes' Service rotation — pods that have
// not yet completed discovery return 503 from /ready and stay out
// of the load balancer until discovery succeeds.
//
// This is a refinement on Layer A (v0.8.0 discoverWithRetry):
// Layer A blocks startup for up to DiscoveryRetryBudget seconds
// while it retries. Layer B inverts the model so the consumer's
// HTTP listener comes up immediately and the brown-out window
// becomes 503-on-/ready (Kubernetes-aware) rather than
// connection-refused (Kubernetes-blind).
//
// Lifecycle:
//   - NewBackground(ctx, cfg) — non-blocking; returns *DeferredAuth.
//   - DeferredAuth.Ready() bool — non-blocking; true after the
//     background New() call returns (success or error).
//   - DeferredAuth.Get() (*Auth, error) — blocks until Ready() then
//     returns whatever New() returned. Safe for concurrent callers.
//
// Cancel the parent ctx to stop the background goroutine early.

import (
	"context"
	"sync"
)

// DeferredAuth is the handle returned by NewBackground. The
// background goroutine writes the final (auth, err) into the
// slot exactly once and closes the ready channel.
type DeferredAuth struct {
	ready chan struct{}

	mu   sync.Mutex
	auth *Auth
	err  error
}

// NewBackground spawns OIDC discovery on a goroutine and returns
// immediately. The background goroutine respects the parent
// context's cancellation. Idempotent: calling Get() / Ready()
// before the goroutine completes is the supported pattern.
func NewBackground(ctx context.Context, cfg Config) *DeferredAuth {
	d := &DeferredAuth{ready: make(chan struct{})}
	go func() {
		a, err := New(ctx, cfg)
		d.mu.Lock()
		d.auth = a
		d.err = err
		d.mu.Unlock()
		close(d.ready)
	}()
	return d
}

// Ready reports whether the background New() call has completed
// (success or error). Non-blocking.
func (d *DeferredAuth) Ready() bool {
	select {
	case <-d.ready:
		return true
	default:
		return false
	}
}

// Get blocks until Ready() and returns the stored (auth, err).
// Safe for concurrent callers; same (auth, err) is returned to
// every caller.
func (d *DeferredAuth) Get() (*Auth, error) {
	<-d.ready
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.auth, d.err
}

// Err reports the discovery error (if any) at the moment of call.
// Returns nil when Ready() is false (caller MUST check Ready first
// when distinguishing "not done yet" from "succeeded"). Useful for
// /ready handlers that want to surface the error reason without
// blocking on Get().
func (d *DeferredAuth) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}
