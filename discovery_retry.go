package vaioidc

// discovery_retry.go — DC-OIDC-RETRY-01 (v0.8.0).
//
// Wraps the one-shot `discover()` call in `New()` with a jittered
// exponential-backoff loop bounded by Config.DiscoveryRetryBudget.
//
// Closes the cold-boot failure class: a consumer pod starts before the
// OIDC provider has finished its own bootstrap, the single discovery
// HTTP GET returns "connection refused", the caller logs a WARN and
// proceeds with a nil Auth, and /auth/login then serves HTTP 401
// indefinitely until a manual pod restart clears it.
//
// Retryable classes:
//   - Transient HTTP (5xx, 408, 429).
//   - Network-class (connection refused, EOF, i/o timeout, DNS
//     "no such host", "network is unreachable", "connection reset").
//   - context.DeadlineExceeded from the per-attempt child context.
//
// Permanent classes (short-circuit, no retry):
//   - 4xx other than 408/429 (auth/config errors).
//   - JSON parse errors (malformed discovery document).
//   - Any error that doesn't match the transient set.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"
)

// discoverWithRetry runs `discover` with the retry policy. Returns
// the same shape as a single-shot `discover()` call.
//
// When `budget <= 0` the helper degrades to the pre-v0.8.0 single
// attempt — preserves back-compat for callers that explicitly opt
// out via `Config.DiscoveryRetryBudget = -1` (or any negative).
func discoverWithRetry(
	ctx context.Context,
	logger *slog.Logger,
	budget time.Duration,
	discoveryURL, clientID, clientSecret, callbackURL, issuerOverride string,
	scopes []string,
) (*oidcProvider, error) {
	if budget <= 0 {
		return discover(ctx, discoveryURL, clientID, clientSecret, callbackURL, issuerOverride, scopes)
	}

	started := time.Now()
	deadline := started.Add(budget)
	attempt := 0
	var lastErr error
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Budget exhausted. Surface the last seen error so the
			// caller can identify the actual failure mode (rather
			// than a generic "timeout"); the err already carries
			// ErrDiscoveryFailed via discover()'s wrap.
			if lastErr == nil {
				lastErr = fmt.Errorf("vai-oidc: discovery budget %s exhausted without an attempt", budget)
			}
			return nil, lastErr
		}

		perAttempt := discoveryRetryPerAttemptTimeout
		if remaining < perAttempt {
			perAttempt = remaining
		}
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		prov, err := discover(attemptCtx, discoveryURL, clientID, clientSecret, callbackURL, issuerOverride, scopes)
		cancel()
		attempt++

		if err == nil {
			if attempt > 1 {
				logger.Info(logMsgDiscoverySuccess,
					slog.String(logKeyComponent, logComponent),
					slog.Int(logKeyDiscoveryAttempt, attempt),
					slog.Duration(logKeyDiscoveryElapsed, time.Since(started)),
				)
			}
			return prov, nil
		}
		lastErr = err

		if !isDiscoveryRetryable(err) {
			// Permanent class — no point retrying.
			return nil, err
		}

		// Backoff before the next attempt.
		base := discoveryRetryBaseDelay << (attempt - 1)
		if base > discoveryRetryMaxDelay {
			base = discoveryRetryMaxDelay
		}
		jitter := time.Duration(0)
		if base > 0 {
			jitter = time.Duration(rand.Int63n(int64(base / 2)))
		}
		backoff := base + jitter
		if backoff > time.Until(deadline) {
			// Sleeping past the deadline would just produce a budget-
			// exhausted error on the next loop iteration; return now.
			return nil, lastErr
		}

		logger.Warn(logMsgDiscoveryRetry,
			slog.String(logKeyComponent, logComponent),
			slog.Int(logKeyDiscoveryAttempt, attempt),
			slog.Duration(logKeyDiscoveryElapsed, time.Since(started)),
			slog.Duration(logKeyDiscoveryBackoff, backoff),
			slog.String(logKeyError, err.Error()),
		)

		select {
		case <-ctx.Done():
			// Parent context canceled (e.g. shutdown). Return the
			// caller-visible reason rather than the last discovery
			// error so the upper layer doesn't double-wrap.
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// isDiscoveryRetryable classifies whether `err` represents a
// transient failure worth retrying against.
//
// The check is intentionally string-based for HTTP-status and
// network-error matching because go-oidc wraps the underlying
// transport error layers deep; introspecting via errors.As to
// every possible concrete type would be brittle. The substrings
// used here are stable across go-oidc + net/http and have been
// the same set since Go 1.0.
func isDiscoveryRetryable(err error) bool {
	if err == nil {
		return false
	}
	// context.DeadlineExceeded wrapping (per-attempt timeout).
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	// Transient HTTP status codes surface via the discovery client's
	// error text. 5xx is a server-side blip; 408/429 are
	// timeout/rate-limit which retry typically resolves.
	for _, needle := range []string{
		"500 Internal Server Error",
		"502 Bad Gateway",
		"503 Service Unavailable",
		"504 Gateway Timeout",
		"408 Request Timeout",
		"429 Too Many Requests",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	// Network-class failures. These match the actual error strings
	// emitted by Go's net package for the most common cold-boot
	// race scenarios.
	for _, needle := range []string{
		"connection refused",
		"no such host",
		"network is unreachable",
		"i/o timeout",
		"connection reset",
		"EOF",
		"context deadline exceeded",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}
