// Package obolresolver implements the canonical vai-oidc UserResolver
// for vAudience.AI services that delegate identity-to-org resolution
// to obol's `POST /api/v1/identity/ensure` endpoint.
//
// Auth-platform-spec.md §5 documents the contract end-to-end. This
// package replaces the per-consumer `NewDefaultOrgResolver` MVP shape
// (folios DC-AUTH-02, skope DC-AUTH-03, aigentflow DC-AUTH-04) with
// the production resolver from DC-AUTH-05 onward.
//
// Wire shape:
//
//	import "github.com/vAudience/go-vai-oidc/obolresolver"
//
//	cfg.UserResolver = obolresolver.New(obolresolver.Config{
//	    BaseURL: os.Getenv("FOL_OBOL_URL"),
//	    Client:  charonClient,
//	})
//
// The HTTP client is supplied by the caller (typically charonmw's
// S2S-authenticated client). This package does NOT pull charonmw as
// a transitive dependency — the caller's client implements the
// minimal `HTTPClient` interface defined here. Tests substitute a
// stub.
package obolresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	vaioidc "github.com/vAudience/go-vai-oidc"
)

// HTTPClient is the minimal interface obolresolver needs from the
// caller's HTTP client. Compatible with both `*http.Client` (basic
// case; no S2S auth) AND `*charonmw.Client` (production case;
// charon-S2S-authenticated). Only requires Do(req).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config carries the per-call inputs for a New() invocation.
type Config struct {
	// BaseURL is the obol cluster-internal URL, e.g.
	// "http://obol.vaik8s-vai-base-itsatony-vai-base-app.svc.cluster.local:17350".
	// The resolver POSTs to BaseURL + "/api/v1/identity/ensure".
	BaseURL string

	// Client is the HTTP client to use. Production callers pass a
	// charon-S2S-authenticated client (charonmw.Client); tests pass
	// any HTTPClient impl. Required.
	Client HTTPClient

	// Timeout caps each HTTP call. Default 5s — matches obol's
	// charon.timeout default in its own config (`obol.config.yaml`).
	Timeout time.Duration

	// AllowEmptyMembership, when true, lets a zero-membership
	// response from obol fall through to "user is logged in but has
	// no org". Default false: empty memberships → resolver returns
	// nil error AND nil user, which vai-oidc treats as a rejection
	// (user lands on LogoutRedirect). The strict default matches
	// the spec §5.5 "(nil, nil)" row contract.
	AllowEmptyMembership bool
}

// IdentityEnsureRequest mirrors obol's
// `internal/obol.handler.identity.go::IdentityEnsureRequest`.
// Subset shape; obol may grow optional fields without breaking this
// resolver.
type IdentityEnsureRequest struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// IdentityEnsureMembership mirrors obol's per-membership response
// row.
type IdentityEnsureMembership struct {
	OrgID   string `json:"org_id"`
	OrgName string `json:"org_name,omitempty"`
	OrgSlug string `json:"org_slug,omitempty"`
	Role    string `json:"role,omitempty"`
}

// IdentityEnsureResponse is the shape obol returns from the
// `/identity/ensure` endpoint.
type IdentityEnsureResponse struct {
	UserID      string                     `json:"user_id"`
	Memberships []IdentityEnsureMembership `json:"memberships"`
}

// obolEnvelope wraps every obol response. We only consult Data +
// Error; meta is opaque.
type obolEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// New returns a vai-oidc UserResolver that calls obol's
// `POST /api/v1/identity/ensure` to resolve the user's org
// membership. The resolver:
//
//  1. Issues a POST with {sub, email, name} from the OIDC user.
//  2. Surfaces the FULL membership set on user.Memberships (v0.14.0)
//     so a multi-org consumer can render a picker; sets user.OrgID =
//     memberships[0].org_id as the backward-compatible default active
//     org. The consumer commits a different pick via
//     `vaioidc.Auth.UpdateSession()` (spec §5.4).
//
// On failure paths:
//   - HTTP-transport / 5xx / non-2xx → returns wrapped error;
//     vai-oidc redirects user to LogoutRedirect with a Warn log.
//   - Empty memberships AND AllowEmptyMembership=false →
//     (nil, nil) which vai-oidc treats as a rejection (per spec).
//   - Empty memberships AND AllowEmptyMembership=true →
//     (user, nil) with OrgID unset (consumer decides).
//
// Returns a no-op resolver (never called) when cfg.BaseURL is empty
// — caller can wire it unconditionally without nil-checks.
func New(cfg Config) vaioidc.UserResolver {
	if cfg.BaseURL == "" {
		return nil
	}
	if cfg.Client == nil {
		// Defensive: a misconfigured caller would otherwise crash on
		// the first request. Return a resolver that always errors
		// loudly instead.
		return func(_ context.Context, _ *vaioidc.User) (*vaioidc.User, error) {
			return nil, errors.New("obolresolver: Config.Client is nil — supply a charonmw.Client or *http.Client")
		}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/api/v1/identity/ensure"
	allowEmpty := cfg.AllowEmptyMembership

	return func(ctx context.Context, user *vaioidc.User) (*vaioidc.User, error) {
		if user == nil {
			return nil, errors.New("obolresolver: user is nil")
		}
		body, mErr := json.Marshal(IdentityEnsureRequest{
			Sub:   user.Sub,
			Email: user.Email,
			Name:  user.Name,
		})
		if mErr != nil {
			return nil, fmt.Errorf("obolresolver: marshal request: %w", mErr)
		}

		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, rerr := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if rerr != nil {
			return nil, fmt.Errorf("obolresolver: build request: %w", rerr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, doErr := cfg.Client.Do(req)
		if doErr != nil {
			return nil, fmt.Errorf("obolresolver: %s: %w", endpoint, doErr)
		}
		defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if readErr != nil {
			return nil, fmt.Errorf("obolresolver: read response: %w", readErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("obolresolver: %s returned %d: %s",
				endpoint, resp.StatusCode, truncate(string(respBody), 200))
		}

		// Parse envelope. Obol always wraps responses in {"data": ..., "error": ...}.
		var env obolEnvelope
		if jerr := json.Unmarshal(respBody, &env); jerr != nil {
			return nil, fmt.Errorf("obolresolver: parse envelope: %w (body: %s)",
				jerr, truncate(string(respBody), 200))
		}
		if env.Error != nil {
			return nil, fmt.Errorf("obolresolver: obol error %s — %s",
				env.Error.Code, env.Error.Message)
		}

		var inner IdentityEnsureResponse
		if jerr := json.Unmarshal(env.Data, &inner); jerr != nil {
			return nil, fmt.Errorf("obolresolver: parse data: %w", jerr)
		}

		if len(inner.Memberships) == 0 {
			if allowEmpty {
				return user, nil
			}
			// Empty membership → reject (per spec §5.5).
			return nil, nil
		}

		// Surface the FULL membership set to the consumer (v0.14.0) so a
		// multi-org user can be offered an org picker instead of silently
		// inheriting the first org. OrgID still defaults to the first
		// membership for backward compatibility: single-org consumers and
		// consumers that ignore User.Memberships behave exactly as before;
		// a multi-org-aware consumer reads len(user.Memberships) > 1 and
		// calls Auth.UpdateSession() once the user picks.
		user.Memberships = toVaiMemberships(inner.Memberships)
		user.OrgID = inner.Memberships[0].OrgID
		return user, nil
	}
}

// toVaiMemberships maps obol's per-row membership shape to the public
// vaioidc.Membership type carried on User (and persisted in the session).
func toVaiMemberships(in []IdentityEnsureMembership) []vaioidc.Membership {
	if len(in) == 0 {
		return nil
	}
	out := make([]vaioidc.Membership, 0, len(in))
	for _, m := range in {
		out = append(out, vaioidc.Membership{
			OrgID:   m.OrgID,
			OrgName: m.OrgName,
			OrgSlug: m.OrgSlug,
			Role:    m.Role,
		})
	}
	return out
}

// truncate caps log-friendly error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
