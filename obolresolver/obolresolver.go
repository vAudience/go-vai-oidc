// Package obolresolver is a reference go-vai-oidc UserResolver adapter
// for vAudience.AI services that delegate identity-to-org resolution to
// the Obol billing service's `POST /api/v1/identity/ensure` endpoint.
//
// It is an optional, vendor-specific example of the generic
// go-vai-oidc UserResolver seam: generic consumers do not need it (Go
// tree-shakes it out; it adds no dependency to the root package). Use
// it as a template for your own resolver, or ignore it entirely.
//
// Wire shape:
//
//	import "github.com/vAudience/go-vai-oidc/obolresolver"
//
//	cfg.UserResolver = obolresolver.New(obolresolver.Config{
//	    BaseURL: os.Getenv("OBOL_URL"),
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
	"net/url"
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
	// BaseURL is the Obol service base URL, e.g.
	// "http://obol.internal:17350" (typically a cluster-internal
	// address). The resolver POSTs to BaseURL + "/api/v1/identity/ensure".
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

	// AllowedLandingHosts optionally PINS which hosts a landing redirect may
	// name. Empty — the default — admits any host, provided the URL is a
	// well-formed absolute http/https URL with no embedded credentials.
	//
	// ⚠️ THE THREAT MODEL IS NOT AN OPEN REDIRECT AND SAYING SO IS THE POINT.
	// This value never comes from the browser: it arrives in the body of an
	// authenticated server-to-server response from the obol deployment this
	// resolver was configured to trust. An attacker who can set it already
	// controls the identity backend, i.e. the login itself. So the residual risk
	// is a MISCONFIGURED obol (a wrong `org_ui.public_base_url`), and this field
	// is the mitigation for that — not for a hostile browser.
	//
	// ⚠️ IT MUST NOT DEFAULT TO Config.BaseURL'S HOST, WHICH IS THE OBVIOUS AND
	// WRONG TIGHTENING. BaseURL is how this service DIALS obol and is routinely
	// cluster-internal (`http://obol.<ns>.svc.cluster.local:17350`), while the
	// landing URL is the PUBLIC address a browser must reach
	// (`https://obol.example.com/app/signup`). Those hosts differ by design, so
	// a same-host rule would reject every correct URL and silently disable the
	// feature — the failure would look like obol not serving a decision at all.
	//
	// Comparison is on the URL's host (including port when present), case-folded.
	AllowedLandingHosts []string
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
	// TeamIDs are the user's active teams within this org. Obol emits the field
	// unconditionally (never omitempty) from the release that added it, so an
	// absent key here means an OLDER obol rather than a user with no teams — the
	// two decode the same into a nil slice, which is why no consumer may read nil
	// as an authoritative "no teams".
	TeamIDs []string `json:"team_ids,omitempty"`
}

// IdentityEnsureLanding mirrors obol's landing DECISION (obol 3.185.0 /
// ADR-199). Absent on an older obol, which is why the field below is a pointer:
// "obol has no opinion" and "obol says ready" must not decode to the same
// value, because the safe reading of the two differs.
type IdentityEnsureLanding struct {
	Decision   string `json:"decision"`
	LandingURL string `json:"landing_url"`
}

// IdentityEnsureResponse is the shape obol returns from the
// `/identity/ensure` endpoint.
type IdentityEnsureResponse struct {
	UserID      string                     `json:"user_id"`
	Memberships []IdentityEnsureMembership `json:"memberships"`
	Landing     *IdentityEnsureLanding     `json:"landing"`
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
	allowedHosts := normalizeHosts(cfg.AllowedLandingHosts)

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
		// ⚠️ THIS HEADER CLOSES A MEASUREMENT GAP THAT ONLY THIS FILE COULD CLOSE
		// (obol ADR-194 D5). obol counts which client contract each consumer runs
		// on `obl_consumer_sdk_total{service_id,sdk_contract}`, and that rail had
		// an irreducible `absent` floor because THIS module hand-builds its
		// request and carried no version header on any released version — so a
		// share of `absent` belonged to a shared dependency that no consumer could
		// fix by pinning a newer obol SDK. Measured on styx before this change:
		// `atl` read `identity.write` 1,329 against `absent` 1,672.
		//
		// It reports THIS MODULE's version, deliberately, and not a value the
		// consumer supplies: the question obol is asking is which code composed
		// the request, and that is this file.
		req.Header.Set(headerObolClientVersion, ClientVersion)

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

		landing := admitLanding(inner.Landing, allowedHosts)

		if len(inner.Memberships) == 0 {
			// ⚠️ A LANDING DECISION MAKES AllowEmptyMembership IRRELEVANT, AND THAT
			// IS THE WHOLE BEHAVIOURAL CHANGE OF v0.18.0. Before it, the two
			// available answers for a person obol placed in no organization were
			// "silently adopt whatever came first" and "bounce them to a logout
			// page" — and NEITHER IS ONBOARDING. A backend that has decided this
			// person needs onboarding has told us they are a legitimate,
			// authenticated human at the start of a flow, so rejecting the login
			// would discard the one instruction we asked for.
			//
			// The flag survives for consumers with a custom resolver or an older
			// obol, where it still decides. It just stops deciding a human's fate
			// whenever a decision is present.
			if landing != nil {
				user.Landing = landing
				return user, nil
			}
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
		// ⚠️ OrgID IS STILL SET, IN EVERY ARM, INCLUDING `org_selection`, AND
		// REMOVING THAT IS THE MOST TEMPTING WRONG CHANGE HERE. obol fills the
		// org id alongside the decision on purpose: several services in the fleet
		// read an EMPTY org id as *all tenants*, so a consumer that ignores
		// `landing` must degrade to the previous behaviour and never to a
		// cross-tenant read. That is also what lets the fleet adopt this in any
		// order. The decision travels BESIDE the default pick; it does not
		// replace it.
		user.Landing = landing
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
			TeamIDs: m.TeamIDs,
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

// ---------------------------------------------------------------------------
// The landing decision: admission, and why it is validated HERE.
// ---------------------------------------------------------------------------

// headerObolClientVersion is the header obol reads to learn which client
// contract a consumer runs. It is the same header `pkg/oblclient` sends, on
// purpose: obol bounds the value into a closed vocabulary and a second header
// name would give it two populations to reconcile.
const headerObolClientVersion = "X-Obol-Client-Version"

// ClientVersion is the version this module reports to obol.
//
// ⚠️ IT IS THIS MODULE'S VERSION AND NOT THE obol SDK'S. `go-vai-oidc` cannot
// depend on `pkg/oblclient` — that package lives in obol's nested module, and
// this module is a dependency of services still frozen on obol's PRE-SPLIT root
// module, which cannot carry it at all. So the honest answer to "which code
// composed this request" is a version string this file owns, and it must be
// bumped with versions.yaml (TestClientVersionMatchesTheManifest pins it).
const ClientVersion = "go-vai-oidc/0.21.0"

// admitLanding turns obol's landing object into a value the callback may act
// on, or nil.
//
// ⚠️ VALIDATION LIVES HERE RATHER THAN IN auth.go, AND THAT SPLIT IS THE
// SECURITY ARGUMENT. `auth.go`'s isValidRedirect enforces a SAME-ORIGIN RELATIVE
// PATH, because the value it guards comes from the BROWSER (`/auth/login?redirect=…`).
// A landing URL is the opposite kind of value: it is absolute and cross-origin
// BY CONSTRUCTION — obol is on another host — and it arrives in the body of an
// authenticated server-to-server response. Running it through isValidRedirect
// would reject every correct URL; running it through nothing would let a
// misconfigured backend point a browser anywhere. So the resolver, which is the
// only component that knows it is talking to obol, admits it.
//
// What is checked, and what each check is for:
//
//   - a decision that wants no redirect (`ready`, or one this version does not
//     know) keeps its URL out of the callback entirely, so a future decision
//     name cannot move a user by accident;
//   - the URL must PARSE as an absolute http/https URL with a host, which is
//     what excludes `javascript:`, `data:` and protocol-relative forms — the
//     actual redirect-abuse class;
//   - it must carry no embedded credentials (`user:pass@`), which is the
//     phishing form of a legitimate-looking URL;
//   - and, when the deployment pinned hosts, the host must be one of them.
//
// A rejected URL does NOT reject the login: the landing object is returned with
// its URL cleared, so the decision still reaches the consumer (which may want to
// display something) while RedirectTarget answers false and the login finishes
// where it would have before.
func admitLanding(in *IdentityEnsureLanding, allowedHosts []string) *vaioidc.Landing {
	if in == nil {
		return nil
	}
	out := &vaioidc.Landing{Decision: in.Decision}
	if in.LandingURL == "" {
		return out
	}
	// Only the arms that actually redirect are worth validating; for anything
	// else the URL is not carried at all.
	switch in.Decision {
	case vaioidc.LandingDecisionOnboarding, vaioidc.LandingDecisionOrgSelection:
	default:
		return out
	}
	u, err := url.Parse(in.LandingURL)
	if err != nil {
		return out
	}
	if u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS {
		return out
	}
	if u.Host == "" || u.User != nil {
		return out
	}
	if len(allowedHosts) > 0 && !hostAllowed(u.Host, allowedHosts) {
		return out
	}
	out.URL = in.LandingURL
	return out
}

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// normalizeHosts case-folds the configured allow-list once, at construction,
// so the per-request check is a plain comparison.
func normalizeHosts(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(host)
	for _, a := range allowed {
		if host == a {
			return true
		}
	}
	return false
}
