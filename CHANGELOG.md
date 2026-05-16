# Changelog

## v0.9.0 — 2026-05-15

vaik8s MASTERPLAN-RESILIENCE `DC-OIDC-READINESS-01` Layer B. Adds a
non-blocking constructor `NewBackground(ctx, cfg) *DeferredAuth`
that performs OIDC discovery on a background goroutine and exposes
`Ready()` + `Get()` + `Err()` so consumers can serve `/health` as
soon as the HTTP listener binds and gate Kubernetes' Service
rotation via `/ready`. Pods that have not yet completed discovery
return 503 from `/ready` and stay out of the load balancer until
discovery succeeds. The brown-out window becomes 503-on-/ready
(Kubernetes-aware) rather than connection-refused (Kubernetes-
blind).

Layer A (v0.8.0 `discoverWithRetry`) is still the underlying
retry mechanism — `NewBackground` calls `New` which calls
`discoverWithRetry`. The change is purely about WHEN the
discovery is waited on (background goroutine vs main goroutine).

### Added

- `deferred.go::DeferredAuth` — the handle. Carries a ready chan,
  the final `*Auth` slot, and the final error. Mutex-guarded for
  concurrent `Get()` callers.
- `deferred.go::NewBackground(ctx, cfg) *DeferredAuth` — spawns
  the discovery goroutine and returns immediately.
- `DeferredAuth.Ready() bool` — non-blocking; true after the
  background `New` call returns.
- `DeferredAuth.Get() (*Auth, error)` — blocks until ready; safe
  for concurrent callers.
- `DeferredAuth.Err() error` — non-blocking error peek for
  `/ready` handlers.
- `deferred_test.go` — 5 tests (happy/error/ready-before-Get/
  20-goroutine concurrent Get/parent-ctx-cancel).

### Reversibility

Pure-additive. `New(ctx, cfg)` semantics unchanged. To roll back,
consumers swap `NewBackground` → `New` and remove the `/ready`
hook.

### Related

- vaik8s `docs/cycles/dc-oidc-readiness-01-layer-b.md` — cycle
  plan.
- Layer A: v0.8.0 (2026-05-15) — `Config.DiscoveryRetryBudget`.
- MASTERPLAN-RESILIENCE.md Cluster B.2.

## v0.7.0 — 2026-05-07

vaik8s MASTERPLAN-AUTH `DC-AUTH-07` Phase A. Adds the
**`Config.RequireEmailDomain`** email-domain gate so consumers can
enforce a tenant-domain claim filter without writing their own
UserResolver — used by vaisite to replace its bespoke `hd`-claim
check (DC-NXS-09 → DC-AUTH-07 migration). ADR-084 in vaik8s records
the rationale for picking `email`-domain over Google's `hd` claim
(IdP-portability; the realm-side `vaisite-google-only` browser flow
is the primary IdP gate).

### Added

- `Config.RequireEmailDomain string` — when non-empty, the OIDC
  callback rejects logins whose verified id_token `email` claim
  domain part (case-insensitive, last-`@`-split) does not match.
  Empty (default) preserves existing behaviour.
- `applyDefaults()` lowercases the configured value so runtime
  comparison is plain equality.
- `validate()` rejects `@` and whitespace runes in the configured
  value (prevents accidental full-email or rendering-bug values
  from passing through).
- New helper `enforceEmailDomain(user, requiredDomain)` runs the
  gate; called from `handleCallback` between claim extraction and
  `UserResolver` so custom resolvers don't need to know the rule.
- New typed sentinels `ErrEmailDomainMismatch` + `ErrEmailClaimMissing`
  for callers that want to programmatically inspect the rejection.
- 18 unit tests across config validation, helper boundaries
  (last-`@`-wins, missing/malformed email, leading-`@`), and
  reason-string mapping.

### Notes

- The masterplan §4 row 8 originally projected this functional bump
  at `v0.5.0`. That tag was consumed by DC-AUTH-OPS-04 (kc_idp_hint
  passthrough) and `v0.6.0` by DC-AUTH-05 Phase A; the DC-AUTH-07
  bump therefore lands at `v0.7.0`. vaik8s ADR-084 records the
  correction.

## v0.6.0 — 2026-05-07

vaik8s MASTERPLAN-AUTH `DC-AUTH-05` Phase A. Introduces the
**`obolresolver` sub-package** — the canonical UserResolver that
delegates org-resolution to obol's `POST /api/v1/identity/ensure`.
Replaces the per-consumer `NewDefaultOrgResolver` MVP shape used
by folios (DC-AUTH-02), skope (DC-AUTH-03), and aigentflow
(DC-AUTH-04). From DC-AUTH-05 onward every vai-oidc consumer
imports this sub-package verbatim.

### Added

- New sub-package `github.com/vAudience/go-vai-oidc/obolresolver`
  with:
  - `New(Config{BaseURL, Client, Timeout, AllowEmptyMembership})
    UserResolver`. Returns nil when BaseURL is empty so callers
    can wire it unconditionally.
  - `IdentityEnsureRequest`/`IdentityEnsureMembership`/
    `IdentityEnsureResponse` wire-shape structs mirroring obol's
    `obol.handler.identity.go` request+response contract.
  - Minimal `HTTPClient` interface (`Do(req)`) — caller supplies a
    charon-S2S-authenticated client (charonmw.Client) in production
    or any HTTPClient impl in tests. NO transitive charonmw
    dependency.
- 9 unit tests covering happy-path, empty-membership reject (default)
  and pass-through (AllowEmptyMembership), 5xx propagation, envelope-
  error propagation, nil-Client defensive resolver, transport
  errors, request-shape verification.

### Notes

- spec contract: `auth-platform-spec.md` §5.3 (UserResolver shape) +
  §5.5 (failure-mode matrix).
- The MVP `NewDefaultOrgResolver` callers (folios, skope, aigentflow)
  migrate to `obolresolver.New(...)` in their respective DC-AUTH-NN
  follow-ups (no upstream code changes required in this v0.6.0 — the
  sub-package is purely additive).

## v0.5.0 — 2026-05-04

vaik8s MASTERPLAN-AUTH `DC-AUTH-OPS-04` follow-up. Adds kc_idp_hint
and prompt query-param passthrough from `/auth/login` to the
Keycloak authorize URL. Lets consumer apps render a "Sign in with
Google" button that hrefs `/auth/login?kc_idp_hint=google` —
Keycloak then federates straight to Google instead of showing its
own login page first.

### Added

- `/auth/login?kc_idp_hint=<value>` is forwarded to Keycloak as
  `kc_idp_hint=<value>` on the authorize URL. Skips Keycloak's
  realm login page when the operator wants the consumer's SPA to
  drive IdP selection directly.
- `/auth/login?prompt=<value>` is forwarded similarly. Useful
  values: `login` (force credential prompt), `none` (silent
  refresh), `consent` (force consent screen).
- The forward whitelist is hardcoded to `kc_idp_hint` + `prompt`
  so unknown query params cannot leak into the authorize URL.

### Changed

- `(*oidcProvider).authCodeURL` signature gained a third
  `extra map[string]string` argument; downstream callers
  populate it via the new `authCodeExtras` helper.

## v0.4.0 — 2026-05-04

vaik8s MASTERPLAN-AUTH `DC-AUTH-OPS-02` follow-up. Adds the
kubernetes-native pattern where the consumer pod's discovery URL
intentionally differs from the issuer URL keycloak returns — needed
when Keycloak is configured with a public-base `--hostname` (so
browser-visible URLs are HTTPS) but cluster-internal callers reach
Keycloak via the cluster Service URL.

### Added

- `Config.IssuerURLOverride string` — when set, vai-oidc DISCOVERS
  at the URL composed from `KeycloakURL+Realm` but ACCEPTS the
  override as the canonical issuer in the discovery response (and
  uses it to verify ID-token `iss` claims). Internally implemented
  via `go-oidc.InsecureIssuerURLContext`. The override is a
  legitimate kubernetes-native configuration, not a security
  relaxation: the cluster-internal URL is just a different network
  path to the same identity provider.

### Why v0.4.0 (not v0.3.x)

vaik8s's MASTERPLAN-AUTH §7 reserved v0.4.0 for the `obolresolver`
sub-package at vaik8s DC-AUTH-05. To keep the version trail readable
this release uses the v0.4.0 slot for the IssuerURLOverride feature;
`obolresolver` shifts to v0.5.0 (DC-AUTH-05) and the vaisite
`RequireEmailDomain` claim-filter shifts to v0.6.0 (DC-AUTH-07).

## v0.3.0 — 2026-04-14

Module path fix release; API byte-identical to v0.2.2. (See
go-vai-oidc git tags v0.3.0.)

## v0.2.2 — 2026-04-14

Nil safety fixes from code review.

### Fixed
- `UpdateSession`: nil guard on `mutate` callback — returns nil (no-op) instead of panic
- OIDC callback: nil guard on `UserResolver` return — `(nil, nil)` treated as login rejection instead of panic
- `versions.yaml`: updated to match actual version

---

## v0.2.1 — 2026-04-14

Documentation and test alignment.

### Changed
- Rewrote README: UserResolver + Obol org resolution is the primary narrative, not an addendum
- Updated doc.go package comment to mention UserResolver and OrgID
- Updated all godoc examples (example_test.go) to show OrgID and Claims
- Updated project_plan/vai-oidc_spec.md to v2.0 (full API surface with v0.2.0 additions)
- Updated project_plan/masterplan.md to reflect completed status

### Added
- `TestUpdateSession_SetOrgID` — verifies OrgID mutation + IDToken/Exp preserved
- `TestUpdateSession_NoSession` — error path when no session cookie
- `TestSessionPayload_FromUser` — fromUser round-trip with all fields
- `TestEncryptDecrypt_RoundTrip_WithOrgIDAndClaims` — crypto round-trip with new fields

---

## v0.2.0 — 2026-04-14

Identity resolution and multi-org support.

### Added
- `User.OrgID` — first-class org ID field, resolved by `UserResolver` callback
- `User.Claims` — extra claims from ID token, configured via `Config.ExtraClaims`
- `Config.ExtraClaims` — list of additional ID token claim names to extract
- `Config.UserResolver` — callback invoked during OIDC callback to enrich user (resolve org, validate, etc.)
- `Auth.UpdateSession()` — mutate an existing session cookie (e.g., org selection post-login)
- `sessionPayload.fromUser()` — internal helper for session mutation

### Changed
- `extractUser()` now accepts `extraClaims` parameter for custom claim extraction
- Session payload includes `OrgID` and `Claims` fields (backward compatible — empty if unused)
- `TestSessionCookie()` preserves OrgID and Claims in test cookies

---

## v0.1.0 — 2026-04-14

Initial release.

- OIDC Authorization Code Flow with PKCE against Keycloak
- AES-256-GCM encrypted stateless session cookies
- `RequireSession` / `OptionalSession` chi middleware
- Keycloak federated logout via `end_session_endpoint` with `id_token_hint`
- `?redirect=` param with open-redirect protection (blocks absolute URLs, protocol-relative, backslashes)
- Browser vs API detection (redirect vs 401 JSON)
- Logger injection via `*slog.Logger`
- Sentinel errors for `errors.Is()` by consumers
- Test helpers: `NewTestAuth`, `SetTestUser`, `TestSessionCookie`, `TestSessionSecret`
- 66+ tests, race-clean
