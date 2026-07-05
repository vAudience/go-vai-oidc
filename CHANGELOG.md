# Changelog

## v0.15.0 — 2026-07-05

`DC-FACELIFT-01` (obol) — **first-class Keycloak realm roles on `User`.**

### Added

- **`User.RealmRoles []string`** and **`User.HasRealmRole(role string) bool`**.
  Extracted unconditionally from the ID token's standard `realm_access.roles`
  claim (no `Config.ExtraClaims` entry needed — this is a first-class field,
  like `OrgID`/`Memberships`). Nil if the claim is absent or shaped
  unexpectedly; that's not an error, just "this IdP/realm carries no realm
  roles for this token."
- Persisted in the encrypted session (`sessionPayload.Rls`) via `toUser`/
  `fromUser`, so it survives the cookie round-trip like every other
  user-visible field.
- Motivating use case: a consumer that serves more than one user class from
  one session mechanism (e.g. obol's org-admins + system-admins) can now
  gate the highest-trust tier on an explicit Keycloak realm role instead of
  inventing a side-channel claims scheme or, worse, trusting "which OIDC
  client authenticated this session" as an implicit role signal.

### Fixed

- `TestAuth.TestSessionCookie` (test helper) built its `sessionPayload` from
  a hand-rolled literal that silently dropped `Memberships` — the same
  field-drift class fixed for the real callback path in v0.14.1, just
  unnoticed in the test helper. Now uses `fromUser` like every other payload
  construction site, so `Memberships` and the new `RealmRoles` both survive.

### Behavior

- No breaking change. `RealmRoles` is additive (`omitempty` on the wire);
  existing sessions decode fine with a nil `RealmRoles` until the user's next
  login.

## v0.14.1 — 2026-06-11

`DC-MULTI-ORG-FIX` — **persist `User.Memberships` from the OIDC callback.**
A regression-fix release for v0.14.0.

### Fixed

- **`handleCallback` now writes the full membership set into the session.**
  v0.14.0 added `User.Memberships` and `sessionPayload.Mbs`, and the
  `obolresolver` populated `User.Memberships` correctly — but the callback built
  its `sessionPayload` from a hand-rolled struct literal that **omitted `Mbs`**.
  The membership set was resolved and then silently dropped before the cookie was
  written, so `UserFromContext` on every subsequent request returned an empty
  `Memberships` slice and a consumer's multi-org picker never triggered. The
  callback now constructs the payload via `sessionPayload.fromUser`, which carries
  **every** user-visible field (incl. `Mbs`), structurally preventing this class
  of write-side field-drift. `IDToken`/`Exp` are session-only and remain set
  directly (and are preserved by `fromUser`).
- New `TestCallbackPayloadConstruction_PersistsMemberships` drives the exact
  callback construction through the real `OptionalSession` → `UserFromContext`
  read path and asserts the membership set survives. The v0.14.0 tests only
  covered `session.go`'s `toUser`/`fromUser`/encrypt round-trip, which passed
  while the callback write path bypassed `fromUser` — this test closes that gap.

### Behavior

- No API change. v0.14.0's `User.Memberships` claim ("persisted in the encrypted
  session … so a post-login org picker still has the candidate orgs on later
  requests") now actually holds end-to-end. Consumers on v0.14.0 should upgrade.

## v0.14.0 — 2026-06-11

`DC-MULTI-ORG` — **surface the full org membership set** so consumers can
render a multi-org picker instead of silently inheriting the first membership.

### Added

- **`User.Memberships []Membership`** — the complete set of orgs the
  authenticated user belongs to, when a `UserResolver` supplies it. New
  `Membership{OrgID, OrgName, OrgSlug, Role}` type. Persisted in the encrypted
  session (payload key `mbs`) so a post-login org picker still has the candidate
  orgs on later requests, and so it survives `Auth.UpdateSession`.
- **`obolresolver` now populates `User.Memberships`** from Obol's
  `/identity/ensure` response (all rows, not just the first).

### Behavior

- **Fully backward compatible.** `obolresolver` still sets
  `User.OrgID = memberships[0].OrgID` as the default active org, so single-org
  consumers and any consumer that ignores `User.Memberships` behave exactly as
  in v0.13. The new field is purely additive.
- A multi-org-aware consumer reads `len(user.Memberships) > 1`, presents an org
  picker, then calls `Auth.UpdateSession(w, r, func(u *User){ u.OrgID = chosen })`
  to commit the selection. `len <= 1` needs no picker.
- Empty-membership paths (reject, or `AllowEmptyMembership=true`) leave
  `Memberships` nil — unchanged.
- Session size: memberships are small (a handful of short fields per org); the
  v0.13 cookie chunking already absorbs any overflow.

## v0.13.0 — 2026-06-06

`DC-APIKEY-followup` — **session-cookie chunking**, fixing a login-loop
regression introduced by v0.12.0's `RetainTokens`.

### Fixed

- When `Config.RetainTokens` is true, the encrypted session (id_token +
  access_token + refresh_token) can exceed the browser's ~4 KB single-cookie
  limit. Browsers **silently drop** an oversized `Set-Cookie`, so the user
  landed back at the login page after a successful Keycloak round-trip with no
  session — an endless login redirect. The session is now transparently split
  across the base cookie plus `<name>_1..N` and reassembled on read.

### Behavior

- **Single-cookie fast path is byte-identical to v0.12** for any session that
  fits in one cookie (every `RetainTokens=false` consumer is unaffected). The
  base cookie holds the encrypted payload directly; only when it would exceed
  `maxCookieValueBytes` does the base cookie become a `chunked:N` header with
  the payload in `<name>_1..N`. base64url never contains `:`, so the sentinel
  cannot collide with a real payload — pre-v0.13 sessions still decode.
- Reassembly is **fail-closed**: a missing, oversized, or torn chunk → a clean
  `ErrSessionInvalid` (re-login), never a partial decrypt. AES-256-GCM still
  authenticates the whole payload, so chunk tampering/forgery is rejected.
- Chunk count is capped at `maxSessionCookieChunks` (8 ≈ 28 KB); an even larger
  session is refused on write rather than issued un-readable.
- `clearSessionCookie` (logout) now evicts all chunk slots so a prior chunked
  session leaves nothing behind.
- The `CookieSizeWarnThreshold` warning now signals "session was chunked"
  (logs the chunk count) rather than "approaching the single-cookie limit".

## v0.12.0 — 2026-06-06

`DC-APIKEY-03` — optional Keycloak access-token retention + transparent
refresh, so a service can forward the logged-in user's live access token to a
downstream API (the platform driver: self-service Charon API-key minting for
Keycloak-logged-in users — see vaik8s `MASTERPLAN-APIKEYS.md`).

### Added

- `Config.RetainTokens bool` (default `false`). When true, the OIDC callback
  also stores the user's `access_token` + `refresh_token` + access-token expiry
  in the encrypted session (previously only the `id_token` was kept, for logout).
- `Auth.AccessToken(w, r) (string, error)` — returns a currently-valid Keycloak
  access token for the logged-in user, refreshing transparently via the stored
  refresh token when expired and persisting the rotated tokens back into the
  session cookie (session TTL preserved). Errors: `ErrTokensNotRetained`,
  `ErrTokenRefreshFailed`, plus the usual session errors.
- `CookieSizeWarnThreshold` (exported) + a warning logged by `setSessionCookie`
  when a written cookie is large — retaining both tokens can approach the ~4 KB
  per-cookie browser limit.

### Notes

- Default behaviour is unchanged when `RetainTokens` is false (the access/refresh
  tokens are still discarded; the id_token-only session is byte-identical).
- The access token is forwarded opaquely; the downstream's `aud` requirement is a
  Keycloak audience-mapper concern, not handled here. For refresh surviving
  Keycloak SSO logout, add `"offline_access"` to `Scopes`.

## v0.11.0 — 2026-05-22

`DC-AUTH-HARDENING` — adds `Auth.VerifyIDToken(ctx, rawIDToken) (*User, error)`
public method so consumers that obtain ID tokens via an alternate grant
(ROPC, token exchange) can verify them with the SAME JWKS-backed trust
guarantee the Authorization Code callback uses.

### What this enables

`Auth.IssueSession` (v0.10.0) lets consumers write a `vai_session`
cookie from a token they obtained outside the redirect flow. The
expectation was that the consumer would verify the token signature
themselves, but the library provided no public verifier — so the deepr
team's inline-login handler shipped with TLS-to-Keycloak as the only
trust anchor, base64-decoding the JWT payload without signature check.
That's acceptable as long as the network path is trusted but fragile:
a misconfigured `KEYCLOAK_BASE_URL`, a rogue egress proxy, or a future
split-horizon DNS would silently let an attacker mint arbitrary claims.

`VerifyIDToken` exposes the existing `*gooidc.IDTokenVerifier` (the
same one `handleCallback` uses) and the existing `extractUser` claim
mapper — kept in lockstep with the redirect path so inline-login is
cryptographically equivalent.

### Behavior

- JWKS signature check (RS256/ES256 per realm config) against the
  provider's published keys.
- `iss` must match the discovered issuer (or `Config.IssuerURLOverride`
  when set).
- `aud` must contain `Config.ClientID`.
- `exp` enforced.
- Maps the verified `*gooidc.IDToken` → `*User` via the same
  `extractUser` helper used by the callback handler (Sub/Email/Name/
  Claims per Config.ExtraClaims).
- Any verification failure → error wrapping `ErrTokenVerification`
  (existing sentinel, reused for back-compat with consumers that
  already discriminate via `errors.Is`).
- Empty token → error wrapping `ErrTokenVerification` (no JWKS round
  trip).

### Tests

`verify_test.go` boots an in-process httptest Keycloak (OIDC discovery
+ JWKS endpoint backed by a fresh RSA-2048 key) and asserts:

- Happy path (valid signature, audience, issuer, expiry) → User mapped.
- Empty token → `ErrTokenVerification`.
- Tampered signature → `ErrTokenVerification`.
- Expired token → `ErrTokenVerification`.
- Wrong audience → `ErrTokenVerification`.
- Wrong issuer → `ErrTokenVerification`.
- Malformed token → `ErrTokenVerification`.

### Compat

Strict additive — no exported symbol changed signature, no behavior
of the existing redirect or `IssueSession` paths changed.

---

## v0.10.0 — 2026-05-22

`DC-VAIO-INLINE-LOGIN` — adds `Auth.IssueSession(w, r, *User, rawIDToken)`
public method so consumers can write a `vai_session` cookie WITHOUT
going through the Authorization Code redirect flow.

### What this enables

The deepr team wanted a branded SPA `/login` surface with an inline
email+password form (instead of the "Continue with Keycloak" → hosted
Keycloak page redirect). The clean architecture is **backend-proxied
ROPC**: the SPA POSTs credentials to a backend endpoint; the backend
exchanges them at Keycloak's token endpoint with `grant_type=password`;
the backend then needs to set the same encrypted `vai_session` cookie
that `handleCallback` sets after a normal redirect.

Pre-v0.10.0 the encryption layer was internal — the only public path
was `TestSessionCookie` in `testing.go` (test-only). Consumers would
have had to either:
  - couple to a test helper in production code, or
  - re-implement the AES-256-GCM encoding, or
  - skip vai_session entirely and break downstream middleware.

`IssueSession` exposes the same code path `handleCallback` uses, so
the resulting cookie is byte-identical and indistinguishable from one
issued by the standard flow.

### Behavior

- `a.IssueSession(w, r, user, rawIDToken)` constructs a `sessionPayload`
  from `*User` + raw JWT, encrypts via the same internal helper as the
  callback path, sets the cookie with `cfg.CookieName` / `CookiePath` /
  `secureCookie()` / `cfg.SessionTTL`.
- `nil` user returns `ErrSessionInvalid` without touching the response.
- Empty `rawIDToken` is allowed — federated logout will fall back to a
  plain cookie clear without `id_token_hint` (consumer choice).
- All downstream middleware (`RequireSession`, `OptionalSession`,
  `UserFromContext`) sees the resulting session exactly as if the user
  came through the standard flow.

### Caller responsibilities

The library does NOT do the credential exchange itself — that's the
consumer's job. Concretely:
  1. POST to `<issuer>/protocol/openid-connect/token` with
     `grant_type=password&client_id=...&client_secret=...&username=...&password=...`.
  2. Validate the resulting `id_token` (signature, audience, expiry).
  3. Map claims to a `*User`.
  4. Call `Auth.IssueSession(w, r, user, idToken)`.

ROPC is OAuth's least-loved grant for good reasons (no MFA, no social
IdPs, the SPA's backend handles plaintext passwords). Consumers SHOULD
also implement: rate-limit per email/IP, audit-log every attempt, fall
back to the redirect flow for IdPs that don't support ROPC.

### Tests

- `TestIssueSession_WritesCookieMatchingHandleCallbackShape` — golden-
  shape compare against the payload layout `handleCallback` emits.
- `TestIssueSession_NilUserReturnsErr` — nil-user guard.
- `TestIssueSession_EmptyIDTokenAllowed` — empty `rawIDToken` accepted.
- Existing 50+ tests unaffected; `go test -race ./...` green.

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
