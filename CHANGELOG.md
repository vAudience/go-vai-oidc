# Changelog

## v0.16.0 — 2026-07-21

**Generic OIDC issuer support + first public Apache-2.0 release.** Fully additive and
backward-compatible: existing Keycloak consumers are unaffected (a config setting `KeycloakURL` +
`Realm` behaves exactly as before).

### Added

- **`Config.IssuerURL`** — point the Relying Party at *any* spec-compliant OIDC issuer (Google,
  Okta, Auth0, Entra, Authentik, Dex, …). Discovery goes directly to the issuer
  (`<IssuerURL>/.well-known/openid-configuration`). When set, `KeycloakURL`/`Realm` are ignored.
- **`Config.discoveryURL()`** semantics: exactly one discovery source is required — `IssuerURL`, or
  the Keycloak convenience path (`KeycloakURL` + `Realm`). `validate()` now requires the Keycloak
  fields only when `IssuerURL` is empty; the client/session fields are always required.
- Tests: generic-issuer discovery (non-`/realms/` issuer), config-validation matrix for the two
  discovery sources, and an explicit non-Keycloak (`realm_access`-absent) realm-roles case.

### Changed

- Public release hygiene: added `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, and CI
  (`go test -race` + `golangci-lint` + `govulncheck`). README rewritten generic-first. `go.mod`
  pinned to `go 1.25` (dependency floor: `coreos/go-oidc/v3` and `golang.org/x/oauth2` require 1.25).

## Earlier releases (pre-public)

`v0.16.0` is the first public release. The library was developed privately
through `v0.15.x`; the condensed history below preserves the API-relevant
changes with internal project references removed. All entries are dated
2026-04-14 → 2026-07-05, and every release listed is backward-compatible with
the one before it unless noted.

- **v0.15.1** — `Auth.IssueSession` now persists `Memberships` and `RealmRoles`
  (the inline-login/ROPC session-write path had dropped them via a hand-rolled
  payload literal; it now shares `sessionPayload.fromUser` with the callback
  path). Additive on the wire (`omitempty`); existing sessions unaffected.
- **v0.15.0** — first-class Keycloak realm roles: `User.RealmRoles []string` +
  `User.HasRealmRole(role)`, extracted from the standard `realm_access.roles`
  claim and persisted in the session. Additive.
- **v0.14.1** — regression fix: `handleCallback` now writes the full membership
  set into the session (v0.14.0 resolved it but dropped it before the cookie
  write). Consumers on v0.14.0 should upgrade.
- **v0.14.0** — `User.Memberships []Membership` surfaces the complete org set so
  consumers can render a multi-org picker; committed via
  `Auth.UpdateSession`. Fully backward compatible (the first membership stays the
  default active org).
- **v0.13.0** — transparent session-cookie chunking: when `RetainTokens` makes
  the encrypted session exceed the browser's ~4 KB single-cookie limit, it is
  split across `<name>_1..N` and reassembled on read (fail-closed: a missing/torn
  chunk → clean `ErrSessionInvalid`, never a partial decrypt). The single-cookie
  fast path is byte-identical to v0.12.
- **v0.12.0** — optional access-token retention + transparent refresh:
  `Config.RetainTokens` (default `false`) stores access/refresh tokens in the
  session; `Auth.AccessToken(w, r)` returns a valid token, refreshing and
  re-persisting when expired. Default behaviour unchanged when off.
- **v0.11.0** — `Auth.VerifyIDToken(ctx, rawIDToken) (*User, error)`: a public
  JWKS-backed verifier so consumers using an alternate grant (ROPC, token
  exchange) verify tokens with the same trust guarantee as the callback path
  (signature, `iss`, `aud`, `exp`). Strictly additive.
- **v0.10.0** — `Auth.IssueSession(w, r, *User, rawIDToken)`: write a
  `vai_session` cookie WITHOUT the redirect flow (for backend-proxied ROPC and
  branded inline-login surfaces). Produces a cookie byte-identical to the
  standard flow. The library does not perform the credential exchange — that
  remains the consumer's responsibility.
- **v0.9.0** — `NewBackground(ctx, cfg) *DeferredAuth`: a non-blocking
  constructor that runs discovery on a background goroutine and exposes
  `Ready()`/`Get()`/`Err()`, so a Kubernetes pod can serve `/health` immediately
  and gate `/ready` (503 until discovery succeeds) instead of failing
  connection-refused. Pure-additive; `New` semantics unchanged.
- **v0.8.0** — `Config.DiscoveryRetryBudget`: a jittered exponential-backoff
  retry around discovery, closing the cold-boot "provider not yet reachable"
  race. Set to a negative value to preserve the pre-v0.8.0 single-shot semantics.
- **v0.7.0** — `Config.RequireEmailDomain`: an email-domain claim gate applied in
  the callback (before `UserResolver`), with typed sentinels
  `ErrEmailDomainMismatch` + `ErrEmailClaimMissing`. NOTE: this gate matches the
  email *domain* only — it does not assert `email_verified` (see SECURITY.md).
- **v0.6.0** — the optional `obolresolver` sub-package: a reference `UserResolver`
  adapter that delegates org resolution to an external identity service via
  `POST /api/v1/identity/ensure`. Purely additive; adds no dependency to the root
  package.
- **v0.5.0** — `kc_idp_hint` + `prompt` query-param passthrough from
  `/auth/login` to the Keycloak authorize URL (whitelisted to those two params),
  so a consumer SPA can drive IdP selection directly.
- **v0.4.0** — `Config.IssuerURLOverride`: discover at one URL but accept a
  different canonical `iss` — the split-horizon case where cluster-internal
  callers reach the provider by a different network path than the browser-visible
  issuer.
- **v0.3.0** — module-path fix release; API byte-identical to v0.2.2.
- **v0.2.2** — nil-safety fixes (`UpdateSession` mutate callback, callback
  `UserResolver` nil return).
- **v0.2.1** — documentation and test alignment.
- **v0.2.0** — identity resolution + multi-org: `User.OrgID`, `User.Claims`,
  `Config.ExtraClaims`, `Config.UserResolver`, `Auth.UpdateSession()`.
- **v0.1.0** — initial release: OIDC Authorization Code Flow with PKCE,
  AES-256-GCM encrypted stateless session cookies, `RequireSession` /
  `OptionalSession` chi middleware, federated logout, open-redirect-protected
  `?redirect=`, browser-vs-API detection, and `errors.Is` sentinels.
