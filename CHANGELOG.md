# Changelog

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
