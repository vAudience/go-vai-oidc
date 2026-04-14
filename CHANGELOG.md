# Changelog

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
