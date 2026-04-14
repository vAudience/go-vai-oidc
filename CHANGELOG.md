# Changelog

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
