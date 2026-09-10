# Changelog

## v0.19.0 — 2026-09-10

**Signing out of one product now signs you out of the others.** Option B of the fleet's "one logout"
design: a stateless, refresh-backed revalidation floor. Pays **DC-PORTAL-SIBLINGSESSION-01**.

Additive: `RevalidateInterval` defaults to zero, which is the pre-v0.19.0 behaviour exactly. A
consumer that changes nothing performs no new network calls and behaves identically.

### The gap

A product session was an **independent copy** of an authentication that happened once.
`RequireSession` decrypted the cookie, checked `Exp`, and never re-contacted the IdP. Signing out of
one product terminated the Keycloak SSO session and cleared that product's own cookie — and the
**five sibling products kept serving that person with full access until their own cookies expired**,
up to `SessionTTL` (24 h by default), with every health signal green throughout.

⛔ **Nothing else in the stack closed it either, and the reassuring backstop was refuted by
measurement.** There is no session store to invalidate; cookies are host-only, so no sibling can see
them; and the downstream authorization broker verifies tokens OFFLINE against cached JWKS, with no
introspection and no revocation list. The browser path carries no Keycloak bearer at all. Nothing
anywhere re-asked the IdP whether the person was still signed in.

### The mechanism

Keycloak invalidates refresh tokens bound to an SSO session when that session ends. So a
`refresh_token` grant is a QUESTION with a meaningful answer, and asking it on a floor converts the
product session from an independent copy into something DERIVED from the IdP session — which is what
"one login" means.

```go
cfg.RetainTokens = true
cfg.RevalidateInterval = 5 * time.Minute
```

Three consequences, and only the first is the headline: sign-out propagates within one interval;
**the session becomes sliding** (before this, `Exp` was absolute — set once at login and never
moved); and a successful refresh is itself an IdP interaction, so it resets `ssoSessionIdleTimeout`
and stops the product cookie and the SSO session expiring on independent, inverted clocks.

⭐ **No ceiling is introduced here.** The absolute bound is the realm's `ssoSessionMaxLifespan`: past
it a refresh grant fails regardless of what this library believes, and the failure arrives on the
same `invalid_grant` path. A second ceiling in the library would be a second owner of one policy.

### The three rules that make it safe rather than dangerous

1. ⛔ **Fail CLOSED only on an explicit verdict.** `invalid_grant` is the IdP saying "this session
   ended". A transport error, a 5xx, or any other OAuth2 error code is the IdP failing to answer,
   and each fails OPEN. This matters more than the feature: `invalid_client` is a **rotated or wrong
   client secret**, and failing closed on it would log out every user of a service at the moment of
   a credential rotation — a symptom that reads as a security incident rather than a config error.
2. ⛔ **Ask the IdP, never the local clock.** The refresh is FORCED (`forcedRefresh`), not routed
   through `oauth2.TokenSource`'s expiry check, whose documented semantics return a still-valid
   token **with no network call**. Built on that, a "revalidation" would answer "still signed in"
   from a purely local check — the self-deceiving ping the design forbids, one that keeps the
   product session alive while the IdP session dies underneath it, WIDENING the divergence it was
   added to close. The mechanism is deliberate: a token with an empty `AccessToken` is never
   `Valid()`, so the refresh path is always taken.
3. ⚠️ **An unrevalidatable session is kept, not killed.** A session issued before token retention
   carries no refresh token, so there is no question to ask. Killing it would mean a library upgrade
   signs out everyone currently logged in. It is kept and expires on its own `Exp` — a bounded
   transition window of at most one `SessionTTL`.

### Added

- **`Config.RevalidateInterval`** (`time.Duration`, default 0 = off). ⛔ `New()` REFUSES it without
  `RetainTokens`, and refuses it at or above `SessionTTL`. Both refusals exist because the
  misconfiguration is invisible at every other layer: the config parses, `New()` succeeds, the pod
  boots, every login works, and the feature simply never runs. No log line and no metric
  distinguishes "revalidating every 5 minutes" from "revalidating never" — only the absence of a
  sign-out nobody was watching for.
- **`ErrSessionRevoked`** — the IdP's explicit verdict, deliberately distinct from
  `ErrTokenRefreshFailed` (which covers every refresh failure including transport errors).
- **`GET <mount>/session`** + **`SessionStatus`** — liveness for a hidden tab's ping and an SPA's
  401 trap. Always `Cache-Control: no-store`: a cached `authenticated: true` keeps a signed-out
  browser looking signed in for as long as the cache lives, reintroducing the exact divergence the
  endpoint detects. It carries no profile, no claims and no tokens — a liveness probe that leaks
  identity is an oracle for anything that can reach it. `revalidated_at` is the honest bound on the
  answer: liveness is only ever as fresh as the interval.
- **`sessionPayload.LastValidated`** — the anchor the floor is measured from. ⛔ A zero value is
  read as the session's ISSUE time (`Exp - SessionTTL`), never as the epoch: every session issued
  before this release carries zero, and reading those as "last validated in 1970" makes the floor
  overdue for all of them simultaneously, so the first request after a rolling upgrade fires a
  refresh grant for **every logged-in user at once**, against the IdP, at deploy time.

### Changed

- **`RequireSession` and `OptionalSession` both revalidate.** ⛔ Leaving it out of the OPTIONAL path
  would have been the more dangerous omission, not the safer one: that is the middleware every
  public-facing page runs under, so a signed-out person would keep being rendered as signed in —
  account menu, personalised chrome, "logged in as …" — across every product where they never
  navigated a gated route. A revoked session there simply becomes an anonymous request.
- **`SkipPathsWithPrefix` is now DERIVED from `SkipPaths`** instead of being a second hand-written
  copy. Adding `/session` is exactly the change that gets made in one list and forgotten in the
  other — and an auth route charonmw does not skip is an auth route nobody can reach, whose failure
  reads as a dead session rather than a blocked request. A new test walks the ACTUAL chi router and
  requires the two sets to match in both directions.
- **A successful login now records `LastValidated`.** The code exchange (and `IssueSession`'s
  alternate grant) IS an IdP interaction, so new sessions carry a recorded anchor rather than a
  derived one.

### Known limits, stated rather than discovered later

- ⚠️ **Concurrency on a realm that rotates refresh tokens.** Several requests arriving together
  after the floor elapses each perform their own grant. With `revokeRefreshToken = false` (this
  fleet's realm) that is harmless — the token is not single-use. With rotation ON, the losers of the
  race hold a token the winner invalidated and will fail their *next* revalidation with a spurious
  `invalid_grant`. The same hazard already existed in `AccessToken()`; this field makes it reachable
  on ordinary page loads rather than only on API-key minting.
- ⚠️ **`IssueSession` (ROPC) sessions stay unrevalidatable** — that entry point takes no refresh
  token, so the floor finds nothing to ask with and fails open for the cookie's whole life.
- ⚠️ **A fail-open backs the anchor off by 30s** rather than retrying on the next request. Without
  it, "retry next request" means "retry on EVERY request" against an IdP that is already unwell,
  with a failing network call added to every page load.
- ⚠️ **The refresh-token carry-forward guard in `maybeRevalidate` is currently unreachable and a
  mutation deleting it SURVIVES the suite** — verified, not assumed. `x/oauth2` already carries the
  previous refresh token forward when a refresh response omits one, so no test driving a real
  `TokenSource` can tell the two versions apart. It is kept deliberately; do not "simplify" it on
  the evidence that nothing goes red, because nothing can.

### Verification

Full suite green under `-race`. Six mutations applied and compile-verified; five caught:
fail-closed-on-any-`RetrieveError` (4 tests) · the lazy `TokenSource` refresh (11 tests) ·
zero-anchor-as-epoch (1) · revalidation dropped from `OptionalSession` (1) · `no-store` removed (1).
The sixth is the carry-forward guard recorded above.

## v0.18.0 — 2026-09-07

**Where a person lands when they log in.** Three defects, all of them invisible from the consumer's
side because the deciding line was inside this library. Pays **go-vai-oidc#3** and **obol#29**;
the landing decision needs **obol ≥ 3.185.0**, and everything else works against any obol.

Additive: a consumer that changes nothing behaves exactly as before, with one deliberate exception
noted at the end.

### 1 — a first-time human had two possible fates and neither was onboarding

`obolresolver` set `user.OrgID = memberships[0].org_id` — and obol serves that list ordered
`joined_at ASC`, so it is *the oldest membership*. For anyone who touched a sibling product first
that is an auto-minted personal workspace rather than the company they belong to. The only
alternative was `AllowEmptyMembership=false` rejecting the login to a logout page.

⛔ **THE ROOT CAUSE IS THAT A BRAND-NEW USER IS BYTE-INDISTINGUISHABLE FROM A RETURNING ONE.** obol
mints a `pending`, tierless personal organization for every authenticated subject with no
membership, so "no org" never arrives — and three consumer services each wrote a fail-closed
"no org ⇒ reject the login" path that is therefore **dead code**, while the human those paths were
written for sails into the product UI on an unfunded placeholder.

obol now serves a **decision** on the same response: `onboarding` · `org_selection` · `ready`, plus
an absolute URL it computes. `User.Landing` carries it; `Landing.RedirectTarget()` decides;
`handleCallback` acts on it. Nil means the backend expressed no opinion (an older obol, a custom
resolver, none at all) and the callback behaves exactly as before.

⚠️ **`OrgID` IS STILL FILLED IN EVERY ARM, INCLUDING `org_selection`, AND REMOVING THAT IS THE MOST
TEMPTING WRONG CHANGE.** obol fills it beside the decision on purpose: several services in that
fleet read an **empty org id as *all tenants***, so a consumer that ignores `landing` must degrade
to the previous behaviour and never to a cross-tenant read. It is also what lets the fleet adopt
this in any order.

⚠️ **The landing URL is NOT passed through `isValidRedirect`, and that split is the security
argument.** `isValidRedirect` enforces a same-origin *relative path* because the value it guards
comes from the **browser** (`/auth/login?redirect=…`). A landing URL is the opposite kind of value —
absolute and cross-origin by construction, from an authenticated server-to-server response — so
that helper would reject every correct one. It is admitted instead by `obolresolver`, the only
component that knows which backend it is talking to: an absolute `http`/`https` URL with a host and
no embedded credentials, optionally pinned by `AllowedLandingHosts`. A rejected URL does **not**
reject the login; the decision still reaches the consumer and the login finishes where it would
have.

⚠️ **`AllowedLandingHosts` must NOT default to `BaseURL`'s host, which is the obvious tightening and
is wrong.** `BaseURL` is how a service *dials* obol and is routinely cluster-internal; the landing
URL is the *public* address a browser must reach. A same-host rule would reject every correct URL
and the failure would look like obol not serving a decision at all.

### 2 — every successful login went to a hard-coded `/`

`target := "/"` with no config field. Two surveyed consumers were broken by it in two different
ways: one serves its UI under a prefix and registers nothing at `/`, so **every successful login
answered 404**; the other serves a public marketing site at `/`, so every signed-in administrator
landed on the **marketing homepage** — the more dangerous shape, because nothing looks broken and
nobody files a bug. Neither could fix it from its own side.

New `Config.PostLoginRedirect`, defaulting to `/` so the change is additive, validated at `New()`
rather than at the end of somebody's login.

### 3 — `RequireSession` discarded every deep link

A signed-out browser request to a gated page is turned into a login in exactly one place — this
middleware's refusal — and it redirected to a **static** `LoginPath`. So a shared admin URL, a
bookmarked report or a link in a ticket sent the person to the login screen and then to the service
root, and no consumer could repair it because the wanted path exists only inside this function. It
now carries `?redirect=<the request's own URI>`, which is same-origin by construction, and
`handleLogin` re-validates it as it always did.

⚠️ **`appendQueryParam` and not string concatenation.** Both surveyed consumers use
`/auth/login?kc_idp_hint=google`, so a naive join produces a second `?` and **loses the IdP hint** —
downgrading a Google-federated login to Keycloak's own password form.

### Also

- **A version header on the `obolresolver` request** (`X-Obol-Client-Version: go-vai-oidc/0.18.0`).
  ⚠️ **This is the only place a named measurement gap could be closed.** obol counts which client
  contract each consumer runs, and that rail had an irreducible `absent` floor *because this module
  hand-builds its request and carried no version header on any released version* — so a share of it
  belonged to a shared dependency no consumer could fix by pinning a newer obol SDK. Measured on the
  dev cluster beforehand: one service read `identity.write` 1,329 against `absent` 1,672.
  `TestClientVersionMatchesTheManifest` keeps the string in step with `versions.yaml`, because a
  version that drifts is worse than none — obol bounds it against the contract it ships, so a stale
  value reads as a *different, older consumer* rather than as unknown.
- **A cross-origin return-to** (`?consumer_return_to=`) on the landing URL, built from
  `CallbackURL` rather than from the request, because a request-derived scheme is wrong behind a
  TLS-terminating proxy. ⚠️ It is deliberately **not** named `return_to`: that is a same-origin
  convention in these products (obol's own login screen refuses a non-relative value on it), and
  handing it a cross-origin absolute URL would be silently dropped at best and an open redirect the
  first time somebody widened the reader. **Nothing honours it yet** — it is recorded here because
  this is the only moment a consumer knows both its own origin and where the person was heading.
- **`TestSessionCarriesEveryUserFieldOrLedgersWhyNot`**, a guard for a defect this repository has
  already shipped: v0.14.0 added `User.Memberships` and a hand-rolled `sessionPayload` literal
  silently dropped it, leaving multi-org consumers with no picker. The fix at the time was a
  **comment** warning the next person, and a comment cannot fail a build. `Landing` is its first
  ledgered omission — deliberately not persisted, because a verdict about one login goes stale the
  moment the person acts on it.

### The one behaviour change

`RequireSession`'s browser refusal now redirects to `LoginPath` **with** `?redirect=…` instead of
bare. A consumer that pattern-matches that Location exactly will see the difference; nothing else
does.

## v0.17.0 — 2026-08-21

**A session user carries the teams it belongs to.** Fully additive and backward-compatible:
a resolver that supplies no teams leaves every new field nil and existing consumers are
unaffected. Pays **atlas#248**; needs **obol ≥ 3.114.0**, which emits the field.

### The gap this closes, and why it was not what the record said

⛔ **THREE SHIPPED FEATURES GOVERN NOTHING BECAUSE A DELEGATED IDENTITY ARRIVES WITH NO TEAMS** —
trove's coffer team narrowing, mediagen's EU-residency team tier, and conduit's ReBaC-via-teams
all read the forwarded identity's team ids, and nothing upstream of them had any to give.

⚠ **THE RECORDED BLOCKER WAS STALE.** It read as "the source of truth holds no teams, so adding a
field ships an always-empty one". Measured: obol has a real team subsystem — rows, an active-only
query, and a per-user read (obol#15, **closed**) — and the identity channel used for API-key/S2S
resolution has been returning populated team ids all along. What had never been extended was the
one endpoint the browser-session path actually calls, `/identity/ensure`.

⚠ **AND charonmw ALREADY CARRIES THE FIELD END TO END** — `Identity.TeamIDs`, the `ctx`/`dlg` S2S
claims, the signer, and the receiver-side extraction. Nothing needed adding to the wire; it has
had the field and nothing to put in it.

### Added

- **`Membership.TeamIDs`** — the user's active teams within **that** org. ⚠ Teams are per-org and
  the field sits on the membership for that reason: a multi-org user has a different team set in
  each org.
- **`User.TeamIDsForOrg(orgID)`** — the pairing, derived once. ⚠ Its callers build a delegated
  identity for a downstream service, so a team id paired with the wrong org is **a grant in an org
  the user did not act in**, not a cosmetic mix-up. Revert-checked against the realistic wrong
  implementation (return the first membership's teams): that mutation hands org-beta org-alpha's
  teams and the guard catches it.
- **`obolresolver`** decodes obol's per-membership `team_ids` and maps it through.

### Compatibility

⚠ **nil IS NOT "this user is in no team".** An older obol emits no key at all and decodes to the
same nil as a genuinely teamless user; a caller that must tell those apart has to ask the
directory, not the session. Obol emits the field unconditionally from the release that adds it, so
the ambiguity is bounded to the version skew. A control test pins that a payload with no `team_ids`
still resolves.

⚠ **Sessions minted before this release carry no teams until the user logs in again** — the
resolver runs at session establishment, not per request.

### Fixed

- `versions.yaml` said **0.15.1** on the commit tagged **v0.16.0**. Metadata-only (nothing in Go
  reads it here), but it is the file the house rules call the single source of version truth.

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
