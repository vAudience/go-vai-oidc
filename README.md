# go-vai-oidc

A generic Go **OIDC Relying Party** — drop-in browser login (OpenID Connect authorization-code
flow + PKCE) with encrypted, stateless session cookies. First-class **Keycloak** convenience, but
works with **any** spec-compliant OIDC provider (Google, Okta, Auth0, Microsoft Entra, Authentik,
Dex, …).

- **Any provider** — point it at an issuer URL; discovery does the rest.
- **Stateless** — the verified user lives in an AES-256-GCM-encrypted cookie. No database, no Redis,
  no server-side session store. Optionally revalidated against the provider on a floor
  (`RevalidateInterval`) so a sign-out elsewhere propagates, and optionally reconciled against the
  browser's own provider session (`SessionSyncEnabled`) so signing in as somebody else is noticed —
  still with no store.
- **Small surface** — `New()`, mount `Routes()`, protect handlers with `RequireSession()`, read the
  user with `UserFromContext()`.
- **Pluggable identity** — an optional `UserResolver` callback runs at login to enrich the user
  (resolve an org/tenant, reject disallowed identities, etc.).

```go
import vaioidc "github.com/vAudience/go-vai-oidc"
```

## Quick start (any OIDC provider)

```go
auth, err := vaioidc.New(ctx, vaioidc.Config{
    // Generic issuer — discovery hits IssuerURL + "/.well-known/openid-configuration".
    IssuerURL:     "https://accounts.google.com",
    ClientID:      "your-client-id",
    ClientSecret:  "your-client-secret",
    CallbackURL:   "https://app.example.com/auth/callback",
    SessionSecret: os.Getenv("SESSION_SECRET"), // base64-encoded 32 bytes: openssl rand -base64 32
})
if err != nil {
    log.Fatal(err)
}

r := chi.NewRouter()
r.Mount("/auth", auth.Routes()) // GET /auth/login, /auth/callback, GET|POST /auth/logout

r.Get("/", handleLanding) // public

r.Group(func(r chi.Router) {
    r.Use(auth.RequireSession()) // redirects to /auth/login when no valid session
    r.Get("/dashboard", handleDashboard)
})
```

Read the authenticated user in any protected handler:

```go
func handleDashboard(w http.ResponseWriter, r *http.Request) {
    user := vaioidc.UserFromContext(r.Context())
    fmt.Fprintf(w, "Hello, %s (%s)", user.Name, user.Email)
}
```

## Keycloak convenience path

If you run Keycloak, set `KeycloakURL` + `Realm` instead of `IssuerURL` — the issuer is composed as
`<KeycloakURL>/realms/<Realm>`:

```go
auth, err := vaioidc.New(ctx, vaioidc.Config{
    KeycloakURL:   "https://keycloak.example.com",
    Realm:         "acme",
    ClientID:      "your-client-id",
    ClientSecret:  "your-client-secret",
    CallbackURL:   "https://app.example.com/auth/callback",
    SessionSecret: os.Getenv("SESSION_SECRET"),
})
```

**Exactly one** discovery source is required: either `IssuerURL`, or `KeycloakURL` + `Realm`. When
`IssuerURL` is set, `KeycloakURL`/`Realm` are ignored.

Keycloak also gives you SSO for free — once a user has logged into any client on the realm, the
authorize step skips the login page and redirects straight back.

## How it works

```
Browser → GET /auth/login
       → OIDC provider (authorization-code flow + PKCE, state cookie)
       → GET /auth/callback
            1. Verify ID token (signature + iss + aud) via coreos/go-oidc
            2. Extract user: Sub, Email, EmailVerified, Name, RealmRoles, ExtraClaims
               (optional) RequireEmailVerified, then RequireEmailDomain — refuse the login
            3. (optional) UserResolver — enrich/reject (resolve org, gate domain, …)
            4. Encrypt session cookie (AES-256-GCM): Sub, Email, Name, OrgID, Memberships, Claims
       → redirect to the post-login target
       → RequireSession middleware decrypts the cookie → *User in the request context
```

The session cookie is `HttpOnly`, `Secure` (unless `InsecureCookie`), `SameSite=Lax`, and encrypted
with a per-service AES-256 key. It is self-contained — no round-trip to the provider on each request.

## Sign-out propagation (v0.19.0)

By default a product session is an **independent copy** of an authentication that happened once:
`RequireSession` decrypts the cookie, checks its expiry, and never re-contacts the provider. Signing
out of one service terminates the provider's SSO session and clears that service's own cookie —
and every **sibling** service keeps serving the same person with full access until its own cookie
expires, up to `SessionTTL`, with every health signal green.

`RevalidateInterval` closes that. On a request whose session has gone longer than the interval
without being validated, the library performs a `refresh_token` grant. Keycloak invalidates refresh
tokens bound to an SSO session when that session ends, so an explicit `invalid_grant` **is** the
signal that the person signed out elsewhere.

```go
cfg.RetainTokens = true            // required: revalidation needs the refresh token
cfg.RevalidateInterval = 5 * time.Minute
```

Three things follow, and only the first is the headline:

1. **Sign-out propagates** within one interval.
2. **The session becomes sliding.** Before v0.19.0 the cookie's expiry was absolute — set once at
   login and never moved. A successful revalidation re-stamps it, so an active client keeps its
   session and an abandoned one does not.
3. **The provider's session stays alive too.** A successful refresh is a provider interaction, so it
   resets the provider's idle timeout. That is what stops the two clocks running independently.

**The absolute ceiling is not a value here** — it is the realm's `ssoSessionMaxLifespan`. Past it a
refresh grant fails regardless of what this library believes, and the failure arrives on the same
`invalid_grant` path.

### `GET <mount>/session`

Registered by `Routes()` and returned by `SkipPaths()`. It runs the same revalidation and answers
`{"authenticated": …}` — 200 when live, 401 when not, always `Cache-Control: no-store`. It is what a
hidden browser tab pings so a sign-out in a sibling product reaches this one, and what an SPA's 401
trap consults. `revalidated_at` is the honest bound on the answer: liveness is only ever as fresh as
the interval.

### Three things to get right before enabling it

- ⛔ **Only `invalid_grant` signs the user out.** A transport error, a 5xx, or any other OAuth2 error
  code fails **open** and is logged. This matters more than the feature itself: treating those as a
  sign-out turns one provider blip — or one rotated client secret, which answers `invalid_client` —
  into a synchronized fleet-wide logout.
- ⚠️ **Do not enable this against a realm that rotates refresh tokens** without addressing
  concurrency first. Several requests arriving together after the interval elapses each perform
  their own grant; with rotation on, the losers hold a token the winner invalidated and will fail
  their *next* revalidation with a spurious `invalid_grant`. With `revokeRefreshToken = false` it is
  harmless.
- ⚠️ **Sessions issued before retention was enabled carry no refresh token** and therefore fail open
  until they expire — a bounded transition window of at most one `SessionTTL`. Killing them instead
  would mean a library upgrade signs out everyone currently logged in.

### Re-resolution on revalidation (v0.25.0, opt-in)

`UserResolver` runs at the login callback, and revalidation alone never re-asks it — so a
session's `OrgID`, `Memberships`, role and resolver-set claims stay what they were at login for the
whole SSO session, and a person demoted or removed in the identity backend keeps the login-time
answer. `ReresolveOnRevalidate` closes that:

```go
cfg.RevalidateInterval = 5 * time.Minute
cfg.UserResolver = obolresolver.New(…)
cfg.ReresolveOnRevalidate = true
```

After every **successful** refresh grant the identity is rebuilt — from the refreshed ID token when
the provider returned one (verified exactly as at login, and only if it names the same subject),
otherwise from the identity stored in the session, stripped of everything a resolver sets — and
passed through the same function the login callback uses: `RequireEmailVerified`, then
`RequireEmailDomain`, then `UserResolver`. The answer is applied like this:

| The answer | At login | On revalidation |
| --- | --- | --- |
| a `User` with an org | session stored with it | **replaces** `OrgID`, `Memberships`, `Claims`, `RealmRoles`, …; cookie re-stamped. An `OrgID` picked after login is kept while it is still a membership |
| a `User` with no org, no redirecting `Landing` | org-less session stored | applied as-is (org-less) |
| a `User` with no org and a redirecting `Landing` | browser sent to the funnel | **session ended** — revalidation cannot navigate; the next login lands in the funnel |
| `(nil, nil)`, or a login gate refuses | login refused | **session ended** (cookies cleared, request treated as signed out) |
| an **error** | login refused | ⛔ **fail open**: old fields kept, WARN logged, refreshed tokens persisted, `Exp` not slid, next attempt backed off as for a provider outage |

- ⛔ **An error is the backend failing to answer, not answering "no".** Ending sessions on it would
  turn one identity-backend blip into a fleet-wide logout — the same reasoning that makes only
  `invalid_grant` sign anyone out. Because `Exp` does not slide on this arm, a resolver outage longer
  than `SessionTTL` still ends the session on its own expiry.
- ⚠️ **The login gates re-run too**, on the same input, so a gate that would refuse the login ends
  the session. Pre-v0.24.0 cookies have `email_verified` false; with `RequireEmailVerified` on, the
  gate reads the refreshed ID token when there is one, so this bites only on providers that return
  no `id_token` from a refresh.
- ⚠️ **It puts one resolver call per session per interval on an ordinary request.** Size the interval
  against the identity backend as well as the provider.

## Identity sync (v0.20.0) — the half revalidation cannot do

`RevalidateInterval` above answers **liveness**: *is the session this cookie was minted from still
alive?* It cannot answer **identity**: *who is signed in to this browser right now?* — and the
difference is not academic:

> Sign in as A on one product. Then sign in as B at the provider. The first product **keeps serving
> A**, with revalidation enabled, passing, and correct.

The refresh grant is bound to A's SSO session. Signing in as B mints a **new** session and swaps the
browser's identity cookie; it does not terminate A's, which survives to its own idle timeout. So the
grant asks *"is A alive?"*, the provider truthfully answers *"yes"*, and the refreshed tokens come
back carrying A's `sub`. ⛔ **No interval fixes this.** Polling faster asks the same question more
often and gets the same answer — the axis is the *question*, not the frequency.

Only a request that travels through the **browser** carries the browser's provider cookie. That is
what `SessionSyncEnabled` adds:

```go
cfg.SessionSyncEnabled = true   // enables GET <mount>/session/sync
```

`GET <mount>/session/sync` performs an authorization request with `prompt=none` — the provider
answers from the browser's current SSO session or refuses explicitly, and never renders a login
form — then compares the returned `sid`/`sub` with this product's own session and reports one of:

| Result | Meaning | Session |
|---|---|---|
| `unchanged` | same person, same sign-in | re-stamped (slides, like a revalidation) |
| `switched` | a **different** identity, or the same person in a new sign-in | **cleared** |
| `signed_out` | the provider has no session in this browser | **cleared** |
| `no_session` | this product had no session to reconcile | untouched |
| `disabled` | `SessionSyncEnabled` is false | untouched |
| `error` | no verdict could be reached | untouched (**fails open**) |
| `not_applicable` | (v0.22.0) the session was minted by `IssueSession` (inline / ROPC login) and the browser holds no provider session — it never had one to lose | untouched |

⭐ **It requires nothing of the realm.** The silent request reuses this consumer's already-registered
`CallbackURL`, so there is no new `redirectUris` entry, no client change and no migration.

### Wiring it in the browser (v0.21.0 — one script tag)

⭐ **The library serves the client script.** Point a `<script>` tag at your own auth mount and you
are done:

```html
<script defer src="/auth/session/sync.js"></script>
```

Compose that path from `vaioidc.SessionSyncScriptSuffix` rather than typing it, and the route and
the tag cannot drift apart. The script derives both of its endpoints from the path it was served
at, so it is correct at **any** mount prefix without being told what that prefix is.

It runs on **focus**, on **visibilitychange**, and on a slow timer — the timer is an ADDITION, never
the primary signal, because browsers throttle background timers. It also exposes
`window.vaioidcSessionSync()` so an API client's 401 trap can reconcile before navigating to login.

On `switched` or `signed_out` it calls `location.reload()`: the session cookie is already gone
server-side, so the reload renders the product's own signed-out state. ⛔ It deliberately does **not**
navigate to `/auth/login` on `switched` — that silently adopts the new identity, which is exactly
the surprise this reports instead of performing. On `disabled` it stops permanently, because that is
the server truthfully saying this deployment did not opt in. On `not_applicable` (v0.22.0) it does
nothing and keeps its schedule, exactly as on `unchanged` — it neither reloads nor stops, because a
provider session that later appears for a different person is still worth a `switched`.

⭐ **If the frame is blocked, the script says so to your server.** After three consecutive runs that
reach no verdict it stops and `POST`s to `<mount>/session/sync/blocked`, which logs one WARN naming
what to check. That is the ONLY server-side signal any browser-side failure of this feature has —
see the two CSP facts below for why it is needed. (The report requires a session, so it cannot be
used to flood your logs, and it always answers 204 so it cannot be used to probe cookie validity.)

⚠️ It assumes the browser-visible path equals the server-visible path. That is true unless a proxy
strips your mount prefix; if one does, serve your own copy instead.

<details>
<summary>Writing your own client instead (pre-v0.21.0, or behind a path-stripping proxy)</summary>

The endpoint is loaded in a hidden **same-origin** iframe and reports its verdict twice — a
`postMessage` to `window.parent`, and `<html data-vaioidc-sync-result="…">` as a fallback for a
consumer whose middleware overwrites `Content-Security-Policy` (which would strip the inline script
*silently*, because a CSP violation is reported to a browser console and nowhere else).

```js
function vaiSessionSync() {
  const f = document.createElement("iframe");
  f.hidden = true;
  f.src = "/auth/session/sync";
  const done = (result) => {
    f.remove();
    if (result === "switched" || result === "signed_out") location.reload();
  };
  const onMsg = (e) => {
    if (e.origin !== location.origin) return;              // same-origin only
    if (e.data?.source !== "vaioidc" || e.data?.type !== "session-sync") return;
    window.removeEventListener("message", onMsg);
    done(e.data.result);
  };
  window.addEventListener("message", onMsg);
  f.onload = () => {                                        // fallback path
    try { done(f.contentDocument.documentElement.dataset.vaioidcSyncResult); }
    catch { /* still mid-flight on the provider's origin */ }
  };
  document.body.appendChild(f);
}

window.addEventListener("focus", vaiSessionSync);
setInterval(vaiSessionSync, 5 * 60 * 1000);
```

</details>

### ⛔ Two CSP facts that will otherwise make this fail silently

The sync document overrules a consumer-wide `X-Frame-Options: DENY` (it sets `SAMEORIGIN` on its
own response) and serves its own `Content-Security-Policy` with a per-response nonce. **Neither of
those can fix the parent page's policy, and the parent page has one job:**

- ⛔ **Your CSP needs `frame-src 'self' https://<your-provider-origin>`.** The iframe starts
  same-origin, but it *navigates to the provider and back*, and CSP checks every navigation in the
  frame. With no `frame-src`, `default-src 'self'` applies and the provider hop is **blocked**.
  ⭐ Use **`auth.AuthorizationOrigin()`** (v0.20.2) for that value — never the `KeycloakURL` you
  configured. Where services reach the provider through a cluster-internal name while the provider
  stamps public URLs into its own discovery document, the configured URL names a host the browser
  never visits, and the resulting CSP blocks the frame with every server-side signal green. An empty
  return means "do not enable session sync", never "no restriction needed".
- ⚠️ **A blocked frame reports to a browser console and nowhere else.** There is no server-side
  signal, no 4xx, no log line: sync would simply never report, on every page, with every health
  check green. Verify in a real browser with the console open, once, per product.

### Sessions minted by `IssueSession` (inline / ROPC login) — v0.22.0

`IssueSession` mints a session from a credential exchange the consumer performed **server-side**
(most commonly ROPC behind an inline login form). The browser therefore holds **no provider SSO
cookie**, by construction, and `prompt=none` answers `login_required` every time. ⛔ Before v0.22.0
sync read that as `signed_out` and cleared every inline-login session on the first focus — enabling
sync on a deployment with inline login signed all of those users out.

Since v0.22.0 such a session is marked in its (encrypted) payload and sync treats it this way:

- **No provider session in the browser** → `not_applicable`; the session is untouched. This is
  consistent with revalidation, which already fails open for these sessions (they carry no refresh
  token).
- **The browser IS signed in to the provider as a different `sub`** → `switched`; the session is
  cleared. Somebody else signing in at this browser is real evidence whatever minted the session.
- **The browser is signed in as the same `sub`** → `unchanged`; the session slides, but it is
  compared on `sub` only (its `sid` names a server-side session the browser never joined) and it
  does **not** adopt the browser's tokens or `sid` — it stays a grant-minted session.

Nothing to configure. ⚠️ Cookies minted before v0.22.0 carry no marker and behave exactly as before
— so an inline-login cookie issued by an older build is still signed out by sync until its holder
signs in again. Bump the pin before (or together with) enabling `SessionSyncEnabled`.

### Three things to get right before enabling it

- ⛔ **Only `login_required` and its siblings sign the user out.** `interaction_required`,
  `consent_required` and `account_selection_required` join it; everything else — a transport
  failure, a 5xx, `invalid_client` from a rotated secret, a state mismatch — fails **open**. The
  classification is what stops this mechanism from logging out every product at once.
- ⛔ **An absent `sid` is not a mismatch.** Sessions minted before v0.20.0 carry none, and treating
  absent as different would sign out every logged-in user on the first sync after an upgrade. The
  comparison degrades to `sub` and the session records its `sid` on that first sync.
- ⚠️ **Enable it alongside `RevalidateInterval`, not instead of it.** Sync needs a live browser, so
  it does nothing for a closed tab or for API traffic; the revalidation floor is the only half that
  covers those. They answer different questions.

## The User

```go
type User struct {
    Sub         string            // subject claim — stable user identifier; use as a foreign key
    Email       string            // email claim (may be empty if scope not granted)
    EmailVerified bool            // email_verified claim (v0.24.0); false when absent — never inferred
    Name        string            // name claim (may be empty)
    OrgID       string            // set by your UserResolver (empty otherwise)
    Memberships []Membership       // set by your UserResolver (multi-org/tenant support)
    Claims      map[string]string // extra claims requested via Config.ExtraClaims
    RealmRoles  []string          // Keycloak realm_access.roles; nil for non-Keycloak providers
    Landing     *Landing          // the identity backend's post-login routing DECISION (v0.18.0)
    AuthTime    time.Time         // id_token auth_time (v0.28.0); zero = unknown; a refresh never advances it
}
```

### `Landing` — where this person should be sent (v0.18.0)

```go
type Landing struct {
    Decision string // "onboarding" | "org_selection" | "closed_beta" (v0.23.0) | "ready"
    URL      string // ABSOLUTE, on the identity backend's origin; empty on "ready"
}

if target, ok := user.Landing.RedirectTarget(); ok {
    http.Redirect(w, r, target, http.StatusFound)   // handleCallback already does this for you
}
```

`obolresolver` populates it from obol ≥ 3.185.0 and `handleCallback` acts on it automatically, so
most consumers need no code at all — only a dependency bump.

⚠️ **`nil` means the backend expressed no opinion, which is NOT the same as `ready`.** An older
backend, a custom resolver or no resolver leaves it nil, and the callback then behaves exactly as it
did before this field existed.

⚠️ **It is a DECISION, not a pair of facts, and re-deriving it is the defect it exists to close.**
The backend deliberately does not publish "is this user new" and "how many orgs" for each consumer
to route on: a fleet survey found five surfaces deriving one rule five different ways, two of which
pinned a person to an auto-minted personal workspace with no way off it.

⚠️ **`OrgID` keeps being filled in every arm, including `org_selection`.** A consumer that ignores
`Landing` degrades to the previous behaviour — never to an empty org id, which several services read
as *all tenants*.

⚠️ **`closed_beta` (v0.23.0) redirects like `onboarding`, and to a PUBLIC page.** It is served where
`onboarding` would be — a verified person with no real organization — on a deployment not admitting
new companies, so `memberships` is empty and `OrgID` is empty on that arm by construction. Below
v0.23.0 the decision was "unknown", the login finished org-less on the consumer's own destination,
and the consumer then refused the person without saying why. `vaioidc.LandingDecisionRedirects` is
the one list of redirecting decisions; `RedirectTarget` and `obolresolver`'s URL admission both read
it.

⛔ **An empty membership set is admitted only when the landing will actually redirect (v0.23.1).**
A landing whose URL `obolresolver` refused, or whose decision never redirects (`ready`, an unknown
value), cannot be followed, so it decides nothing: `AllowEmptyMembership` decides as before v0.18.0,
and with the strict default the login is rejected. Before v0.23.1 such a login finished org-less on
the consumer's own destination — an empty `OrgID`, which several services read as *all tenants*.

⚠️ **It is not persisted in the session, deliberately.** It is a verdict about one login, so a
session copy goes stale the moment the person acts on it.

`RealmRoles` is a Keycloak convenience: for any other provider the `realm_access` claim is simply
absent and the slice is nil (not an error). Check membership with `user.HasRealmRole("some-role")`.

## Step-up (recent authentication) — v0.28.0

A live session proves the person is *still* signed in; it does not prove they *recently* proved who
they are. A write that must not be performed from a browser left unlocked (a platform credential, a
payout target) asks for a fresh authentication:

```go
const stepUpWindow = 5 * time.Minute

func (h *Handler) putPlatformCredential(w http.ResponseWriter, r *http.Request) {
    u := vaioidc.UserFromContext(r.Context())
    if !vaioidc.RecentlyAuthenticated(u, stepUpWindow, time.Now()) {
        stepUp, err := h.auth.StepUpLoginURL("/console/credentials") // same-origin path only
        if err != nil { /* ErrInvalidReturnPath: a bug in your return path */ }
        writeJSON(w, http.StatusUnauthorized, map[string]any{
            "error": "step_up_required", "step_up_url": stepUp,
        })
        return
    }
    // ... perform the write
}
```

The SPA answers that 401 with a **full-page navigation** — `window.location.assign(body.step_up_url)`,
never an XHR/fetch (it is a redirect chain through the provider's login page) — and the callback
returns the browser to the path it named, where the person repeats the action.

- **`/auth/login?max_age=N`** forwards `max_age` to the authorization request (OIDC Core §3.1.2.1);
  `StepUpLoginURL` builds `<LoginPath>?max_age=0&redirect=<path>`, and `max_age=0` forces
  re-authentication. `N` must be a plain non-negative integer of seconds (≤ 2147483647, at most 10
  digits); anything else is **refused with 400**, never dropped — dropping it would silently turn a
  step-up into an ordinary login.
- **The callback verifies `auth_time`** when `max_age` was requested (§3.1.3.7): the claim is then
  REQUIRED and must not predate the login's start by more than `max_age` + `AuthTimeSkew` (30 s).
  A failure is refused like any other callback failure (redirect to `LogoutRedirect`, no session,
  resolver not called).
- **`User.AuthTime`** is the verified ID token's `auth_time`, persisted in the session. ⛔ **A
  revalidation refresh never advances it** — a refresh is not an authentication; a refreshed ID
  token's value is adopted only to fill an unknown or to move it *earlier*. `UpdateSession` and a
  `UserResolver` cannot move it either.
- ⚠️ **A session minted before v0.28.0 carries a zero `AuthTime`**, so `RecentlyAuthenticated` is
  false for it until the person signs in again — the fail-closed direction; the first step-up after an
  upgrade simply asks for a login.
- ⚠️ **The door's check is the guard; the callback's is defence in depth.** `AuthTime` comes only from
  a signature-verified ID token, so nothing a browser does to the `max_age` marker cookie can make an
  old authentication look recent.
- Keycloak needs no realm setting: it honours `max_age` and issues `auth_time` whenever it is
  requested. `IssueSession` (ROPC) records whatever `AuthTime` the caller's `User` carries —
  `VerifyIDToken` fills it from the token.

## Staff surfaces — `RequireStaff` and the ONE staff predicate (v0.24.0)

Every staff admin surface (obol `/console`, the vaisite admin, the conduit admin) gates on the same
rule, operator ruling D2 (2026-09-28). It ships here once so three repositories do not each
hand-roll a security predicate:

```
session AND email_verified AND the parsed email's domain == "vaudience.ai"
        AND (realm role "obol-system-admin" OR realm role "vai-business-manager")
```

```go
admin := chi.NewRouter()
admin.Use(auth.RequireStaff(vaioidc.VAIStaffPolicy())) // includes RequireSession — do not stack it
admin.Get("/", consoleHome)
r.Mount("/console", admin)

// Outside HTTP middleware (a template deciding whether to render an admin link):
if user.IsStaff(vaioidc.VAIStaffPolicy()) { … }
```

| Request | Answer |
|---|---|
| no / expired / revoked session | exactly `RequireSession`'s answer: browser → login redirect with the deep link, API → 401 |
| session, `email_verified` not true | 403 `{"error":"staff access required"}` (or `StaffPolicy.Forbidden`) |
| session, verified, domain ≠ `vaudience.ai` (incl. `evilvaudience.ai`, `x.vaudience.ai`, a display-name form, anything `net/mail` cannot parse as a bare address) | 403 |
| session, verified, in domain, none of the roles | 403 |
| all of the above hold | next handler |

- `StaffPolicy.Check(user)` returns `nil` or an error wrapping `ErrNotStaff` plus the cause
  (`ErrEmailNotVerified`, `ErrEmailClaimMissing`, `ErrEmailDomainMismatch`, `ErrStaffRoleMissing`).
  Every refusal logs `staff gate refused request` with a stable `staff_reason`.
- ⛔ An invalid policy (no domain, no roles) is logged at ERROR when the middleware is built and then
  **refuses everyone** — a misconfigured admin surface is closed, never open.
- ⚠️ Roles and `email_verified` are read from the SESSION, captured at login. A role revoked in
  Keycloak takes effect at the person's next login (or when revalidation ends the SSO session).
- ⚠️ A session cookie minted before v0.24.0 carries no `email_verified` and therefore fails the staff
  gate until the person signs in again. That is the intended, fail-closed upgrade behaviour.
- Realm prerequisites (true for realm `vaudience`): the `email verified` and `realm roles` mappers
  add their claims to the **ID token**, and the realm has `verifyEmail: true`.

For a login-time gate (refuse the login itself rather than a route), set
`RequireEmailVerified: true` alongside `RequireEmailDomain`.

## Mounting under a path prefix (the portal: `app.<base>/<product>/`)

Under the portal every product is served from one origin at its own path. There is **one seam**,
the mount prefix, and every path-bearing field must carry it. For a product at `/deepr`:

```go
auth, err := vaioidc.New(ctx, vaioidc.Config{
    CallbackURL:       "https://app.vai.team/deepr/auth/callback", // ⇒ the redirect_uri, byte-for-byte
    LoginPath:         "/deepr/auth/login",
    PostLoginRedirect: "/deepr/",
    LogoutRedirect:    "https://app.vai.team/deepr/",               // ⇒ post_logout_redirect_uri
    CookiePath:        "/deepr",                                    // session AND the state/PKCE cookies
    CookieName:        "deepr_session",                             // unique per product on the origin
    // …
})
r.Mount("/deepr/auth", auth.Routes())
skip := auth.SkipPathsWithPrefix("/deepr/auth")
```

- **The `redirect_uri` the IdP sees is `CallbackURL` exactly** —
  `https://app.<base>/<product>/auth/callback`. It must be in the realm client's *Valid redirect
  URIs*, and `LogoutRedirect` in its *Valid post logout redirect URIs*. A mismatch fails **at
  Keycloak** (`Invalid parameter: redirect_uri`), on a page the product cannot improve, so register
  both before the first deploy.
- **`CookiePath` scopes the state and PKCE cookies too**, so it must be a prefix of the callback
  path, or the callback arrives without them and every login ends at `LogoutRedirect`.
- **`CookieName` must differ per product.** One origin, many products: two products sharing a name
  (and a `CookiePath` of `/`) overwrite each other's session. Do not set a cookie `Domain`; the
  one-origin model depends on host-only cookies.
- ⛔ **Do not let the reverse proxy strip the prefix.** `RequireSession` builds the post-login deep
  link from the request's own path, and `session/sync.js` derives its endpoints from the path it was
  served at — both lose `/deepr` if the upstream sees `/…` and send the browser to the wrong product.
  Serve the application under the prefix end to end.

## UserResolver — enrich or reject at login

`UserResolver` runs during the callback, after the ID token is verified and before the cookie is
written. Return the enriched user, or a non-nil error to reject the login.

```go
type UserResolver func(ctx context.Context, user *User) (*User, error)

cfg.UserResolver = func(ctx context.Context, user *vaioidc.User) (*vaioidc.User, error) {
    // e.g. look the user up in your own system and assign an org/tenant:
    org, err := myDirectory.EnsureUser(ctx, user.Sub, user.Email)
    if err != nil {
        return nil, err // login rejected
    }
    user.OrgID = org.ID
    return user, nil
}
```

For multi-org users, populate `user.Memberships` and leave `OrgID` empty; render a picker post-login
and commit the choice with `auth.UpdateSession(w, r, func(u *User){ u.OrgID = chosen })`.

By default the resolver runs **only here**, so its answer is frozen for the life of the session; set
`ReresolveOnRevalidate` to re-ask it on every successful revalidation (see
"Re-resolution on revalidation" above).

**vAudience note:** `obolresolver/` is an optional reference `UserResolver` adapter that resolves
identities against the Obol billing service. It is a vendor-specific example — generic consumers do
not import it, and it adds no dependency to the root package. Use it as a template for your own.

## Forwarding the user's access token (optional)

By default the library keeps only the `id_token` (for logout) and discards the OAuth2
access/refresh tokens. Set `RetainTokens: true` to store them in the encrypted session, then call
`AccessToken(w, r)` to get a currently-valid access token (transparently refreshed when expired):

```go
token, err := auth.AccessToken(w, r) // ErrTokensNotRetained / ErrTokenRefreshFailed on failure
if err != nil {
    http.Error(w, "re-authentication required", http.StatusUnauthorized)
    return
}
req.Header.Set("Authorization", "Bearer "+token)
```

Retaining both tokens adds ~2–4 KB to the cookie (the library warns when a written cookie approaches
the ~4 KB browser limit; sessions are transparently chunked across cookies when needed). For refresh
that survives the provider's SSO logout, add `"offline_access"` to `Scopes`.

## Extra claims

```go
cfg.ExtraClaims = []string{"tenant_id", "department"} // extracted into User.Claims
// non-string claim values are JSON-serialized into the string map
```

## Config reference

```go
vaioidc.Config{
    // Discovery source — set EITHER IssuerURL OR (KeycloakURL + Realm).
    IssuerURL    string // generic issuer, e.g. "https://accounts.google.com"
    KeycloakURL  string // Keycloak base URL (convenience path)
    Realm        string // Keycloak realm (convenience path)

    // Required.
    ClientID      string
    ClientSecret  string
    CallbackURL   string // full URL, e.g. https://app.example.com/auth/callback
    SessionSecret string // base64-encoded 32 bytes (openssl rand -base64 32)

    // Optional (defaults shown).
    LogoutRedirect       string        // post-logout redirect (default "/")
    LoginPath            string        // RequireSession redirect target (default "/auth/login")
    PostLoginRedirect    string        // where a SUCCESSFUL login lands when nothing was
                                       // deep-linked (default "/") — ⚠️ SET IT IF YOUR UI IS
                                       // NOT AT THE ROOT: until v0.18.0 this was hard-coded,
                                       // and it 404'd every login for a service whose UI is
                                       // under a prefix, and silently landed administrators on
                                       // the public marketing homepage for a service that
                                       // serves one at "/".
    SessionTTL           time.Duration // cookie lifetime (default 24h)
    CookieName           string        // (default "vai_session")
    CookiePath           string        // (default "/")
    InsecureCookie       bool          // allow cookies over plain http:// (dev only; default false)
    Scopes               []string      // (default [openid, profile, email])
    ExtraClaims          []string      // extra ID-token claims → User.Claims
    UserResolver         UserResolver  // enrich/reject at login
    RetainTokens         bool          // store access+refresh tokens in the session
    RevalidateInterval   time.Duration // re-ask the provider whether this person is still signed
                                       // in, at most this often (default 0 = OFF = pre-v0.19.0
                                       // behaviour). ⛔ REQUIRES RetainTokens and must be shorter
                                       // than SessionTTL; New() refuses both, because an interval
                                       // that silently does nothing is indistinguishable from one
                                       // that works. See "Sign-out propagation" below.
    ReresolveOnRevalidate bool         // re-run the login gates and UserResolver on every
                                       // successful revalidation, so an org/role change in the
                                       // identity backend reaches a live session (v0.25.0;
                                       // default false = resolver at login only). A resolver
                                       // ERROR fails open; an answer that would refuse the login
                                       // ends the session. ⛔ REQUIRES RevalidateInterval and
                                       // UserResolver. See "Re-resolution on revalidation" below.
    SessionSyncEnabled   bool          // enable GET <mount>/session/sync — a browser-side check of
                                       // WHO is signed in, which RevalidateInterval structurally
                                       // cannot answer (default false = pre-v0.20.0). Needs no realm
                                       // change. See "Identity sync" below.
    RequireEmailDomain   string        // reject logins whose email domain != this
    RequireEmailVerified bool          // reject logins without email_verified=true (v0.24.0).
                                       // ⛔ SET IT WHENEVER RequireEmailDomain IS SET — New() warns
                                       // otherwise. See "Staff surfaces" below.
    DiscoveryRetryBudget time.Duration // retry cold-boot discovery failures (default 90s; <0 disables)
    IssuerURLOverride    string        // accept a different iss than the discovery URL (see below)
    Logger               *slog.Logger  // (default slog.Default())
}
```

### `IssuerURL` vs `IssuerURLOverride`

They are distinct:

- **`IssuerURL`** is *where discovery fetches from* — the provider's issuer. It must equal the
  provider's own `iss` value: `go-oidc` verifies that the discovery document's `issuer` matches the
  URL discovery was fetched from (byte-for-byte; a trailing slash is trimmed for you). Providers
  whose `iss` differs from their discovery base — a tenant-templated issuer (e.g. some Entra
  configurations), or a split-horizon deployment — will fail discovery unless you set
  `IssuerURLOverride`.
- **`IssuerURLOverride`** changes *which `iss` value is accepted* — the escape hatch for any
  discovery-URL vs `iss` mismatch. The canonical case is split-horizon Kubernetes: the pod performs
  discovery over a cluster-internal URL (e.g. `http://keycloak.<ns>.svc.cluster.local:8080`) while
  the provider issues tokens with its public issuer URL. Set the override to the public issuer so
  ID-token `iss` verification passes. This is a legitimate deployment topology, not a security
  relaxation — the internal URL is just a different network path to the same provider and the same
  signing keys.

## Bypassing your own middleware on the auth routes

The `/auth/*` routes are unauthenticated by definition, so any auth middleware you run must skip
them. `SkipPaths()` / `SkipPathsWithPrefix(prefix)` return those paths for you to feed into whatever
middleware you use:

```go
skip := auth.SkipPathsWithPrefix("/auth")
r.Use(myAuthMiddleware(skip)) // your middleware, not part of this library
r.Mount("/auth", auth.Routes())
```

## Testing

`NewTestAuth(t)` builds an `Auth` with no OIDC discovery, so handler tests need no live provider:

```go
func TestMyHandler(t *testing.T) {
    auth := vaioidc.NewTestAuth(t)

    r := chi.NewRouter()
    r.With(auth.RequireSession()).Get("/dashboard", handleDashboard)

    req := httptest.NewRequest("GET", "/dashboard", nil)
    req = auth.SetTestUser(req, &vaioidc.User{
        Sub: "test-user", Email: "alice@example.com", Name: "Alice",
    })

    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)
    assert.Equal(t, 200, w.Code)
}
```

`SetTestUser` injects a user into the request context (no cookie); `TestSessionCookie` mints a real
encrypted cookie for middleware-level tests.

## Requirements & license

- Go 1.25+ (dependency floor: `coreos/go-oidc/v3` and `golang.org/x/oauth2` require 1.25). Public
  dependencies only: `github.com/coreos/go-oidc/v3`, `github.com/go-chi/chi/v5`,
  `golang.org/x/oauth2`.
- Licensed under **Apache-2.0** (see `LICENSE`). Security policy: `SECURITY.md`. Contributions:
  `CONTRIBUTING.md`.
