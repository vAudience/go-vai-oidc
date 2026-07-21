# go-vai-oidc

A generic Go **OIDC Relying Party** — drop-in browser login (OpenID Connect authorization-code
flow + PKCE) with encrypted, stateless session cookies. First-class **Keycloak** convenience, but
works with **any** spec-compliant OIDC provider (Google, Okta, Auth0, Microsoft Entra, Authentik,
Dex, …).

- **Any provider** — point it at an issuer URL; discovery does the rest.
- **Stateless** — the verified user lives in an AES-256-GCM-encrypted cookie. No database, no Redis,
  no server-side session store, no per-request token refresh.
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
            2. Extract user: Sub, Email, Name, RealmRoles, ExtraClaims
            3. (optional) UserResolver — enrich/reject (resolve org, gate domain, …)
            4. Encrypt session cookie (AES-256-GCM): Sub, Email, Name, OrgID, Memberships, Claims
       → redirect to the post-login target
       → RequireSession middleware decrypts the cookie → *User in the request context
```

The session cookie is `HttpOnly`, `Secure` (unless `InsecureCookie`), `SameSite=Lax`, and encrypted
with a per-service AES-256 key. It is self-contained — no round-trip to the provider on each request.

## The User

```go
type User struct {
    Sub         string            // subject claim — stable user identifier; use as a foreign key
    Email       string            // email claim (may be empty if scope not granted)
    Name        string            // name claim (may be empty)
    OrgID       string            // set by your UserResolver (empty otherwise)
    Memberships []Membership       // set by your UserResolver (multi-org/tenant support)
    Claims      map[string]string // extra claims requested via Config.ExtraClaims
    RealmRoles  []string          // Keycloak realm_access.roles; nil for non-Keycloak providers
}
```

`RealmRoles` is a Keycloak convenience: for any other provider the `realm_access` claim is simply
absent and the slice is nil (not an error). Check membership with `user.HasRealmRole("some-role")`.

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
    SessionTTL           time.Duration // cookie lifetime (default 24h)
    CookieName           string        // (default "vai_session")
    CookiePath           string        // (default "/")
    InsecureCookie       bool          // allow cookies over plain http:// (dev only; default false)
    Scopes               []string      // (default [openid, profile, email])
    ExtraClaims          []string      // extra ID-token claims → User.Claims
    UserResolver         UserResolver  // enrich/reject at login
    RetainTokens         bool          // store access+refresh tokens in the session
    RequireEmailDomain   string        // reject logins whose email domain != this
    DiscoveryRetryBudget time.Duration // retry cold-boot discovery failures (default 90s; <0 disables)
    IssuerURLOverride    string        // accept a different iss than the discovery URL (see below)
    Logger               *slog.Logger  // (default slog.Default())
}
```

### `IssuerURL` vs `IssuerURLOverride`

They are distinct:

- **`IssuerURL`** is *where discovery fetches from* — the provider's issuer.
- **`IssuerURLOverride`** changes *which `iss` value is accepted*. Use it for the split-horizon
  Kubernetes case: the pod performs discovery over a cluster-internal URL (e.g.
  `http://keycloak.<ns>.svc.cluster.local:8080`) while the provider issues tokens with its public
  issuer URL. Set the override to the public issuer so ID-token `iss` verification passes. This is a
  legitimate deployment topology, not a security relaxation — the internal URL is just a different
  network path to the same provider and the same signing keys.

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
