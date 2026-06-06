# vai-oidc

Drop-in OIDC browser login with org resolution for vAI Go services.

Users authenticate via Keycloak (Google OAuth / email+password), then vai-oidc resolves their organization via Obol. The result — `user.Sub`, `user.Email`, `user.OrgID` — is stored in an encrypted session cookie. No database, no Redis, no token refresh.

Keycloak session persistence gives **de facto SSO** — users log in once, all services redirect instantly.

## Quick Start

```go
import vaioidc "github.com/vAudience/vai-oidc"
```

### 1. Create the Auth instance (at startup)

```go
auth, err := vaioidc.New(ctx, vaioidc.Config{
    KeycloakURL:   cfg.OIDC.BaseURL,      // "https://keycloak.dev.styx.vaieco.vaudience.io"
    Realm:         cfg.OIDC.Realm,         // "vaudience"
    ClientID:      cfg.OIDC.ClientID,      // "skope"
    ClientSecret:  cfg.OIDC.ClientSecret,  // from K8s secret
    CallbackURL:   cfg.OIDC.CallbackURL,   // "https://skope.dev.styx.../auth/callback"
    SessionSecret: cfg.OIDC.SessionSecret, // base64-encoded 32 bytes

    // Resolve the user's org during login (calls Obol)
    UserResolver: func(ctx context.Context, user *vaioidc.User) (*vaioidc.User, error) {
        resp, err := obolClient.EnsureIdentity(ctx, user.Sub, user.Email, user.Name)
        if err != nil {
            return nil, err // login rejected
        }
        if len(resp.Memberships) == 1 {
            user.OrgID = resp.Memberships[0].OrgID
        }
        // Multiple orgs: leave OrgID empty, redirect to org picker post-login
        return user, nil
    },
})
if err != nil {
    log.Fatal(err)
}
```

### 2. Mount routes + protect pages

```go
r := chi.NewRouter()

// Charon S2S middleware — skip the auth routes
r.Use(CharonS2SMiddleware(charonInstance, append(mySkipPaths, auth.SkipPathsWithPrefix("/auth")...)))

// Mount login/callback/logout handlers
r.Mount("/auth", auth.Routes())

// Public pages
r.Get("/", handleLanding)

// Protected pages — redirects to /auth/login if no session
r.Group(func(r chi.Router) {
    r.Use(auth.RequireSession())
    r.Get("/dashboard", handleDashboard)
    r.Get("/settings", handleSettings)
})
```

### 3. Read the user in your handlers

```go
func handleDashboard(w http.ResponseWriter, r *http.Request) {
    user := vaioidc.UserFromContext(r.Context())
    // user.Sub   — "a1b2c3d4-..." (Keycloak subject UUID, stable user ID)
    // user.Email — "toni.wagner@vaudience.ai"
    // user.Name  — "Toni Wagner"
    // user.OrgID — "00000000-0000-0000-0000-000000000000" (resolved by UserResolver)
    fmt.Fprintf(w, "Hello, %s (org: %s)", user.Name, user.OrgID)
}
```

## How It Works

```
Browser → GET /auth/login
       → Keycloak (Google OAuth / email+password)
       → GET /auth/callback
            1. Verify ID token (PKCE + signature)
            2. Extract user: Sub, Email, Name, ExtraClaims
            3. Call UserResolver → Obol POST /api/v1/identity/ensure
               → Obol upserts user, ensures org exists, returns memberships
               → UserResolver sets user.OrgID
            4. Encrypt session cookie (AES-256-GCM): Sub, Email, Name, OrgID, Claims
       → redirect to /dashboard
       → RequireSession middleware decrypts cookie → User in context
```

**Session cookie**: AES-256-GCM encrypted, HttpOnly, Secure, SameSite=Lax. Stateless — no database, no Redis, no token refresh.

**Keycloak SSO**: If the user already logged into any vAI service, Keycloak skips the login page entirely. The redirect chain takes ~200ms.

**Org resolution**: Obol is the source of truth for user-to-org mapping. `@vaudience.ai` users are auto-assigned to the owner org (`00000000-0000-0000-0000-000000000000`). New external users get a personal org auto-created. The Obol call happens once per login — subsequent requests read OrgID from the encrypted cookie.

## User Struct

```go
type User struct {
    Sub    string            // Keycloak subject UUID — stable user identifier
    Email  string            // e.g. "toni.wagner@vaudience.ai"
    Name   string            // e.g. "Toni Wagner"
    OrgID  string            // Organization UUID (resolved by UserResolver via Obol)
    Claims map[string]string // Extra claims from ExtraClaims config
}
```

| Field | Source | Notes |
|-------|--------|-------|
| `Sub` | ID token `sub` claim | Keycloak user UUID. Use as foreign key. Stable across email/IdP changes. |
| `Email` | ID token `email` claim | May be empty if `email` scope not granted. |
| `Name` | ID token `name` claim | May be empty. Falls back to `preferred_username`. |
| `OrgID` | `UserResolver` callback | Set by your resolver (typically from Obol). Empty if resolver not configured or user has multiple orgs (pending selection). |
| `Claims` | ID token extra claims | Populated from `Config.ExtraClaims`. Non-string values are JSON-serialized. |

## UserResolver — Org Resolution via Obol

The `UserResolver` callback is called during the OIDC callback, after the ID token is verified but before the session cookie is written. This is where you resolve the user's org.

```go
type UserResolver func(ctx context.Context, user *User) (*User, error)
```

**Contract:**
- Receives the user extracted from the ID token (Sub, Email, Name, Claims populated)
- Must return the enriched user (with OrgID set) or an error
- If error is returned, the login is rejected (user redirected to LogoutRedirect)
- Called once per login, not on every request

**Standard pattern (all vAI services):**

```go
UserResolver: func(ctx context.Context, user *vaioidc.User) (*vaioidc.User, error) {
    // Call Obol to ensure user+org exist
    resp, err := obolClient.EnsureIdentity(ctx, user.Sub, user.Email, user.Name)
    if err != nil {
        return nil, fmt.Errorf("obol identity: %w", err)
    }

    switch len(resp.Memberships) {
    case 0:
        return nil, errors.New("no org") // should never happen (Obol auto-creates)
    case 1:
        user.OrgID = resp.Memberships[0].OrgID
    default:
        // Multiple orgs — leave OrgID empty
        // Service redirects to org picker page post-login
    }
    return user, nil
},
```

Obol's `POST /api/v1/identity/ensure` response:
```json
{
  "data": {
    "user_id": "keycloak-sub-uuid",
    "memberships": [
      {"org_id": "00000000-...", "org_name": "vAudience", "org_slug": "owner", "role": "admin"}
    ]
  }
}
```

## UpdateSession — Post-Login Org Selection

For multi-org users, the `UserResolver` leaves `OrgID` empty. The service shows an org picker, then calls `UpdateSession` to write the selected org into the session cookie:

```go
// POST /select-org handler
func handleSelectOrg(auth *vaioidc.Auth) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        orgID := r.FormValue("org_id")
        // TODO: validate orgID belongs to the user (call Obol)
        if err := auth.UpdateSession(w, r, func(u *vaioidc.User) {
            u.OrgID = orgID
        }); err != nil {
            http.Error(w, "session error", 500)
            return
        }
        http.Redirect(w, r, "/dashboard", http.StatusFound)
    }
}
```

`UpdateSession` reads the current session, applies the mutation, and writes a new cookie. The IDToken and expiration are preserved — only User-visible fields change.

## AccessToken — Forward the User's Keycloak Token (v0.12.0+)

By default vai-oidc keeps **only** the `id_token` (for logout) and discards the OAuth2 access/refresh tokens. Set `Config.RetainTokens = true` to also store them in the encrypted session, then call `AccessToken(w, r)` to obtain a **currently-valid** access token — refreshed transparently via the refresh token when expired:

```go
// At startup:
vaioidc.Config{
    // ...
    RetainTokens: true, // store access+refresh tokens in the session
}

// In a handler that must act on the user's behalf against a downstream API
// (e.g. mint a Charon API key for the logged-in user):
token, err := auth.AccessToken(w, r)
if err != nil {
    // ErrTokensNotRetained → retention off or pre-retention session
    // ErrTokenRefreshFailed → re-authentication required
    http.Error(w, "re-authentication required", http.StatusUnauthorized)
    return
}
req.Header.Set("Authorization", "Bearer "+token) // forward to charon, etc.
```

The returned token is the raw Keycloak access-token JWT. The downstream service validates it directly (signature + `aud`); ensure the Keycloak client emits an `aud` the downstream accepts (an audience-mapper concern — vai-oidc forwards the token opaquely). When a refresh occurs the rotated tokens are persisted back into the cookie automatically (the session TTL is preserved).

**Cookie-size trade-off:** retaining both tokens adds ~2–4 KB to the session cookie on top of the id_token, which can approach the ~4 KB per-cookie browser limit. A warning is logged when a written cookie crosses `CookieSizeWarnThreshold`. For refresh that survives Keycloak SSO logout, add `"offline_access"` to `Scopes`.

## ExtraClaims — Custom ID Token Claims

If your Keycloak realm has custom claim mappers, extract them into `User.Claims`:

```go
vaioidc.Config{
    // ...
    ExtraClaims: []string{"tenant_id", "department"},
}
```

In your handler:
```go
user := vaioidc.UserFromContext(r.Context())
tenant := user.Claims["tenant_id"]     // string value from ID token
dept := user.Claims["department"]       // non-string values are JSON-serialized
```

## Config Reference

```go
vaioidc.Config{
    // Required
    KeycloakURL   string // Keycloak base URL
    Realm         string // Keycloak realm name
    ClientID      string // OIDC client ID (registered in Keycloak)
    ClientSecret  string // OIDC client secret (from K8s secret)
    CallbackURL   string // Full URL: https://myservice.../auth/callback
    SessionSecret string // base64-encoded 32 bytes (openssl rand -base64 32)

    // Optional (with defaults)
    LogoutRedirect string        // Post-logout redirect (default: "/")
    LoginPath      string        // Full login path for RequireSession redirects (default: "/auth/login")
    SessionTTL     time.Duration // Session lifetime (default: 24h)
    CookieName     string        // Cookie name (default: "vai_session")
    CookiePath     string        // Cookie path (default: "/")
    InsecureCookie bool          // Allow cookies over plain HTTP (default: false)
    Scopes         []string      // OIDC scopes (default: openid, profile, email)

    // Optional: Identity resolution
    ExtraClaims  []string      // Extra ID token claims to extract into User.Claims
    UserResolver UserResolver  // Called during callback to resolve org (see above)

    // Optional: Observability
    Logger *slog.Logger // Structured logger (default: slog.Default())
}
```

## Service Config YAML (vaiconfig)

```yaml
oidc:
  enabled: ${SVC_OIDC_ENABLED:-true}
  base_url: "${SVC_OIDC_BASE_URL:-https://keycloak.dev.styx.vaieco.vaudience.io}"
  realm: "${SVC_OIDC_REALM:-vaudience}"
  client_id: "${SVC_OIDC_CLIENT_ID:-myservice}"
  client_secret: "${SVC_OIDC_CLIENT_SECRET:!required}"
  callback_url: "${SVC_OIDC_CALLBACK_URL:!required}"
  session_secret: "${SVC_OIDC_SESSION_SECRET:!required}"
```

## K8s Secrets

| Secret | Generated By | Notes |
|---|---|---|
| `SVC_OIDC_CLIENT_SECRET` | Keycloak realm setup (`keycloak.sh`) | Extracted from `keycloak-realm-secrets` |
| `SVC_OIDC_SESSION_SECRET` | `gen_aes_key()` in `03-namespaces-secrets.sh` | Must be base64-encoded 32 bytes |
| `SVC_OIDC_CALLBACK_URL` | Config override per deployment | HTTPS on Styx, HTTP on vaiDevStack |

## Keycloak Client Registration

Your service needs a Keycloak OIDC client. This is automated in `ai_k8s_setup`:

```bash
# In scripts/lib/keycloak.sh
kc_ensure_client "myservice" \
    "https://myservice.dev.styx.vaieco.vaudience.io/auth/callback" \
    "http://192.168.178.176:30XXX/auth/callback"
```

Add the call to `04-infrastructure.sh`. The function creates the client with PKCE, extracts the secret to `keycloak-realm-secrets`.

## charonmw Integration

vai-oidc auth routes must bypass charonmw (they're unauthenticated by definition):

```go
skipPaths := append(CharonSkipPaths(), auth.SkipPathsWithPrefix("/auth")...)
r.Use(CharonS2SMiddleware(instance, skipPaths))
```

S2S API endpoints (called by other services with Charon keys) remain protected by charonmw as before. vai-oidc only handles browser sessions.

## Testing

```go
func TestMyHandler(t *testing.T) {
    auth := vaioidc.NewTestAuth(t)

    r := chi.NewRouter()
    r.With(auth.RequireSession()).Get("/dashboard", handleDashboard)

    req := httptest.NewRequest("GET", "/dashboard", nil)
    req = auth.SetTestUser(req, &vaioidc.User{
        Sub:   "test-user-id",
        Email: "dev@vaudience.ai",
        Name:  "Test User",
        OrgID: "00000000-0000-0000-0000-000000000000",
    })

    w := httptest.NewRecorder()
    r.ServeHTTP(w, req)
    assert.Equal(t, 200, w.Code)
}
```

`SetTestUser` injects the user into the request context (no OIDC flow, no cookies). `TestSessionCookie` creates a real encrypted cookie for middleware-level tests.

## FAQ

**Q: Do I need to change my existing API auth?**
No. charonmw and Charon API keys are unchanged. vai-oidc is only for browser sessions. S2S auth between services still uses Charon.

**Q: Do users need a Charon API key?**
For browser UI: no. The service calls APIs using its own S2S credentials on behalf of the user. For CLI/API access: users get keys from Obol's org dashboard.

**Q: What if Keycloak is down?**
New logins fail. Existing sessions continue working (stateless cookies, no Keycloak round-trip on each request).

**Q: What if Obol is down?**
New logins fail (UserResolver can't resolve org). Existing sessions continue working.

**Q: What about CSRF?**
OIDC state parameter prevents CSRF on the login flow. For your own forms, use your existing CSRF solution — vai-oidc doesn't interfere.

**Q: Can I customize the post-login redirect?**
Yes. `/auth/login?redirect=/my/page` — after auth, the user lands there instead of `/`.

**Q: Multiple services on same domain?**
Each service has its own cookie name (configurable via `CookieName`). No conflicts.

**Q: What's in the session cookie?**
`Sub`, `Email`, `Name`, `OrgID`, `Claims`, raw ID token (for federated logout), expiration. All AES-256-GCM encrypted with a per-service key. ~1.5KB total.
