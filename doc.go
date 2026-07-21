// Package vaioidc provides drop-in OIDC browser login with org resolution for vAI Go services.
//
// It handles the complete Keycloak OIDC Authorization Code Flow with PKCE,
// AES-256-GCM encrypted session cookies, org resolution via UserResolver callback,
// and chi-compatible middleware.
//
// Usage:
//
//	auth, err := vaioidc.New(ctx, vaioidc.Config{
//	    KeycloakURL:   cfg.OIDC.BaseURL,
//	    Realm:         cfg.OIDC.Realm,
//	    ClientID:      cfg.OIDC.ClientID,
//	    ClientSecret:  cfg.OIDC.ClientSecret,
//	    CallbackURL:   cfg.OIDC.CallbackURL,
//	    SessionSecret: cfg.OIDC.SessionSecret, // base64-encoded 32 bytes
//	    UserResolver:  myObolResolver,          // resolves user.OrgID via Obol
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	r := chi.NewRouter()
//	r.Mount("/auth", auth.Routes())
//	r.With(auth.RequireSession()).Get("/dashboard", handleDashboard)
//
// Protected handlers access the authenticated user via context:
//
//	user := vaioidc.UserFromContext(r.Context())
//	fmt.Println(user.Email, user.OrgID)
//
// Email-domain gate (v0.7.0+): set Config.RequireEmailDomain to a
// bare domain (e.g. "example.com") to reject logins whose verified
// id_token email-claim domain does not match. Comparison is
// case-insensitive; the gate runs before UserResolver. Empty value
// (the default) disables the check. Intended as belt-and-braces on
// top of the realm-side IdP flow (e.g. a Google-only browser flow).
package vaioidc
