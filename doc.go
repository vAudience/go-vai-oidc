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
//	    UserResolver:  myUserResolver,          // resolves user.OrgID via your backend
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
// bare domain (e.g. "example.com") to reject logins whose id_token
// email-claim domain does not match. Comparison is case-insensitive;
// the gate runs before UserResolver. Empty value (the default)
// disables the check.
//
// This gate checks the email DOMAIN only — it does NOT inspect the
// email_verified claim, so it is not, by itself, a trust boundary on a
// multi-tenant IdP where a user might hold an unverified address in the
// target domain. Enforce email_verified in your UserResolver (or at the
// IdP) if you need that guarantee. See SECURITY.md.
package vaioidc
