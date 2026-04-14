// Package vaioidc provides drop-in OIDC browser login for vAI Go services.
//
// It handles the complete Keycloak OIDC Authorization Code Flow with PKCE,
// AES-256-GCM encrypted session cookies, and chi-compatible middleware.
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
//	fmt.Println(user.Email) // "toni@vaudience.ai"
package vaioidc
