package vaioidc

import "context"

// User holds the authenticated user's identity extracted from the OIDC ID token.
type User struct {
	// Sub is the Keycloak subject UUID — stable across email and IdP changes.
	// Use this as your foreign key for user-specific data.
	Sub string `json:"sub"`

	// Email is the user's email address from the ID token (may be empty if scope not granted).
	Email string `json:"email"`

	// Name is the user's display name from the ID token (may be empty).
	Name string `json:"name"`
}

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey struct{}

// UserFromContext returns the authenticated User from the request context,
// or nil if no session is present (e.g., the request did not pass through RequireSession).
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(contextKey{}).(*User)
	return u
}

// contextWithUser returns a new context carrying the authenticated user.
func contextWithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, contextKey{}, u)
}
