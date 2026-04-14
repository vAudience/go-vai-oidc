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

	// OrgID is the user's organization ID, resolved by the UserResolver callback.
	// Empty if no UserResolver is configured or the resolver left it unset.
	OrgID string `json:"org_id,omitempty"`

	// Claims holds additional claims extracted from the ID token.
	// Populated from Config.ExtraClaims. Non-string claim values are JSON-serialized.
	Claims map[string]string `json:"claims,omitempty"`
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
