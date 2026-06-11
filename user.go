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

	// OrgID is the user's *active* organization ID, resolved by the UserResolver
	// callback. Empty if no UserResolver is configured or the resolver left it
	// unset. For multi-org users a resolver defaults this to the first membership
	// (see Memberships); the consumer can change it via Auth.UpdateSession after
	// the user picks an org.
	OrgID string `json:"org_id,omitempty"`

	// Memberships is the full set of organizations the authenticated user belongs
	// to, when the UserResolver supplies it (obolresolver populates it from Obol's
	// /identity/ensure as of v0.14.0). It is purely ADDITIVE: a resolver that does
	// not set it leaves the slice nil and consumers see the legacy single-OrgID
	// behaviour unchanged.
	//
	// When len(Memberships) > 1, OrgID holds only the resolver's default pick and
	// the consumer SHOULD present an org picker, then call Auth.UpdateSession to
	// commit the chosen OrgID. len(Memberships) <= 1 needs no picker.
	Memberships []Membership `json:"memberships,omitempty"`

	// Claims holds additional claims extracted from the ID token.
	// Populated from Config.ExtraClaims. Non-string claim values are JSON-serialized.
	Claims map[string]string `json:"claims,omitempty"`
}

// Membership is one organization the authenticated user belongs to, as resolved
// by a UserResolver. Mirrors Obol's per-membership /identity/ensure row.
// Added in v0.14.0 to let consumers render an org picker for multi-org users
// instead of silently inheriting the first membership.
type Membership struct {
	// OrgID is the canonical organization identifier.
	OrgID string `json:"org_id"`
	// OrgName is the human-readable org name (may be empty).
	OrgName string `json:"org_name,omitempty"`
	// OrgSlug is the org's URL-safe slug (may be empty).
	OrgSlug string `json:"org_slug,omitempty"`
	// Role is the user's role within this org (may be empty).
	Role string `json:"role,omitempty"`
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
