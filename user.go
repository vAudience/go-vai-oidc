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

	// SessionID is Keycloak's SSO session id for the session this user was
	// authenticated in (the ID token's `sid` claim, v0.20.0). Empty when the IdP
	// does not issue it.
	//
	// ⛔ IT IS NOT AN ALIAS FOR Sub, AND THE DIFFERENCE IS THE WHOLE POINT. `sub`
	// identifies the PERSON; `sid` identifies the SIGN-IN. A person who signs out
	// and signs back in keeps their `sub` and gets a new `sid` — and every
	// product still holding a cookie from the OLD sign-in is holding a session
	// the IdP no longer knows about, which `sub` alone can never reveal.
	SessionID string `json:"session_id,omitempty"`

	// RealmRoles holds the Keycloak realm roles from the ID token's standard
	// `realm_access.roles` claim, extracted unconditionally (no Config.ExtraClaims
	// entry needed — this is a first-class field, like OrgID/Memberships). Nil
	// if the claim was absent or the ID token carried no realm roles at all.
	RealmRoles []string `json:"realm_roles,omitempty"`

	// Landing is the identity backend's DECISION about where this person should
	// be sent after login (v0.18.0, obolresolver populates it from obol's
	// /identity/ensure). Nil means the backend expressed no opinion — an older
	// obol, a custom resolver, or no resolver at all — and the callback then
	// behaves exactly as it did before this field existed.
	//
	// ⚠️ IT IS A DECISION, NOT A PAIR OF FACTS, AND RE-DERIVING IT IS THE DEFECT
	// IT EXISTS TO CLOSE. The identity backend deliberately does not publish
	// "is this user new" and "how many orgs" for each consumer to route on: a
	// fleet survey found five surfaces deriving one rule five different ways,
	// including two that pinned a person to an auto-minted personal workspace
	// with no way off it.
	//
	// ⚠️ IT IS NOT PERSISTED IN THE SESSION, DELIBERATELY. It is a one-shot
	// verdict about a login, not an attribute of the person: a user who lands on
	// onboarding and completes it would otherwise carry `onboarding` for the rest
	// of their session. TestSessionCarriesEveryUserFieldOrLedgersWhyNot pins that
	// decision so it reads as a choice rather than the omission that dropped
	// Memberships in v0.14.0.
	Landing *Landing `json:"landing,omitempty"`
}

// Landing decisions an identity backend can express. A consumer MUST treat an
// unrecognised value as "no opinion" and proceed as it did before, never as a
// refusal — the vocabulary belongs to the backend and may grow.
const (
	// LandingDecisionOnboarding — this identity holds no organization anybody
	// deliberately placed them in. Send the browser to Landing.URL.
	LandingDecisionOnboarding = "onboarding"

	// LandingDecisionOrgSelection — several real organizations and no usable
	// default; the person must choose. Send the browser to Landing.URL.
	LandingDecisionOrgSelection = "org_selection"

	// LandingDecisionReady — proceed to this service's own destination. URL is
	// empty in this arm by design.
	LandingDecisionReady = "ready"
)

// Landing carries the identity backend's post-login routing decision.
type Landing struct {
	// Decision is one of the LandingDecision* constants, or a value this
	// version of the library does not know.
	Decision string `json:"decision"`

	// URL is an ABSOLUTE URL on the identity backend's own origin, already
	// validated by the resolver that produced it.
	//
	// ⚠️ IT IS EMPTY ON `ready`, AND ALSO EMPTY WHEN THE BACKEND COULD NOT
	// COMPUTE ONE (its public base URL unset). An empty URL therefore never
	// means "redirect to the empty string" — RedirectTarget returns false and
	// the login proceeds to the consumer's own destination.
	URL string `json:"url,omitempty"`
}

// RedirectTarget reports the URL the browser should be sent to instead of the
// consumer's own post-login destination, and whether there is one.
//
// ⚠️ IT IS THE ONE PLACE THAT DECIDES, and every arm of it fails towards the
// consumer's existing behaviour rather than away from it:
//
//   - a nil Landing (no opinion, or a backend older than the field) → false
//   - `ready`, or any decision this library does not recognise → false
//   - a decision that wants a redirect but carries no URL → false
//
// The last arm is the one worth stating: a backend that has decided somebody
// needs onboarding but cannot say where is still better served by letting the
// login finish, because the alternative is a person who authenticated
// successfully and lands nowhere.
func (l *Landing) RedirectTarget() (string, bool) {
	if l == nil || l.URL == "" {
		return "", false
	}
	switch l.Decision {
	case LandingDecisionOnboarding, LandingDecisionOrgSelection:
		return l.URL, true
	default:
		// `ready` and every value this version does not compile. A decision the
		// library cannot interpret must not move the user (see the const block).
		return "", false
	}
}

// HasRealmRole reports whether the user's ID token carried the given Keycloak
// realm role. Case-sensitive exact match, matching Keycloak's own role names.
func (u *User) HasRealmRole(role string) bool {
	if u == nil {
		return false
	}
	for _, r := range u.RealmRoles {
		if r == role {
			return true
		}
	}
	return false
}

// Membership is one organization the authenticated user belongs to, as resolved
// by a UserResolver. Mirrors an upstream directory's per-membership row.
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

	// TeamIDs are the user's ACTIVE team memberships within THIS org, when the
	// UserResolver supplies them (obolresolver populates them from obol's
	// /identity/ensure as of v0.17.0). Nil when the resolver does not set them,
	// which keeps this purely additive for every existing consumer.
	//
	// ⚠ TEAMS ARE PER-ORG, WHICH IS WHY THEY LIVE HERE AND NOT ON User. A multi-org
	// user has a different team set in each org, and a consumer that reads "the
	// user's teams" without saying which org would hand org A's delegation org B's
	// teams. Use User.TeamIDsForOrg rather than reaching into this slice.
	TeamIDs []string `json:"team_ids,omitempty"`
}

// TeamIDsForOrg returns the user's active team ids within orgID, or nil when the
// user has no membership there, the membership carries no teams, or the resolver
// supplied none.
//
// ⚠ IT EXISTS SO THE ORG/TEAM PAIRING IS DERIVED ONCE. The consumers of this are
// building a delegated identity for a downstream service — atlas stamps the result
// onto the forwarded identity that charonmw signs into the S2S claim — and a team id
// paired with the wrong org is a grant in an org the user did not act in. That is a
// one-line loop every caller would otherwise write for itself.
//
// ⚠ nil is NOT "this user is in no team". It is indistinguishable here from a
// resolver that supplies no teams at all, and a caller that must tell those apart has
// to ask the directory, not the session.
func (u *User) TeamIDsForOrg(orgID string) []string {
	if u == nil || orgID == "" {
		return nil
	}
	for _, m := range u.Memberships {
		if m.OrgID == orgID {
			return m.TeamIDs
		}
	}
	return nil
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
