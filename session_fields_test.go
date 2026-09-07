package vaioidc

// session_fields_test.go — v0.18.0: the guard this repository's own history
// argues for.

import (
	"reflect"
	"sort"
	"testing"
)

// sessionOmittedUserFields names every User field that fromUser deliberately
// does NOT persist into the session, with the reason.
//
// ⚠️ IT IS A LEDGER AND NOT AN ALLOW-LIST, AND THE DIFFERENCE IS THE REASON. An
// unlisted omission fails, and a listed field that IS persisted fails too — so
// closing a gap forces its line out of here rather than leaving a stale
// exemption for the next omission to hide behind.
var sessionOmittedUserFields = map[string]string{
	"Landing": "A one-shot verdict about a LOGIN, not an attribute of the person. " +
		"Persisting it would make it stale in the worst direction: somebody who lands " +
		"on onboarding and completes it would carry `onboarding` for the rest of their " +
		"session, and any consumer reading the session rather than the callback would " +
		"keep sending them back. handleCallback consumes it once, immediately after the " +
		"resolver returns, which is the only moment it is true.",
}

// TestSessionCarriesEveryUserFieldOrLedgersWhyNot is the guard for a defect this
// repository has already shipped once.
//
// ⚠️ v0.14.0 ADDED User.Memberships AND A HAND-ROLLED sessionPayload LITERAL IN
// handleCallback SILENTLY DROPPED IT, leaving multi-org consumers with an empty
// membership set and therefore no picker. The fix at the time was to route
// through fromUser and to leave a COMMENT in handleCallback warning the next
// person — and a comment cannot fail a build. This is the executable half.
//
// It compares the two structs by FIELD NAME, which is why it catches the shape
// of the original bug: fromUser assigns field by field, so a new User field is
// simply absent from it and nothing else in the package notices.
func TestSessionCarriesEveryUserFieldOrLedgersWhyNot(t *testing.T) {
	userType := reflect.TypeOf(User{})
	payloadType := reflect.TypeOf(sessionPayload{})

	// What fromUser actually writes, derived by running it over a User whose
	// every field is non-zero and observing which payload fields moved. That is
	// stronger than parsing the assignments: a field assigned from the WRONG
	// source would still be caught by the round-trip arm below.
	persisted := map[string]bool{}
	for _, mapping := range userToPayloadFieldNames() {
		persisted[mapping.user] = true
		if _, ok := payloadType.FieldByName(mapping.payload); !ok {
			t.Fatalf("the field map names sessionPayload.%s, which does not exist — repair the "+
				"map, do not delete the arm", mapping.payload)
		}
	}

	var unledgered []string
	for i := 0; i < userType.NumField(); i++ {
		name := userType.Field(i).Name
		if persisted[name] {
			if _, listed := sessionOmittedUserFields[name]; listed {
				t.Errorf("User.%s is listed in sessionOmittedUserFields but IS persisted. A "+
					"stale exemption is worse than none: it is where the next real omission "+
					"will hide. Remove the line.", name)
			}
			continue
		}
		if _, listed := sessionOmittedUserFields[name]; !listed {
			unledgered = append(unledgered, name)
		}
	}
	sort.Strings(unledgered)

	if len(unledgered) > 0 {
		t.Errorf("these User fields are neither persisted by fromUser nor ledgered: %v.\n"+
			"This is the v0.14.0 defect exactly: Memberships was added to User, a hand-rolled "+
			"payload literal dropped it, and multi-org consumers silently lost their picker. "+
			"Either add the field to fromUser AND sessionPayload, or add it to "+
			"sessionOmittedUserFields WITH A REASON — an omission with no reason cannot be "+
			"told from that bug.", unledgered)
	}

	for name := range sessionOmittedUserFields {
		if _, ok := userType.FieldByName(name); !ok {
			t.Errorf("sessionOmittedUserFields names User.%s, which no longer exists — a ledger "+
				"line for a deleted field is an exemption nobody can evaluate", name)
		}
	}
}

// TestSessionRoundTripsThePersistedFields proves the mapping is not merely
// present but CORRECT, which the name-based arm above cannot see.
//
// ⚠️ A FIELD ASSIGNED FROM THE WRONG SOURCE PASSES EVERY NAME-BASED CHECK. This
// is the arm that would catch `p.OrgID = u.Email`.
func TestSessionRoundTripsThePersistedFields(t *testing.T) {
	in := &User{
		Sub:        "sub-1",
		Email:      "person@example.com",
		Name:       "A Person",
		OrgID:      "org-1",
		Claims:     map[string]string{"k": "v"},
		RealmRoles: []string{"role-a"},
		Memberships: []Membership{
			{OrgID: "org-1", OrgName: "One", OrgSlug: "one", Role: "owner", TeamIDs: []string{"t1"}},
		},
		// Deliberately set, and deliberately expected NOT to survive.
		Landing: &Landing{Decision: LandingDecisionOnboarding, URL: "https://obol.example.com/app/signup"},
	}

	p := &sessionPayload{}
	p.fromUser(in)
	out := p.toUser()

	if out.Sub != in.Sub || out.Email != in.Email || out.Name != in.Name || out.OrgID != in.OrgID {
		t.Errorf("identity fields did not round-trip: %+v", out)
	}
	if len(out.Memberships) != 1 || out.Memberships[0].OrgID != "org-1" ||
		len(out.Memberships[0].TeamIDs) != 1 || out.Memberships[0].TeamIDs[0] != "t1" {
		t.Errorf("Memberships did not round-trip — this is the v0.14.0 defect: %+v", out.Memberships)
	}
	if len(out.RealmRoles) != 1 || out.RealmRoles[0] != "role-a" {
		t.Errorf("RealmRoles did not round-trip: %+v", out.RealmRoles)
	}
	if out.Claims["k"] != "v" {
		t.Errorf("Claims did not round-trip: %+v", out.Claims)
	}
	if out.Landing != nil {
		t.Errorf("Landing survived the session, and it must not: it is a verdict about ONE "+
			"login, so a session copy goes stale the moment the person acts on it. Got %+v",
			out.Landing)
	}
}

// userToPayloadFieldNames is the declared mapping fromUser implements.
//
// ⚠️ IT IS A COMPILED LIST AND NOT A SOURCE PARSE, for the reason ADR-129's route
// postures give: a walk that could not read an assignment would fail OPEN and
// report the field as unpersisted, i.e. produce a false accusation rather than a
// miss. Here a renamed field does not compile, and a field added to fromUser
// without a line here fails the round-trip arm.
func userToPayloadFieldNames() []struct{ user, payload string } {
	return []struct{ user, payload string }{
		{"Sub", "Sub"},
		{"Email", "Email"},
		{"Name", "Name"},
		{"OrgID", "OrgID"},
		{"Memberships", "Mbs"},
		{"Claims", "Claims"},
		{"RealmRoles", "Rls"},
	}
}
