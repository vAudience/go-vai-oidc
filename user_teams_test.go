package vaioidc

import "testing"

// TestTeamIDsForOrg_PairsTeamsWithTheirOwnOrg is the unit half of atlas#248.
//
// The helper exists because its callers build a DELEGATED identity for a downstream
// service, and a team id paired with the wrong org authorises action in an org the user
// did not act in. Reading "the user's teams" without naming an org is the mistake it removes,
// so the fixture is deliberately a multi-org user with disjoint team sets.
func TestTeamIDsForOrg_PairsTeamsWithTheirOwnOrg(t *testing.T) {
	u := &User{
		Sub:   "u1",
		OrgID: "org-alpha",
		Memberships: []Membership{
			{OrgID: "org-alpha", Role: "owner", TeamIDs: []string{"team-a1", "team-a2"}},
			{OrgID: "org-beta", Role: "member", TeamIDs: []string{"team-b1"}},
			{OrgID: "org-gamma", Role: "member"},
		},
	}

	if got := u.TeamIDsForOrg("org-beta"); len(got) != 1 || got[0] != "team-b1" {
		t.Errorf("org-beta = %v, want [team-b1]", got)
	}
	if got := u.TeamIDsForOrg("org-alpha"); len(got) != 2 {
		t.Errorf("org-alpha = %v, want two teams", got)
	}
	// A membership that carries no teams, and an org with no membership at all, are both
	// nil here — the doc comment says so, and a caller needing to tell them apart must ask
	// the directory rather than the session.
	if got := u.TeamIDsForOrg("org-gamma"); got != nil {
		t.Errorf("a teamless membership = %v, want nil", got)
	}
	if got := u.TeamIDsForOrg("org-unknown"); got != nil {
		t.Errorf("an org with no membership = %v, want nil", got)
	}
}

// TestTeamIDsForOrg_DegenerateInputs: a nil receiver and an empty org must not panic — the
// session may legitimately hold neither yet.
func TestTeamIDsForOrg_DegenerateInputs(t *testing.T) {
	var nilUser *User
	if got := nilUser.TeamIDsForOrg("org-alpha"); got != nil {
		t.Errorf("nil user = %v", got)
	}
	u := &User{Memberships: []Membership{{OrgID: "", TeamIDs: []string{"leaked"}}}}
	if got := u.TeamIDsForOrg(""); got != nil {
		t.Errorf("an empty orgID must never match a membership, got %v", got)
	}
}
