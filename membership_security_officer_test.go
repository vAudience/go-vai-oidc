package vaioidc

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMembershipSecurityOfficer_RoundTripsThroughTheSessionCookie drives the whole
// persisted path — fromUser → encrypt → Set-Cookie → read → decrypt → toUser — and
// pins that the designation lands on THE ORG IT WAS SAID FOR (v0.35.0, obol#485 /
// atlas#984). Two orgs with opposite values, so a mapping that copied one row's flag
// onto every row fails.
func TestMembershipSecurityOfficer_RoundTripsThroughTheSessionCookie(t *testing.T) {
	key := testKey(t)
	p := &sessionPayload{Exp: time.Now().UTC().Add(time.Hour).Unix()}
	p.fromUser(&User{
		Sub:   "sub-1",
		OrgID: "org-a",
		Memberships: []Membership{
			{OrgID: "org-a", Role: "member", SecurityOfficer: true},
			{OrgID: "org-b", Role: "owner"},
		},
	})

	w := httptest.NewRecorder()
	require.NoError(t, setSessionCookie(w, p, key, "vai_test", "/", false, nil))
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	read, err := readSessionCookie(req, key, "vai_test")
	require.NoError(t, err)

	out := read.toUser()
	require.Len(t, out.Memberships, 2)
	assert.True(t, out.Memberships[0].SecurityOfficer, "org-a's designation was lost in the session")
	assert.False(t, out.Memberships[1].SecurityOfficer, "org-b acquired a designation it was never given")
}

// TestMembershipSecurityOfficer_AbsentKeyIsFalse is the compatibility control: every
// session minted before v0.35.0 (and every membership an older obol resolved) carries
// no key, and it must decode to false — fail CLOSED, never an error.
func TestMembershipSecurityOfficer_AbsentKeyIsFalse(t *testing.T) {
	var m Membership
	require.NoError(t, json.Unmarshal([]byte(`{"org_id":"org-a","role":"admin"}`), &m))
	assert.False(t, m.SecurityOfficer)

	var p sessionPayload
	require.NoError(t, json.Unmarshal([]byte(`{"sub":"s","mbs":[{"org_id":"org-a"}],"idt":"","exp":1}`), &p))
	require.Len(t, p.Mbs, 1)
	assert.False(t, p.Mbs[0].SecurityOfficer)
}

// TestMembershipSecurityOfficer_FalseCostsNoCookieBytes pins the size decision: a
// membership that is NOT designated encodes exactly as it did before v0.35.0, so the
// field adds bytes to a session only for the (at most one per org) designated member.
func TestMembershipSecurityOfficer_FalseCostsNoCookieBytes(t *testing.T) {
	plain, err := json.Marshal(Membership{OrgID: "org-a", Role: "member"})
	require.NoError(t, err)
	assert.NotContains(t, string(plain), "security_officer")

	designated, err := json.Marshal(Membership{OrgID: "org-a", Role: "member", SecurityOfficer: true})
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(designated), `"security_officer":true`))
	assert.Equal(t, len(`,"security_officer":true`), len(designated)-len(plain))
}
