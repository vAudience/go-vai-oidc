package vaioidc

import "testing"

// TestLanding_RedirectTargetArms drives Landing.RedirectTarget directly, not
// through obolresolver, so a Landing built by a custom resolver is covered too
// and the redirect vocabulary is pinned at the package that owns it.
func TestLanding_RedirectTargetArms(t *testing.T) {
	const u = "https://obol.example.com/app/x"
	cases := []struct {
		name    string
		landing *Landing
		wantOK  bool
	}{
		{"nil landing", nil, false},
		{"onboarding", &Landing{Decision: LandingDecisionOnboarding, URL: u}, true},
		{"org_selection", &Landing{Decision: LandingDecisionOrgSelection, URL: u}, true},
		{"closed_beta", &Landing{Decision: LandingDecisionClosedBeta, URL: u}, true},
		{"closed_beta with no URL", &Landing{Decision: LandingDecisionClosedBeta}, false},
		{"ready", &Landing{Decision: LandingDecisionReady, URL: u}, false},
		{"a decision this version does not know", &Landing{Decision: "future_decision", URL: u}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.landing.RedirectTarget()
			if ok != tc.wantOK {
				t.Fatalf("RedirectTarget() = %q,%v want ok=%v", got, ok, tc.wantOK)
			}
			if ok && got != u {
				t.Errorf("RedirectTarget() = %q want %q", got, u)
			}
		})
	}
}
