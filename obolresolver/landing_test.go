package obolresolver

// landing_test.go — v0.18.0: obol's landing DECISION, the version header, and
// the two things this cycle deliberately made impossible.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaioidc "github.com/vAudience/go-vai-oidc"
)

// landingServer answers /identity/ensure with the given raw `data` object and
// records the request headers, so one helper covers both the decision arms and
// the version-header arm.
func landingServer(t *testing.T, dataJSON string, seen *http.Header) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = r.Header.Clone()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":`+dataJSON+`,"error":null,"meta":{}}`)
	}))
}

func resolve(t *testing.T, cfg Config) *vaioidc.User {
	t.Helper()
	r := New(cfg)
	if r == nil {
		t.Fatal("resolver is nil")
	}
	u, err := r(context.Background(), &vaioidc.User{Sub: "sub-1", Email: "a@b.c"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return u
}

// TestLanding_SendsTheVersionHeader closes obol ADR-194 D5's `absent` floor.
//
// ⚠️ THIS IS THE ONLY PLACE THE FLOOR COULD BE CLOSED. obol's
// obl_consumer_sdk_total counts which client contract each consumer runs, and a
// share of `absent` belonged to THIS module, because it hand-builds its request
// — so no consumer could fix it by pinning a newer obol SDK. If this test is
// ever deleted as "trivial", the rail silently regains a floor nobody can
// explain from obol's side.
func TestLanding_SendsTheVersionHeader(t *testing.T) {
	var seen http.Header
	srv := landingServer(t, `{"user_id":"u","memberships":[{"org_id":"o1"}]}`, &seen)
	defer srv.Close()

	resolve(t, Config{BaseURL: srv.URL, Client: srv.Client()})

	got := seen.Get("X-Obol-Client-Version")
	if got == "" {
		t.Fatal("no X-Obol-Client-Version header was sent — obol's consumer-SDK rail " +
			"cannot attribute this module's traffic and its `absent` cell keeps a floor " +
			"that no consumer can remove")
	}
	if got != ClientVersion {
		t.Errorf("header = %q, want %q", got, ClientVersion)
	}
	if !strings.HasPrefix(got, "go-vai-oidc/") {
		t.Errorf("header %q must name THIS module: the question obol asks is which code "+
			"composed the request, and it is this file — not the consumer, and not obol's "+
			"own SDK, which this module cannot import", got)
	}
}

func TestLanding_DecisionArms(t *testing.T) {
	const publicURL = "https://obol.example.com/app/signup"

	cases := []struct {
		name        string
		data        string
		wantDec     string
		wantRedirTo string
		why         string
	}{
		{
			name:        "onboarding with a URL redirects",
			data:        `{"user_id":"u","memberships":[{"org_id":"o1"}],"landing":{"decision":"onboarding","landing_url":"` + publicURL + `"}}`,
			wantDec:     vaioidc.LandingDecisionOnboarding,
			wantRedirTo: publicURL,
			why:         "the arm the whole cycle exists for",
		},
		{
			name:        "org_selection with a URL redirects",
			data:        `{"user_id":"u","memberships":[{"org_id":"o1"},{"org_id":"o2"}],"landing":{"decision":"org_selection","landing_url":"https://obol.example.com/app/select"}}`,
			wantDec:     vaioidc.LandingDecisionOrgSelection,
			wantRedirTo: "https://obol.example.com/app/select",
			why:         "the owner's own request: surface the org selection at login",
		},
		{
			name:        "ready never redirects",
			data:        `{"user_id":"u","memberships":[{"org_id":"o1"}],"landing":{"decision":"ready","landing_url":""}}`,
			wantDec:     vaioidc.LandingDecisionReady,
			wantRedirTo: "",
			why:         "an established person proceeds to the consumer's own destination",
		},
		{
			name:        "a decision this version does not know never moves the user",
			data:        `{"user_id":"u","memberships":[{"org_id":"o1"}],"landing":{"decision":"quarantine","landing_url":"` + publicURL + `"}}`,
			wantDec:     "quarantine",
			wantRedirTo: "",
			why: "⚠️ FORWARD COMPATIBILITY IS A SAFETY PROPERTY HERE. obol may grow this " +
				"vocabulary, and a value this library cannot interpret must leave the login " +
				"exactly where it was — an unknown decision acted on is a person sent " +
				"somewhere for a reason nobody in this process understands",
		},
		{
			name:        "a decision with no URL never redirects",
			data:        `{"user_id":"u","memberships":[{"org_id":"o1"}],"landing":{"decision":"onboarding","landing_url":""}}`,
			wantDec:     vaioidc.LandingDecisionOnboarding,
			wantRedirTo: "",
			why: "obol serves the decision even when its own public base URL is unset. A " +
				"person who authenticated successfully must not land nowhere, so the login " +
				"finishes where it would have before",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := landingServer(t, tc.data, nil)
			defer srv.Close()

			u := resolve(t, Config{BaseURL: srv.URL, Client: srv.Client()})
			if u.Landing == nil {
				t.Fatalf("Landing is nil: %s", tc.why)
			}
			if u.Landing.Decision != tc.wantDec {
				t.Errorf("decision = %q, want %q", u.Landing.Decision, tc.wantDec)
			}
			got, ok := u.Landing.RedirectTarget()
			if tc.wantRedirTo == "" {
				if ok {
					t.Errorf("RedirectTarget() = %q, true — must be false: %s", got, tc.why)
				}
				return
			}
			if !ok || got != tc.wantRedirTo {
				t.Errorf("RedirectTarget() = %q,%v want %q,true: %s", got, ok, tc.wantRedirTo, tc.why)
			}
		})
	}
}

// TestLanding_AbsentMeansNoOpinionAndNotReady is ADR-102's
// three-permanently-distinct-states rule at the consumer end.
func TestLanding_AbsentMeansNoOpinionAndNotReady(t *testing.T) {
	srv := landingServer(t, `{"user_id":"u","memberships":[{"org_id":"o1"}]}`, nil)
	defer srv.Close()

	u := resolve(t, Config{BaseURL: srv.URL, Client: srv.Client()})
	if u.Landing != nil {
		t.Fatalf("an obol that serves no `landing` key must leave Landing NIL, not a "+
			"zero-valued decision: \"this obol cannot decide\" and \"obol says ready\" have "+
			"different safe readings, and collapsing them is how a consumer starts trusting "+
			"an answer nobody gave. Got %+v", u.Landing)
	}
	if _, ok := u.Landing.RedirectTarget(); ok {
		t.Error("a nil Landing must not redirect")
	}
	if u.OrgID != "o1" {
		t.Errorf("OrgID = %q — an older obol must behave exactly as before", u.OrgID)
	}
}

// TestLanding_RefusesAUrlThatIsNotAnAbsoluteHTTPURL is the security arm.
//
// ⚠️ THE THREAT MODEL IS NOT AN OPEN REDIRECT, AND CONFLATING THE TWO IS WHY
// THIS VALIDATION LIVES HERE AND NOT IN isValidRedirect. This value never comes
// from the browser — it arrives in an authenticated server-to-server response —
// so the same-origin relative-path rule that guards `?redirect=` would reject
// every CORRECT landing URL, obol being on another host by construction. What is
// left to defend against is a misconfigured backend and the scheme-abuse class,
// and that is exactly what these cases cover.
func TestLanding_RefusesAUrlThatIsNotAnAbsoluteHTTPURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		why  string
	}{
		{"javascript scheme", "javascript:alert(1)", "the actual redirect-abuse class"},
		{"data scheme", "data:text/html,<script>1</script>", "same class, different scheme"},
		{"protocol-relative", "//evil.example.com/app/signup", "parses with no scheme and a host"},
		{"relative path", "/app/signup", "a relative path resolves against the CONSUMER's origin, " +
			"sending the person to a route that does not exist there — which reads as the " +
			"identity backend being broken"},
		{"embedded credentials", "https://user:pass@obol.example.com/app/signup",
			"the phishing form of a legitimate-looking URL"},
		{"no host", "https:///app/signup", "nothing to dial"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"user_id":     "u",
				"memberships": []map[string]any{{"org_id": "o1"}},
				"landing":     map[string]any{"decision": "onboarding", "landing_url": tc.url},
			})
			srv := landingServer(t, string(body), nil)
			defer srv.Close()

			u := resolve(t, Config{BaseURL: srv.URL, Client: srv.Client()})
			if u.Landing == nil {
				t.Fatal("the DECISION must survive a rejected URL — a consumer may still want " +
					"to show the person something")
			}
			if u.Landing.URL != "" {
				t.Errorf("URL %q was admitted: %s", u.Landing.URL, tc.why)
			}
			if _, ok := u.Landing.RedirectTarget(); ok {
				t.Errorf("RedirectTarget() said true for %q: %s", tc.url, tc.why)
			}
			if u.OrgID != "o1" {
				t.Errorf("and the login must still finish as before; OrgID = %q", u.OrgID)
			}
		})
	}
}

// TestLanding_AllowedHostsPinsTheOriginWhenConfigured covers the optional
// tightening — and the trap in the obvious version of it.
func TestLanding_AllowedHostsPinsTheOriginWhenConfigured(t *testing.T) {
	const good = "https://obol.example.com/app/signup"
	srv := landingServer(t, `{"user_id":"u","memberships":[{"org_id":"o1"}],"landing":{"decision":"onboarding","landing_url":"`+good+`"}}`, nil)
	defer srv.Close()

	t.Run("an allow-list naming the host admits it", func(t *testing.T) {
		u := resolve(t, Config{BaseURL: srv.URL, Client: srv.Client(),
			AllowedLandingHosts: []string{"OBOL.EXAMPLE.COM"}})
		if got, ok := u.Landing.RedirectTarget(); !ok || got != good {
			t.Errorf("RedirectTarget() = %q,%v — the comparison is case-folded", got, ok)
		}
	})

	t.Run("an allow-list not naming the host refuses it", func(t *testing.T) {
		u := resolve(t, Config{BaseURL: srv.URL, Client: srv.Client(),
			AllowedLandingHosts: []string{"obol.internal.example.com"}})
		if _, ok := u.Landing.RedirectTarget(); ok {
			t.Error("a pinned deployment must refuse a host it did not name")
		}
	})

	t.Run("BaseURL's own host is NOT the implicit allow-list", func(t *testing.T) {
		// ⚠️ THIS IS THE TRAP, AND IT WOULD HAVE DISABLED THE FEATURE SILENTLY.
		// Defaulting AllowedLandingHosts to BaseURL's host is the obvious
		// tightening and it is wrong: BaseURL is how this service DIALS obol and
		// is routinely cluster-internal, while the landing URL is the PUBLIC
		// address a browser must reach. Here BaseURL is the httptest server —
		// 127.0.0.1 — and the landing host is obol.example.com, which is exactly
		// the real-world shape.
		u := resolve(t, Config{BaseURL: srv.URL, Client: srv.Client()})
		if got, ok := u.Landing.RedirectTarget(); !ok || got != good {
			t.Errorf("RedirectTarget() = %q,%v — with no allow-list configured the URL must "+
				"be admitted even though its host differs from BaseURL's. A same-host default "+
				"would reject every correct URL and the failure would look like obol not "+
				"serving a decision at all", got, ok)
		}
	})
}

// TestLanding_ZeroMembershipsWithADecisionIsNotARejection is the behavioural
// change of v0.18.0.
//
// ⚠️ BEFORE THIS, A PERSON obol HAD PLACED IN NO ORGANIZATION HAD TWO POSSIBLE
// FATES AND NEITHER WAS ONBOARDING: adopt whatever came first, or be bounced to
// a logout page. AllowEmptyMembership decided which — a flag deciding a human's
// fate. With a decision present it decides nothing.
func TestLanding_ZeroMembershipsWithADecisionIsNotARejection(t *testing.T) {
	srv := landingServer(t, `{"user_id":"u","memberships":[],"landing":{"decision":"onboarding","landing_url":"https://obol.example.com/app/signup"}}`, nil)
	defer srv.Close()

	// AllowEmptyMembership stays FALSE — the strict default, which before this
	// cycle rejected the login outright.
	r := New(Config{BaseURL: srv.URL, Client: srv.Client()})
	u, err := r(context.Background(), &vaioidc.User{Sub: "sub-new"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatal("a (nil, nil) return bounces the person to a logout page. obol told us this " +
			"is a legitimate authenticated human at the START of a flow, so rejecting the " +
			"login discards the one instruction we asked for")
	}
	if got, ok := u.Landing.RedirectTarget(); !ok || got == "" {
		t.Errorf("and they must be sent to onboarding; got %q,%v", got, ok)
	}

	t.Run("with NO decision the flag still decides", func(t *testing.T) {
		// The flag survives for a custom resolver or an older obol. It just stops
		// being the thing that decides when a decision exists.
		plain := landingServer(t, `{"user_id":"u","memberships":[]}`, nil)
		defer plain.Close()
		r := New(Config{BaseURL: plain.URL, Client: plain.Client()})
		u, err := r(context.Background(), &vaioidc.User{Sub: "sub-old"})
		if err != nil || u != nil {
			t.Errorf("want (nil, nil) — the pre-v0.18.0 contract is unchanged where there is "+
				"no decision to honour; got (%v, %v)", u, err)
		}
	})
}
