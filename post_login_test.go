package vaioidc

// post_login_test.go — v0.18.0: where a successful login lands, and the
// cross-origin return-to it can carry.

import (
	"net/url"
	"testing"
)

// TestPostLoginTarget covers the field that fixed two live consumer defects.
//
// ⚠️ BOTH DEFECTS WERE INVISIBLE FROM THE CONSUMER'S SIDE because this was a
// hard-coded "/" with no config field. One service serves its UI under a prefix
// and registers nothing at "/", so **every successful login answered 404**.
// Another serves a public marketing site at "/", so every signed-in
// administrator landed on the marketing homepage — the more dangerous shape,
// because nothing looks broken and nobody files a bug.
func TestPostLoginTarget(t *testing.T) {
	cases := []struct {
		name           string
		configured     string
		storedRedirect string
		want           string
		why            string
	}{
		{
			name:       "the configured destination when nothing was deep-linked",
			configured: "/ui",
			want:       "/ui",
			why:        "the arm that fixes a UI served under a prefix",
		},
		{
			name:       "the configured destination for an admin area behind a marketing site",
			configured: "/admin",
			want:       "/admin",
			why:        "the arm that stops an administrator landing on the public homepage",
		},
		{
			name:           "a deep link always wins over the configured destination",
			configured:     "/ui",
			storedRedirect: "/ui/servers/abc?tab=logs",
			want:           "/ui/servers/abc?tab=logs",
			why: "the person asked for somewhere specific; the configured value is only the " +
				"answer to 'nowhere in particular'",
		},
		{
			name:       "an unset field keeps the pre-v0.18.0 behaviour exactly",
			configured: defaultPostLoginRedirect,
			want:       "/",
			why: "the field is purely ADDITIVE — a consumer that sets nothing must land " +
				"where it always did, or a dependency bump becomes a behaviour change " +
				"nobody asked for",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{cfg: Config{PostLoginRedirect: tc.configured}}
			if got := a.postLoginTarget(tc.storedRedirect); got != tc.want {
				t.Errorf("postLoginTarget(%q) = %q, want %q: %s",
					tc.storedRedirect, got, tc.want, tc.why)
			}
		})
	}
}

// TestConsumerReturnTo pins the two decisions in the cross-origin return-to.
func TestConsumerReturnTo(t *testing.T) {
	const callback = "https://atlas.example.com/auth/callback"

	cases := []struct {
		name     string
		callback string
		target   string
		want     string
		why      string
	}{
		{
			name:     "a deep link becomes an absolute URL on THIS service's origin",
			callback: callback,
			target:   "/reports/42",
			want:     "https://atlas.example.com/reports/42",
			why: "the identity backend is on another host, so only an absolute URL can " +
				"bring the person back",
		},
		{
			name:     "the service root carries nothing",
			callback: callback,
			target:   "/",
			want:     "",
			why: "nobody deep-linked; the person ends at the service root anyway once the " +
				"backend's flow finishes, so a return-to would be noise on the URL",
		},
		{
			name:     "an empty target carries nothing",
			callback: callback,
			target:   "",
			want:     "",
			why:      "same reason",
		},
		{
			name:     "an absolute target is refused rather than forwarded",
			callback: callback,
			target:   "https://evil.example.com/steal",
			want:     "",
			why: "⚠️ THIS ARM SHOULD BE UNREACHABLE — target is either \"/\" or a value " +
				"isValidRedirect already admitted at /auth/login — and it is checked anyway " +
				"because the output is handed to ANOTHER ORIGIN. An unvalidated path turned " +
				"into an absolute URL and posted to the identity backend is how a " +
				"same-origin guard becomes somebody else's open redirect",
		},
		{
			name:     "a protocol-relative target is refused",
			callback: callback,
			target:   "//evil.example.com/steal",
			want:     "",
			why:      "same class, and the form browsers normalise most surprisingly",
		},
		{
			name:     "an unparseable callback URL carries nothing",
			callback: "::not a url::",
			target:   "/reports/42",
			want:     "",
			why: "the ORIGIN comes from CallbackURL and not from the request, deliberately: a " +
				"request-derived scheme is wrong behind a TLS-terminating proxy. So when " +
				"CallbackURL is unusable there is no honest origin to state, and stating a " +
				"wrong one would send the person to http:// for an https:// service",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{cfg: Config{CallbackURL: tc.callback}}
			if got := a.consumerReturnTo(tc.target); got != tc.want {
				t.Errorf("consumerReturnTo(%q) = %q, want %q: %s", tc.target, got, tc.want, tc.why)
			}
		})
	}
}

// TestAppendQueryParam covers the join, including the case that made a naive
// string concatenation wrong.
func TestAppendQueryParam(t *testing.T) {
	t.Run("a URL that already carries a query keeps it", func(t *testing.T) {
		// ⚠️ THIS IS WHY IT IS NOT `url + "?" + k + "=" + v`. The login path in
		// two surveyed consumers is "/auth/login?kc_idp_hint=google", so a naive
		// join produces a second "?" and the IdP hint is lost — which downgrades
		// a Google-federated login to Keycloak's own username/password form.
		got := appendQueryParam("/auth/login?kc_idp_hint=google", queryParamRedirect, "/admin/audit")
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("result does not parse: %v", err)
		}
		q := u.Query()
		if q.Get("kc_idp_hint") != "google" {
			t.Errorf("the existing parameter was lost: %q", got)
		}
		if q.Get(queryParamRedirect) != "/admin/audit" {
			t.Errorf("the redirect was not added: %q", got)
		}
	})

	t.Run("an absolute URL keeps its path", func(t *testing.T) {
		got := appendQueryParam("https://obol.example.com/app/select", queryParamConsumerReturnTo,
			"https://atlas.example.com/reports/42")
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("result does not parse: %v", err)
		}
		if u.Host != "obol.example.com" || u.Path != "/app/select" {
			t.Errorf("host/path changed: %q", got)
		}
		if u.Query().Get(queryParamConsumerReturnTo) != "https://atlas.example.com/reports/42" {
			t.Errorf("the return-to did not survive encoding: %q", got)
		}
	})
}

// TestConfigRefusesAnUnusablePostLoginRedirect proves the boot-time refusal.
//
// ⚠️ IT FAILS AT New() RATHER THAN AT THE END OF SOMEBODY'S LOGIN, which is the
// whole reason it is validated at all: an absolute URL here would send every
// successful login to another origin, and a path not starting with "/" resolves
// relative to /auth/ and produces a 404 nobody can explain from the outside.
func TestConfigRefusesAnUnusablePostLoginRedirect(t *testing.T) {
	for _, bad := range []string{"https://evil.example.com/", "ui", "//evil.example.com", "/ui\\x"} {
		t.Run(bad, func(t *testing.T) {
			cfg := Config{
				KeycloakURL:       "https://kc.example.com",
				Realm:             "r",
				ClientID:          "c",
				ClientSecret:      "s",
				CallbackURL:       "https://svc.example.com/auth/callback",
				SessionSecret:     testSessionSecretBase64,
				PostLoginRedirect: bad,
				Logger:            noopLogger(),
			}
			cfg.applyDefaults()
			if _, err := cfg.validate(); err == nil {
				t.Errorf("PostLoginRedirect %q was accepted", bad)
			}
		})
	}
}
