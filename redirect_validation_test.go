package vaioidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// go-vai-oidc#30: a tab inside the path survives into the Location header and
// browsers (WHATWG URL parsing) strip ASCII tab/LF/CR, so "/\t/host" resolves
// to "//host". The validator must refuse every control character and every
// whitespace, not only the shapes that are dangerous before normalisation.
func TestIsValidRedirect_SameOriginPathOnly(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		// The issue's payload and its siblings.
		{"tab between slashes", "/\t/host", false},
		{"newline between slashes", "/\n/host", false},
		{"carriage return between slashes", "/\r/host", false},
		{"NUL between slashes", "/\x00/host", false},
		{"vertical tab", "/\v/host", false},
		{"form feed", "/\f/host", false},
		{"tab at the end", "/app\t", false},
		{"newline header injection", "/app\r\nSet-Cookie: x=1", false},
		{"DEL", "/path\x7f", false},
		{"other C0 control", "/a\x1fb", false},
		{"C1 NEL", "/a\u0085b", false},
		{"unicode line separator", "/a b", false},
		{"NBSP", "/a b", false},
		// Slash and backslash shapes.
		{"protocol-relative", "//host", false},
		{"protocol-relative with path", "//evil.com/path", false},
		{"backslash after slash", "/\\host", false},
		{"backslash first", "\\\\/host", false},
		{"backslash slash backslash", "/\\/host", false},
		{"backslash deep in path", "/a/b\\c", false},
		// Not a path.
		{"absolute https", "https://evil", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"leading space", " /path", false},
		{"space inside", "/a b", false},
		{"empty", "", false},
		{"no leading slash", "dashboard", false},
		{"at-sign in path is still a path", "/@evil.com", true}, // still a path: begins with exactly one "/"
		// Valid same-origin paths.
		{"root", "/", true},
		{"app", "/app", true},
		{"query and fragment", "/app?x=1#y", true},
		{"nested", "/a/b/c", true},
		{"query with url inside", "/app?next=https://x.test/", false}, // contains "://": kept refused (pre-existing rule)
		// Percent-encoded forms are literal path bytes: the value is placed in
		// a Location header as-is, never decoded, so the browser sees a path
		// segment named "%09", not a tab. (A consumer that decodes it first
		// must re-validate; the request query decode has already happened by
		// the time this runs.)
		{"percent tab literal", "/%09/host", true},
		{"percent slashes literal", "/%2F%2Fhost", true},
		{"percent backslashes literal", "/%5C%5Chost", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, isValidRedirect(tt.input), "input %q", tt.input)
		})
	}
}

// The percent-encoded tab arrives DECODED: /auth/login reads it through
// r.URL.Query().Get, so ?redirect=%2F%09%2Fevil is "/\t/evil" by the time the
// validator runs — the form the issue exploits.
func TestIsValidRedirect_DecodedQueryPayload(t *testing.T) {
	assert.False(t, isValidRedirect("/\t/evil.example.com"))
}

// The callback reads the redirect back out of a cookie; the cookie is the
// browser's, so the value is re-validated rather than trusted for having been
// validated at /auth/login.
func TestPostLoginTarget_RevalidatesStoredRedirect(t *testing.T) {
	a := &Auth{cfg: Config{PostLoginRedirect: "/home"}}
	assert.Equal(t, "/app?x=1", a.postLoginTarget("/app?x=1"))
	assert.Equal(t, "/home", a.postLoginTarget(""))
	for _, bad := range []string{"/\t/host", "//host", "https://evil", "/\\host"} {
		assert.Equal(t, "/home", a.postLoginTarget(bad), "stored %q", bad)
	}
}

func TestStepUpLoginURL_RefusesControlCharacters(t *testing.T) {
	a := &Auth{cfg: Config{LoginPath: "/auth/login"}}
	_, err := a.StepUpLoginURL("/\t/host")
	require.ErrorIs(t, err, ErrInvalidReturnPath)
}
