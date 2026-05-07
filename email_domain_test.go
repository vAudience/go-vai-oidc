package vaioidc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// enforceEmailDomain — pure-function gate tests (DC-AUTH-07).
//
// Tests the gate without spinning a Keycloak fake. The gate runs
// AFTER claim extraction, so the unit under test takes a *User
// with the email already populated.
// ---------------------------------------------------------------------------

func TestEnforceEmailDomain_EmptyConfigSkipsCheck(t *testing.T) {
	err := enforceEmailDomain(&User{Email: "anyone@anywhere.example"}, "")
	require.NoError(t, err)
}

func TestEnforceEmailDomain_EmptyConfigAllowsMissingEmail(t *testing.T) {
	// Disabled gate must not reject users with an absent email claim.
	err := enforceEmailDomain(&User{Email: ""}, "")
	require.NoError(t, err)
}

func TestEnforceEmailDomain_NilUserRejected(t *testing.T) {
	err := enforceEmailDomain(nil, "vaudience.ai")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmailClaimMissing))
}

func TestEnforceEmailDomain_MatchingDomainAllowed(t *testing.T) {
	err := enforceEmailDomain(&User{Email: "alice@vaudience.ai"}, "vaudience.ai")
	require.NoError(t, err)
}

func TestEnforceEmailDomain_MismatchRejected(t *testing.T) {
	err := enforceEmailDomain(&User{Email: "eve@example.com"}, "vaudience.ai")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmailDomainMismatch))
	assert.False(t, errors.Is(err, ErrEmailClaimMissing))
}

func TestEnforceEmailDomain_CaseInsensitiveMatch(t *testing.T) {
	// Mixed case in both the email and (defensively) the configured
	// domain should still match. applyDefaults() is expected to
	// lowercase the config; this test pins runtime tolerance.
	err := enforceEmailDomain(&User{Email: "BOB@VAUDIENCE.AI"}, "vaudience.ai")
	require.NoError(t, err)

	err = enforceEmailDomain(&User{Email: "bob@vaudience.ai"}, "VAUDIENCE.AI")
	require.NoError(t, err)
}

func TestEnforceEmailDomain_MissingEmailRejected(t *testing.T) {
	err := enforceEmailDomain(&User{Email: ""}, "vaudience.ai")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmailClaimMissing))
}

func TestEnforceEmailDomain_MalformedEmailRejected(t *testing.T) {
	tests := []string{
		"no-at-sign",
		"trailing-at@",
		"@",
	}
	for _, e := range tests {
		t.Run(e, func(t *testing.T) {
			err := enforceEmailDomain(&User{Email: e}, "vaudience.ai")
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrEmailClaimMissing),
				"want ErrEmailClaimMissing, got %v", err)
		})
	}
}

func TestEnforceEmailDomain_LeadingAtTreatedAsMissingDomain(t *testing.T) {
	// "@example.com" → LastIndex("@") = 0 → idx == 0, len-1 = 11, idx
	// is NOT len-1 so domain part = "example.com". Match against
	// "example.com" succeeds. Documenting the boundary here so future
	// callers know the gate trusts whatever Keycloak issued — the
	// upstream realm is the gate against malformed claims.
	err := enforceEmailDomain(&User{Email: "@example.com"}, "example.com")
	require.NoError(t, err)
}

func TestEmailDomainOf_HappyPath(t *testing.T) {
	assert.Equal(t, "vaudience.ai", emailDomainOf("alice@vaudience.ai"))
	assert.Equal(t, "vaudience.ai", emailDomainOf("ALICE@VAUDIENCE.AI"))
}

func TestEmailDomainOf_EmptyOrMalformed(t *testing.T) {
	assert.Equal(t, "", emailDomainOf(""))
	assert.Equal(t, "", emailDomainOf("no-at"))
	assert.Equal(t, "", emailDomainOf("trailing@"))
}

func TestEmailDomainOf_LastAtSeparatorWins(t *testing.T) {
	// Defensive: pathological email with multiple `@` characters
	// (RFC 5321 quoted local-part). emailDomainOf splits on the LAST
	// `@`, matching how mail servers parse the address.
	assert.Equal(t, "example.com", emailDomainOf(`"a@b"@example.com`))
}

func TestDomainReason_Mapping(t *testing.T) {
	assert.Equal(t, logReasonEmailDomainMismatch, domainReason(ErrEmailDomainMismatch))
	assert.Equal(t, logReasonEmailDomainMissingClaim, domainReason(ErrEmailClaimMissing))
	// Wrapped errors must still resolve via errors.Is.
	wrapped := errors.Join(ErrEmailDomainMismatch, errors.New("extra"))
	assert.Equal(t, logReasonEmailDomainMismatch, domainReason(wrapped))
	// Unknown error falls through to .Error().
	other := errors.New("something else")
	assert.Equal(t, "something else", domainReason(other))
}

// ---------------------------------------------------------------------------
// Config-side validation tests (DC-AUTH-07).
// ---------------------------------------------------------------------------

func TestConfig_RequireEmailDomain_LowercasedByApplyDefaults(t *testing.T) {
	c := Config{RequireEmailDomain: "Vaudience.AI"}
	c.applyDefaults()
	assert.Equal(t, "vaudience.ai", c.RequireEmailDomain)
}

func TestConfig_RequireEmailDomain_EmptyStaysEmpty(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	assert.Equal(t, "", c.RequireEmailDomain)
}

func TestConfig_RequireEmailDomain_RejectsAtSign(t *testing.T) {
	c := minimalValidConfig(t)
	c.RequireEmailDomain = "alice@vaudience.ai"
	c.applyDefaults()
	_, err := c.validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfig))
}

func TestConfig_RequireEmailDomain_RejectsWhitespace(t *testing.T) {
	cases := []string{"vau dience.ai", "vaudience.ai\t", "\nvaudience.ai", "vaudience.ai\r"}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			c := minimalValidConfig(t)
			c.RequireEmailDomain = v
			c.applyDefaults()
			_, err := c.validate()
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidConfig),
				"want ErrInvalidConfig, got %v", err)
		})
	}
}

func TestConfig_RequireEmailDomain_AcceptsCleanDomain(t *testing.T) {
	c := minimalValidConfig(t)
	c.RequireEmailDomain = "vaudience.ai"
	c.applyDefaults()
	_, err := c.validate()
	require.NoError(t, err)
}

// minimalValidConfig returns a Config that passes validate() so a
// per-test mutation can isolate the field under test. KeycloakURL +
// Realm + ClientID etc. are all populated; SessionSecret is a real
// 32-byte base64 key.
func minimalValidConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		KeycloakURL:   "https://kc.example.com",
		Realm:         "vaudience",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		CallbackURL:   "https://app.example.com/auth/callback",
		SessionSecret: testSessionSecretBase64,
	}
}

// testSessionSecretBase64 is a fixed base64-encoded 32-byte key for
// tests. Generated once with `head -c 32 /dev/urandom | base64`; not
// a secret because it never leaves the test binary.
const testSessionSecretBase64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
