package vaioidc

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	key := make([]byte, aesKeyLength)
	for i := range key {
		key[i] = byte(i)
	}
	return Config{
		KeycloakURL:   "https://keycloak.example.com",
		Realm:         "testrealm",
		ClientID:      "testclient",
		ClientSecret:  "secret",
		CallbackURL:   "https://app.example.com/auth/callback",
		SessionSecret: base64.StdEncoding.EncodeToString(key),
		Logger:        slog.Default(),
	}
}

func TestConfig_ApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()

	assert.Equal(t, defaultLogoutRedirect, cfg.LogoutRedirect)
	assert.Equal(t, defaultSessionTTL, cfg.SessionTTL)
	assert.Equal(t, defaultCookieName, cfg.CookieName)
	assert.Equal(t, defaultCookiePath, cfg.CookiePath)
	assert.Len(t, cfg.Scopes, 3)
	assert.NotNil(t, cfg.Logger)
}

func TestConfig_ApplyDefaults_PreservesExisting(t *testing.T) {
	cfg := Config{
		LogoutRedirect: "/custom",
		SessionTTL:     2 * time.Hour,
		CookieName:     "my_session",
	}
	cfg.applyDefaults()

	assert.Equal(t, "/custom", cfg.LogoutRedirect)
	assert.Equal(t, 2*time.Hour, cfg.SessionTTL)
	assert.Equal(t, "my_session", cfg.CookieName)
}

func TestConfig_Validate_Success(t *testing.T) {
	cfg := validConfig()
	cfg.applyDefaults()
	key, err := cfg.validate()
	require.NoError(t, err)
	assert.Len(t, key, aesKeyLength)
}

func TestConfig_Validate_MissingRequired(t *testing.T) {
	tests := []struct {
		name  string
		mutate func(*Config)
	}{
		{"KeycloakURL", func(c *Config) { c.KeycloakURL = "" }},
		{"Realm", func(c *Config) { c.Realm = "" }},
		{"ClientID", func(c *Config) { c.ClientID = "" }},
		{"ClientSecret", func(c *Config) { c.ClientSecret = "" }},
		{"CallbackURL", func(c *Config) { c.CallbackURL = "" }},
		{"SessionSecret", func(c *Config) { c.SessionSecret = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.applyDefaults()
			tt.mutate(&cfg)
			_, err := cfg.validate()
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidConfig))
		})
	}
}

func TestConfig_Validate_BadBase64Secret(t *testing.T) {
	cfg := validConfig()
	cfg.applyDefaults()
	cfg.SessionSecret = "not-valid-base64!!!"
	_, err := cfg.validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionKeyInvalid))
}

func TestConfig_Validate_WrongKeyLength(t *testing.T) {
	cfg := validConfig()
	cfg.applyDefaults()
	cfg.SessionSecret = base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err := cfg.validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSessionKeyInvalid))
}

func TestConfig_Validate_HTTPCallbackWithSecureCookie(t *testing.T) {
	// This should succeed but log a warning (InsecureCookie=false + http:// callback).
	cfg := validConfig()
	cfg.applyDefaults()
	cfg.CallbackURL = "http://localhost:8080/auth/callback"
	cfg.InsecureCookie = false // default — secure cookies on http:// should warn
	key, err := cfg.validate()
	require.NoError(t, err, "http + secure cookies should warn, not fail")
	assert.Len(t, key, aesKeyLength)
}
