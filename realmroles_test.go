package vaioidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractRealmRoles(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]interface{}
		want   []string
	}{
		{
			name: "standard Keycloak shape",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"obol-system-admin", "offline_access"},
				},
			},
			want: []string{"obol-system-admin", "offline_access"},
		},
		{
			name:   "claim absent",
			claims: map[string]interface{}{"email": "a@b.com"},
			want:   nil,
		},
		{
			name:   "realm_access not an object",
			claims: map[string]interface{}{"realm_access": "not-an-object"},
			want:   nil,
		},
		{
			name: "roles not an array",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{"roles": "obol-system-admin"},
			},
			want: nil,
		},
		{
			name: "roles array with non-string entries skips them",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{"roles": []interface{}{"admin", 42, "member"}},
			},
			want: []string{"admin", "member"},
		},
		{
			name: "empty roles array",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{"roles": []interface{}{}},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRealmRoles(tt.claims)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUser_HasRealmRole(t *testing.T) {
	tests := []struct {
		name string
		user *User
		role string
		want bool
	}{
		{"present", &User{RealmRoles: []string{"obol-system-admin", "offline_access"}}, "obol-system-admin", true},
		{"absent", &User{RealmRoles: []string{"offline_access"}}, "obol-system-admin", false},
		{"nil roles", &User{}, "obol-system-admin", false},
		{"nil user", nil, "obol-system-admin", false},
		{"case-sensitive mismatch", &User{RealmRoles: []string{"Obol-System-Admin"}}, "obol-system-admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.user.HasRealmRole(tt.role))
		})
	}
}
