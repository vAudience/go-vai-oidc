module github.com/vAudience/go-vai-oidc

go 1.26.0

// The consumer floor is Go 1.26 since v0.40.0 (stack-wide Go 1.26.11 move,
// vaik8s#2284): the stdlib advisories this module has tracked are fixed only on
// the 1.26 line, so a 1.25 floor promised a build nobody should ship. The
// toolchain selects the patched release that is govulncheck-clean. History:
// v0.32.0 1.26.9 (GO-2026-66xx net/http, net/textproto, crypto/tls); v0.34.0
// 1.26.10 (GO-2026-6809, crypto/x509); v0.38.0 1.26.11 (GO-2026-6859, net/http).
toolchain go1.26.11

require (
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/stretchr/testify v1.11.1
	golang.org/x/oauth2 v0.36.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
