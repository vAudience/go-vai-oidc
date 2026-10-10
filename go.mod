module github.com/vAudience/go-vai-oidc

go 1.25.0

// Build with a patched toolchain that clears the current stdlib advisories
// (govulncheck-clean). This does NOT raise the consumer floor — the `go`
// directive above stays at 1.25.0 — it only selects the toolchain that builds
// this module. v0.32.0: 1.26.9, because the 1.25 line has no fix for the
// GO-2026-66xx net/http, net/textproto and crypto/tls advisories.
toolchain go1.26.9

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
