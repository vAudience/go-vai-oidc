# Contributing to go-vai-oidc

Thanks for helping improve `go-vai-oidc`. This is a public, generic OIDC Relying
Party library consumed by multiple downstream services that pin release tags, so
backward compatibility is a first-class concern.

## Building and Testing

Before opening a pull request, run the full local gate:

```sh
go build ./...
go test -race ./...
golangci-lint run
govulncheck ./...
```

All four must pass. The race detector is **non-negotiable** — every test run uses
`-race`, and no PR is merged with data races.

## House Rules

- **Table-driven tests** using `github.com/stretchr/testify` for assertions.
- **Named constants over magic strings** — no bare literals for keys, header names,
  claim names, cookie names, or durations.
- **Additive, backward-compatible within a minor version.** Because downstream
  services pin tags, do not change or remove exported symbols, signatures, or
  behavior in a way that breaks existing consumers. Add; don't break.
- Keep the public API small and well-documented; new exported types and functions
  need doc comments.

## Subpackage Boundaries

The module ships one optional subpackage, `obolresolver/`, a vendor-specific
reference `UserResolver` adapter. It may depend on the root package, but the root
package **must never** depend on `obolresolver/` and must never gain a dependency
introduced solely for it. The root package stays generic and vendor-neutral.

## Pull Request Flow

1. Fork the repository and create a topic branch.
2. Make your change, add/extend table-driven tests, and ensure the full local gate
   above is green.
3. Open a PR describing the change and, explicitly, its **backward-compatibility
   impact** (additive / no API change / potentially breaking).
4. Ensure CI is green before requesting review.
