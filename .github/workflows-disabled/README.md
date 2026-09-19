# Retired GitHub Actions workflows

**Status: RETIRED by operator decision (2026-09-19). Not parked pending re-enable.**

GitHub Actions has been retired across vAudience repositories. Every check that
used to run in CI now runs locally, in a standard gate:

```bash
make ci-local
```

`ci-local` is required to be **at least as complete and strict** as the CI it
replaces. It fails on the first error; a missing tool is a **failure** with an
install command, never a skip.

## What each retired CI step maps to

The retired workflow is `ci.yml` in this directory.

| Retired CI step (`ci.yml`)                        | Local gate       |
|---------------------------------------------------|------------------|
| `go build ./...`                                   | `make build`     |
| `go vet ./...`                                     | `make vet`       |
| `go test -race -coverprofile=coverage.out ./...`   | `make test`      |
| `golangci-lint-action@v8` (`version: v2.3.0`)      | `make lint`      |
| `govulncheck ./...` (installed at `v1.1.4`)        | `make vuln`      |
| — (not in CI; added here)                          | `make fmt-check` |

`make lint` runs the locally installed `golangci-lint` against the repo's
existing `.golangci.yml` (v2 format, curated `standard` set plus `gofmt`) —
unchanged by this cutover. The Makefile records `v2.3.0` as the version to
install, matching what the retired action pinned.

`make fmt-check` is an addition, not a mapping. `gofmt -l` prints offending file
names and still exits 0, so the target asserts that its output is **empty**.
(The `gofmt` formatter inside `.golangci.yml` covers the same ground; the
explicit target makes the failure legible without reading lint output.)

## A note on `make vuln` and the toolchain pin

`go.mod`'s `toolchain` directive exists, by its own comment, to select a patched
1.25.x that is **govulncheck-clean**. It said `go1.25.12`, and four new standard
library advisories (`GO-2026-5971/5972/5026` and one more) have since landed with
fixes in `go1.25.13` — so `govulncheck ./...` reported four called-vulnerability
findings on a clean tree. The pin is now `go1.25.13`. This does **not** raise the
consumer floor: the `go` directive stays at `1.25.0`.

Expect this pin to need bumping again whenever a new stdlib advisory lands. That
maintenance used to be invisible, because `setup-go` resolved `go-version: '1.25'`
to the newest patch on the runner and quietly ignored the pin.

## What this does NOT cover

- **OS matrix.** CI ran on `ubuntu-latest`. The local gate runs on whatever the
  developer's machine is. Nothing verifies macOS or Windows behaviour.
- **Go version matrix.** CI requested `go-version: '1.25'` and got whatever the
  newest 1.25.x on the runner was, regardless of the `toolchain` pin. The local
  gate builds with exactly the pinned toolchain. Neither arrangement tests the
  `go.mod` floor (`go 1.25.0`) or any newer major release.
- **Coverage reporting.** `make test` writes `coverage.out`
  (`go tool cover -html=coverage.out` to read it). Nothing is uploaded and no
  coverage trend is tracked anywhere. (The retired workflow wrote the profile but
  never uploaded it either, so nothing is lost here.)
- **Enforcement on push/PR.** These checks ran automatically on every push and
  every pull request. Nothing runs them automatically now — running
  `make ci-local` before you push is a human responsibility.
- **A clean-checkout guarantee.** CI started from a fresh `actions/checkout`. The
  local gate runs against your working tree, including untracked files.
- **A freshly resolved module graph.** CI hit the proxy on every run. Locally you
  are using your module cache; this repo's retired workflow had no
  `go mod verify` step, and neither does the local gate.

## Re-enabling (not planned)

`git mv .github/workflows-disabled/ci.yml .github/workflows/` would restore it.
This is recorded for completeness only; the decision is retirement.
