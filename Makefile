# go-vai-oidc local gate.
#
# GitHub Actions is retired for this repository (operator decision, 2026-09-19).
# `make ci-local` IS the gate now: it runs everything the old .github/workflows/ci.yml
# ran, minus the things a dev box cannot do.
#
# A missing tool is a FAILURE, never a skip: a check that cannot run must not
# report success.

GO                ?= go
GOLANGCI_LINT     ?= golangci-lint
GOLANGCI_VERSION   = v2.3.0
GOLANGCI_INSTALL   = go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
GOVULNCHECK_VERSION = v1.8.0
COVERPROFILE      ?= coverage.out
# TOOLBIN keeps the pinned scanner out of the developer's GOPATH/bin, so the version this
# gate runs is the version this Makefile names and not whatever was installed last.
TOOLBIN           := $(CURDIR)/.tools

# TOOLCHAIN_PIN is DERIVED from go.mod, never copied.
#
# ⛔ THE VULN GATE MUST ANALYSE THE TOOLCHAIN THE PIN SELECTS, AND IT DID NOT.
# go-vai-oidc#9 measured the general shape — "the check and the thing being checked were
# never the same artifact" — against `setup-go`, which ignores the a toolchain directive.
# The local gate that replaced it reproduced the SAME defect one box over: `GOTOOLCHAIN`
# defaults to `auto`, which takes the MAXIMUM of the module's requirement and whatever is
# installed. So on any developer machine with a newer Go than the pin, `make vuln` reported
# on a stdlib the pin does not select, and reported it clean.
#
# ⚠️ It is asymmetric and therefore quiet: the gate can only ever be MORE up to date than
# the artifact, so it fails open, forever, and the pin ages behind a green run.
#
# ⚠️ Derived with `awk` rather than written out, because a literal here would be a second
# copy of the pin — and a second copy that silently disagrees is the exact failure this
# whole target exists to catch. `TestVulnGateUsesThePinnedToolchain` fails the build if
# anybody replaces the derivation with a constant.
TOOLCHAIN_PIN     := $(shell awk '$$1 == "toolchain" { print $$2 }' go.mod)

.DEFAULT_GOAL := help
.NOTPARALLEL:
.PHONY: help ci-local fmt-check build vet test lint vuln clean

help:
	@echo "go-vai-oidc local gate (replaces GitHub Actions)"
	@echo ""
	@echo "  make ci-local    run the full gate: fmt-check build vet test lint vuln"
	@echo ""
	@echo "  make fmt-check   fail if any file is not gofmt-clean"
	@echo "  make build       go build ./..."
	@echo "  make vet         go vet ./..."
	@echo "  make test        go test -race -coverprofile=$(COVERPROFILE) ./..."
	@echo "  make lint        golangci-lint run ./... (config: .golangci.yml)"
	@echo "  make vuln        govulncheck ./..."
	@echo "  make clean       remove $(COVERPROFILE)"
	@echo ""
	@echo "  tools: golangci-lint $(GOLANGCI_VERSION), govulncheck $(GOVULNCHECK_VERSION)"
	@echo "  vuln runs at the go.mod toolchain pin: $(TOOLCHAIN_PIN)"

ci-local: fmt-check build vet test lint vuln
	@echo ""
	@echo "ci-local: PASS"

# gofmt -l PRINTS the offending file names and exits 0, so the exit code alone
# proves nothing. Fail when the output is non-empty.
fmt-check:
	@echo "==> gofmt -l ."
	@out="$$(gofmt -l . )"; \
	if [ -n "$$out" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$out"; \
		echo "run: gofmt -w ."; \
		exit 1; \
	fi; \
	echo "gofmt: clean"

build:
	@echo "==> go build ./..."
	$(GO) build ./...

vet:
	@echo "==> go vet ./..."
	$(GO) vet ./...

test:
	@echo "==> go test -race ./..."
	$(GO) test -race -coverprofile=$(COVERPROFILE) ./...

lint:
	@echo "==> golangci-lint run ./..."
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "ERROR: golangci-lint is not installed; the lint gate cannot run."; \
		echo "install it with:"; \
		echo "    $(GOLANGCI_INSTALL)"; \
		exit 1; \
	}
	$(GOLANGCI_LINT) run ./...

# vuln runs govulncheck AT THE PINNED TOOLCHAIN and at a PINNED SCANNER VERSION.
#
# ⭐ THE TWO TOOLCHAINS ARE DELIBERATELY DIFFERENT, and conflating them is what the first
# attempt at this fix got wrong. The SCANNER is built with whatever toolchain can build it
# (govulncheck v1.8.0 itself requires Go >= 1.26, so forcing the module's pin on the build
# fails outright). The ANALYSIS runs at `GOTOOLCHAIN=$(TOOLCHAIN_PIN)`, because that is the
# stdlib the pin actually selects — and govulncheck reports the Go version it analysed, so
# the claim is checkable rather than asserted (`GOTOOLCHAIN=x govulncheck -version`).
#
# ⚠️ `go install` at a pinned version rather than a PATH lookup, for the reason the fleet
# already paid for once in forgebox: a PATH check proves the tool EXISTS and says nothing
# about which version ran, so a stated pin is documentation. It is module-cached after the
# first run. A missing tool is still a failure and never a skip.
vuln:
	@if [ -z "$(TOOLCHAIN_PIN)" ]; then \
		echo "ERROR: go.mod has no a toolchain directive, so the vulnerability gate cannot"; \
		echo "know which stdlib to analyse. Either restore the pin or delete this guard"; \
		echo "deliberately — an unpinned gate that reports clean is worse than no gate."; \
		exit 1; \
	fi
	@echo "==> installing govulncheck $(GOVULNCHECK_VERSION) (built with the default toolchain)"
	@GOBIN=$(TOOLBIN) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@echo "==> govulncheck ./...  (GOTOOLCHAIN=$(TOOLCHAIN_PIN), scanner $(GOVULNCHECK_VERSION))"
	@GOTOOLCHAIN=$(TOOLCHAIN_PIN) $(TOOLBIN)/govulncheck -version | head -2
	GOTOOLCHAIN=$(TOOLCHAIN_PIN) $(TOOLBIN)/govulncheck ./...

clean:
	rm -f $(COVERPROFILE)
