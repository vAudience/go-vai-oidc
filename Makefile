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
GOVULNCHECK       ?= govulncheck
GOVULNCHECK_VERSION = v1.1.4
GOVULNCHECK_INSTALL = go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
COVERPROFILE      ?= coverage.out

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

vuln:
	@echo "==> govulncheck ./..."
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { \
		echo "ERROR: govulncheck is not installed; the vulnerability gate cannot run."; \
		echo "install it with:"; \
		echo "    $(GOVULNCHECK_INSTALL)"; \
		echo "(and make sure \"\$$(go env GOPATH)/bin\" is on your PATH)"; \
		exit 1; \
	}
	$(GOVULNCHECK) ./...

clean:
	rm -f $(COVERPROFILE)
