#!/usr/bin/env bash
# Purpose: VAI-SEC-002 secret scan, run locally by `make ci-local` (GitHub Actions are disabled
# on vAudience repos since 2026-11-21; this replaces .github/workflows/security.yml 1:1).
# Same pinned binary as the retired workflow: gitleaks 8.30.1, verified by sha256 before use.
# Scans the FULL git history, redacted, and fails on any finding.
# A finding is never "fixed" by rewriting history: rotate the secret, then add its fingerprint to
# .gitleaksignore with a comment naming the rotation (or the reason it is a false positive).
set -euo pipefail

GITLEAKS_VERSION="8.30.1"
GITLEAKS_SHA256_LINUX_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *) echo "ci-gitleaks: only linux/x86_64 has a pinned checksum; refusing to run an unverified binary" >&2; exit 2 ;;
esac

cache="${XDG_CACHE_HOME:-$HOME/.cache}/vai-ci/gitleaks-${GITLEAKS_VERSION}"
bin="${cache}/gitleaks"
if [[ ! -x "${bin}" ]]; then
  mkdir -p "${cache}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  curl -fsSL -o "${tmp}/gitleaks.tgz" "${url}"
  echo "${GITLEAKS_SHA256_LINUX_X64}  ${tmp}/gitleaks.tgz" | sha256sum -c - >/dev/null
  tar -xzf "${tmp}/gitleaks.tgz" -C "${tmp}" gitleaks
  install -m 0755 "${tmp}/gitleaks" "${bin}"
fi

"${bin}" version >/dev/null
exec "${bin}" git --redact --no-banner --exit-code 1 "$(git rev-parse --show-toplevel)"
