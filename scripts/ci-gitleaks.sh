#!/usr/bin/env bash
# Purpose: VAI-SEC-002 secret scan, run locally by `make ci-local` (GitHub Actions are disabled
# on vAudience repos since 2026-11-21; this replaces .github/workflows/security.yml).
# Same pinned binary as the retired workflow: gitleaks 8.30.1. The release tarball AND the extracted
# binary are pinned by sha256; the cached binary is re-verified on every run.
# Scope: the full history of every LOCAL ref (`gitleaks git`), so it is stricter than the workflow's
# checkout: unpushed local branches are scanned too. A shallow clone is refused (the workflow forced
# fetch-depth: 0), because a truncated history would scan clean.
# A finding is never "fixed" by rewriting history: rotate the secret, then add its fingerprint to
# .gitleaksignore with a comment naming the rotation (or the reason it is a false positive).
set -euo pipefail

GITLEAKS_VERSION="8.30.1"
GITLEAKS_TGZ_SHA256_LINUX_X64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
GITLEAKS_BIN_SHA256_LINUX_X64="88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *) echo "ci-gitleaks: only linux/x86_64 has a pinned checksum; refusing to run an unverified binary" >&2; exit 2 ;;
esac

root="$(git rev-parse --show-toplevel)"
if [[ "$(git -C "${root}" rev-parse --is-shallow-repository)" != "false" ]]; then
  echo "ci-gitleaks: shallow clone; the scan needs the full history. Run: git fetch --unshallow" >&2
  exit 2
fi

cache="${XDG_CACHE_HOME:-$HOME/.cache}/vai-ci/gitleaks-${GITLEAKS_VERSION}"
bin="${cache}/gitleaks"

verify_bin() { echo "${GITLEAKS_BIN_SHA256_LINUX_X64}  ${bin}" | sha256sum -c - >/dev/null 2>&1; }

if [[ ! -x "${bin}" ]] || ! verify_bin; then
  mkdir -p "${cache}"
  tmp="$(mktemp -d)"
  url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  if ! curl -fsSL -o "${tmp}/gitleaks.tgz" "${url}" \
    || ! echo "${GITLEAKS_TGZ_SHA256_LINUX_X64}  ${tmp}/gitleaks.tgz" | sha256sum -c - >/dev/null \
    || ! tar -xzf "${tmp}/gitleaks.tgz" -C "${tmp}" gitleaks \
    || ! echo "${GITLEAKS_BIN_SHA256_LINUX_X64}  ${tmp}/gitleaks" | sha256sum -c - >/dev/null; then
    rm -rf "${tmp}"
    echo "ci-gitleaks: download or checksum verification failed" >&2
    exit 2
  fi
  # Atomic: a concurrent or interrupted install never leaves a half-written executable.
  install -m 0755 "${tmp}/gitleaks" "${bin}.tmp.$$"
  mv -f "${bin}.tmp.$$" "${bin}"
  rm -rf "${tmp}"
  verify_bin || { echo "ci-gitleaks: installed binary failed its checksum" >&2; exit 2; }
fi

"${bin}" version >/dev/null
exec "${bin}" git --redact --no-banner --exit-code 1 "${root}"
