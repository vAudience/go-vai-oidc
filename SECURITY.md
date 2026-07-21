# Security Policy

`go-vai-oidc` is a generic OpenID Connect Relying Party library for Go. Because it
sits on the authentication path of its consumers, we take security reports seriously.

## Supported Versions

This library is pre-release; there is no long-term-support (LTS) branch yet.

| Version   | Security fixes |
| --------- | -------------- |
| v0.16.x   | Yes (latest minor) |
| < v0.16.0 | No             |

Security fixes land only on the latest minor. Pin a recent tag and upgrade promptly.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** — do **not** open a public
GitHub issue, pull request, or discussion for a security-sensitive defect.

Email **security@vaudience.ai** with:

- A clear description of the issue and its security impact.
- Reproduction steps (or a minimal proof of concept).
- The affected version(s) / commit(s).

We aim to acknowledge new reports within **3 business days** and will coordinate a
fix and disclosure timeline with you from there.

## Scope

This library performs:

- OIDC provider discovery.
- The PKCE authorization-code flow.
- ID-token verification (via `github.com/coreos/go-oidc`).
- Encrypted session cookies (AES-256-GCM).

The following are the **consumer's** responsibility and out of scope for this library:

- Generation, storage, and rotation of the session-encryption secret.
- Correct configuration of the issuer URL, callback/redirect URIs, and client credentials.
- Transport security (TLS) and secure cookie attributes at the deployment boundary.
