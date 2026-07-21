# Security Policy

`go-vai-oidc` is a generic OpenID Connect Relying Party library for Go. Because it
sits on the authentication path of its consumers, we take security reports seriously.

## Supported Versions

This library is pre-1.0 (`0.x`). Under semantic versioning a `0.x` minor bump
carries **no backward-compatibility guarantee**, so pin an exact tag
(`go get github.com/vAudience/go-vai-oidc@v0.16.0`) and upgrade deliberately.

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

### `Config.RequireEmailDomain` is a domain filter, not a verification check

The optional email-domain gate matches the `email` claim's **domain** only — it
does **not** inspect `email_verified`. On a multi-tenant IdP where a user could
hold an unverified address in the target domain, do not treat this gate as a
trust boundary. If you need verified-email enforcement, assert `email_verified`
in your `UserResolver` (add it to `Config.ExtraClaims` and check it) or enforce
it at the IdP.
