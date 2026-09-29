# Security Policy

Piper intercepts and decrypts network traffic and manages a local root certificate, so we take
security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/hkiam/piper/security/advisories/new)
("Security" tab → "Report a vulnerability"). Please include:

- the affected version or commit,
- your platform (macOS / Windows / Linux and version),
- steps to reproduce, and the impact you observed or expect.

We aim to acknowledge reports within a few working days, keep you informed about the fix, and
credit you in the release notes if you wish.

## Scope

Especially relevant are issues in:

- certificate generation, storage or trust handling (`crates/piper-tls`),
- the proxy and TLS interception (`crates/piper-proxy`),
- automatic authentication and credential storage (`crates/piper-auth`, `crates/piper-platform`),
- sandboxing of scripts (`crates/piper-script`) and WASM plugins (`crates/piper-plugin-host`),
- remote-connection handling (allow-list, landing page),
- restoring the system proxy after exit or crash.

## Supported versions

Piper is in early preview. Security fixes are made on `main` and shipped in the next release.
