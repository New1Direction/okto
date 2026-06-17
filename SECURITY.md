# Security Policy

Okto is an alpha HTTPS-intercepting proxy for local agent traffic. Use it only on systems, accounts, and networks you control.

## Sensitive data

Okto can observe request/response headers, streamed model output, tool payloads, and agent session metadata. Local captures are written under `~/.okto/sessions` by default. Do not share session logs until you have reviewed and redacted them.

Local CA material is generated under `~/.okto/certs`. Never commit these files.

## Reporting issues

Please open a private security advisory on GitHub, or contact the maintainer directly if private advisories are not enabled yet. Include:

- affected version or commit,
- reproduction steps,
- expected vs. actual behavior,
- whether credentials, session logs, or local CA material could be exposed.

## Supported versions

Before a 1.0 release, only the latest `main` branch is supported for security fixes.
