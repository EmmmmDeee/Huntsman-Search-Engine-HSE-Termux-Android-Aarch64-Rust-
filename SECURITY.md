# Security Policy

## Supported Versions

While HSE is `0.x` only the latest minor version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅        |
| 0.1.x   | ❌        |
| < 0.1   | ❌        |

## Security model

HSE is an OSINT collection tool. By design it makes outbound HTTP requests
to public and key-gated APIs, stores results locally, and runs as your
unprivileged user. It is **not** a sandbox; treat its scan output as you
would any other reconnaissance data — confidential to you and your
authorised investigation.

### What HSE never stores or transmits

These are enforced architecture invariants. Any violation is a security
bug; please report immediately.

- **Passwords, password hashes, plaintext credentials.** Modules that query
  breach/stealer-log sources (`hudsonrock`, future `dehashed`, `oathnet_pro`,
  etc.) deliberately ignore credential fields in API responses. Only
  metadata (machine name, OS, date, count) is recorded.
- **`Credential` and `Password` entity kinds** exist in the schema but
  are never produced by built-in modules.
- **API keys.** Stored only in `$HOME/.huntsman.env` (chmod `0600`) and
  loaded into memory at scan time; never logged, never written to the
  SQLite database, never included in event payloads, never sent to any
  endpoint other than the API that owns the key.
- **Telemetry / phone-home.** None. HSE makes only the HTTP requests that
  active modules explicitly perform.

### What HSE does store

- Scans, entities, evidence, tags — all in `$HOME/.huntsman/huntsman.db`
  (SQLite WAL).
- Build logs in `$HOME/.cache/hse-install.log` (from `install.sh` only).
- A timestamp-mixed scan ID per run.

### Network exposure

- v0.1 / v0.2 ship a CLI only. No listening sockets.
- v0.3+ adds an HTTP server bound to `127.0.0.1:8080` by default — local
  loopback only, no LAN exposure unless you change `DEFAULT_BIND`. CORS is
  permissive to allow Chrome on the device to talk to itself.

## Reporting a vulnerability

**Do not** open a public GitHub issue for security bugs.

Report vulnerabilities privately via GitHub Security Advisories:
<https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/security/advisories/new>

Please include:
- A clear description of the vulnerability and affected components
- Reproduction steps (PoC commands, sample inputs, etc.)
- Affected versions
- Suggested fix, if any

You'll receive an acknowledgement within 7 days. Fixes are normally
released as a patch version within 14 days of confirmation, with a
GitHub Security Advisory and CVE if appropriate.

## Hardening checklist for users

- Run as your unprivileged Termux user; HSE never needs root.
- Set `$HOME/.huntsman.env` to `0600` (the installer does this).
- Keep `cargo install --git ... --locked` so `Cargo.lock` is honoured.
- Review modules' source before enabling key-gated ones — `src/modules/*`
  is the single source of truth for what each module sends and stores.
- Use `--free-only` if you don't want any external paid API contact.
- Use `--passive-only` if you don't want network calls at all (only local
  derivations and, in v0.6+, on-device sensors).
