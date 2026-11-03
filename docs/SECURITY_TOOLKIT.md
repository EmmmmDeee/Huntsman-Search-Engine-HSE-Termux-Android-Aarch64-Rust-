# Canonical Rust security-tool integrations

## Contract and boundary

The nine names below identify *workflows*, not bundled or vendored upstream
programs. HUNTSMAN is a single native Rust binary. The canonical registry is
`src/security_toolkit.rs`; both the CLI and the guarded Web API serialize that
same static registry. A listed subset is not full tool parity. The upstream
tools are not subprocess dependencies. Existing provider credentials, results,
rate limits and evidence provenance remain owned by their original modules.

| Upstream family | Rust owner | Delivered behavior | Explicitly absent |
| --- | --- | --- | --- |
| John the Ripper | `security_toolkit::audit_sha256` | bounded offline raw unsalted SHA-256 audit | formats, masks, rules, GPU |
| Hashcat | shared SHA-256 audit, not a second engine | CPU-only candidate verification | kernels, GPU, rule/mode parity |
| Burp Suite | `http`, `fetch`, `mitm_guard`, `security_web` | guarded HTTP, TLS posture and native security headers | proxy, interception, replay/scanner |
| SQLmap | no owner | no SQLi tests | all SQLmap testing features |
| DIRB | `security_web`, `domain_cli`, `wayback_cdx`, `common_crawl` | bounded, consent-gated HTTPS path probes plus historical leads | recursion, extensive signatures, extensions |
| Aircrack-ng | `wifi_radar`, `mitm_guard` | OS-cached radio metadata | monitor mode, injection and cracking |
| Subfinder | `submd`, `crtsh`, `certspotter` and DNS providers | passive discovery with source evidence | full provider/configuration parity |
| ExifTool | `exif`, `docmeta` | bounded local metadata parsing | all writable/rare metadata |
| theHarvester | domain/email/search providers and pivots | public domain contact/infrastructure leads | complete provider/CLI format parity |

## Canonical entry points

- `huntsman-recon security-tools catalog` — bounded native JSON inventory.
- `huntsman-recon security-tools sha256-audit HEX_SHA256 WORDLIST` —
  compares a single **raw, unsalted** hexadecimal SHA-256 digest against each
  byte-exact line of a local file. Input is capped at 2 MiB; lines longer than
  256 bytes or containing NUL are rejected and counted. Leading/trailing
  spaces are significant, CRLF is recognized. The report prints only counts,
  a Boolean, and the matching line number; it never prints a candidate.
  A negative match exits successfully because it is a valid audit outcome.
- `huntsman-recon security-tools headers HTTPS_ORIGIN` — one read-only,
  anonymous HTTPS request, reports HTTP status, security-header presence
  and cookie attribute counts without exposing cookie contents.
- `huntsman-recon security-tools paths HTTPS_ORIGIN WORDLIST --authorized` —
  opt-in anonymous HTTPS GET enumeration. Maximum 16 unique relative
  ASCII paths and 8 KiB input. Sequential at 150 ms intervals, 7-second
  per-request timeout and 2 KiB per-response maximum. No cookies,
  query strings, redirects or private egress. One missing-path baseline
  reduces simple wildcard false positives; all hits remain *leads*.
- `GET /api/security-tools` — guarded, read-only JSON catalogue. The
  embedded Web UI displays it at **Tools**, along with explicit gaps.
- Existing `domain`, `exif`, `docmeta`, `radar`, `mitm`, `query` and
  `osint lookup` commands remain the sole owners of their workflows.

## Safety and resource invariants

This integration introduces only explicit, single-origin HTTPS security checks and requires no API
keys or third-party executables. All new network calls use the existing public-only egress guard; no Android root, packet injection, radio
monitor mode, GPU access, interception CA, browser proxy, or runtime LLM is
assumed. It doesn't claim a SHA-256 candidate check is equivalent to a
salted, stretched password hash/KDF audit. Do not use weak unsalted SHA-256
for newly stored passwords.

HTTP and CLI return the same inventory and describe unimplemented features
honestly. The network-capable existing commands are separately subject to
their established egress/credential controls. The Web UI doesn't accept
candidate password lists.

## Verification gates

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --all-targets`
4. `huntsman-recon security-tools catalog` — exactly nine unique IDs;
   the unavailable SQLmap entry must never be reported as functioning.
5. `huntsman-recon security-tools sha256-audit HASH FILE` — positive,
   negative, malformed hash, CRLF, binary line, and oversized-list cases.
6. `GET /api/security-tools` on loopback — JSON count nine; public bind
   without a bearer token — HTTP 401.
7. Termux Android AArch64 — repeat CLI and page testing against the actual
   device binary. A Linux CI pass is not evidence of Android sensor access.

**Release policy:** Merge only after actual CI and relevant acceptance tests
complete. No claim of feature parity or a functional Termux binary follows
from adding a registry or opening a pull request.
