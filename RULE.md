# THE RULES

Huntsman Search Engine (HSE) is an evidentiary OSINT/GEOINT/NETINT engine.
Every claim it emits will be acted on. False confidence is worse than missing
coverage. These three binding rules exist to keep the engine trustworthy.

---

## RULE 1: Nothing Ships Unless Backed by Verifiable Evidence

**Nothing — code, tests, docs, data, or any finding the engine emits — ships
unless it is backed by verifiable evidence from an authoritative source.**

### Why

HSE's only product is a claim an operator will act on. A false claim that
*looks* true is worse than a missing one, because it is trusted. Every other
quality (speed, coverage, ergonomics) is worthless if the output cannot be
trusted.

### What It Forbids

- **No fabricated findings.** Never emit an entity, evidence record, or
  correlation the code did not actually observe.
- **No assumed API contracts.** Never call an endpoint, pass a parameter, or
  parse a response field you have not confirmed exists in the provider's
  authoritative spec or in a real response. An API you *expect* to work is a
  guess until the provider says otherwise.
- **No synthetic/mocked data passed off as real.** Test fixtures must be labelled
  fixtures. A mock may prove *logic*; it may never stand in as *evidence* that
  a live service behaves a given way.
- **No speculative conclusions.** "Probably", "should", "I assume" are not
  evidence. If the code depends on it, verify it or do not depend on it.

### The Evidence Test

For every external fact a change relies on — every endpoint path, query
parameter, response field, status code, quota, and auth scheme — you must be
able to point at **at least one** of:

1. **Authoritative documentation** — the provider's OpenAPI/Swagger spec, or
   their official API reference.
2. **Real, observed response** — a captured response from the live service.
3. **Reproducible run** — a test that exercises the code path live.

If you can point at none, you have a guess. Guesses do not ship.

### When You Cannot Verify

Say so in the change itself. Mark unverified parts as unverified in code
comments; never present them as fact. "I could not reach the service to
confirm this" is an acceptable, honest state. Silently shipping the guess as
fact is the one thing this rule exists to stop.

### The Cautionary Case

WiGLE's integration called `/api/v2/network/search?type=cell` and `?type=bluetooth`.
WiGLE's authoritative Swagger spec lists **no `type` parameter** on that endpoint —
cell and Bluetooth live under separate endpoints (`/api/v2/cell/search`,
`/api/v2/bluetooth/search`). A parameter the server never reads is silently ignored,
so those calls returned Wi-Fi rows that the code then labelled as cell/Bluetooth
intelligence: **a fabricated finding, produced by an unverified API assumption.**
One look at the authoritative spec would have caught it. That look is now mandatory.

---

## RULE 2: The Latest Query Must Always Be Followed Exactly

**When given a directive, the latest (most recent) instruction supersedes all
prior instructions. It must be followed exactly as stated, without omission,
reinterpretation, or negotiation.**

### Why

In a fast-paced, evidence-driven development cycle, priorities shift. The most
recent query reflects the current intent. Ignoring it or second-guessing it
introduces delay and compounds errors. Respect the user's direction by taking it
at face value.

### What It Means

- If an earlier directive said "do A" and a later one says "do B instead",
  follow B.
- Do not assume an old priority still holds unless restated. Do not split the
  difference.
- Do not ask for clarification unless truly blocked. Take the directive as
  written.
- Do not substitute your own judgment about what the user "really meant". If the
  instruction is ambiguous, take the most literal reading.
- Apply this rule to every directive: code changes, documentation updates, API
  investigation, feature requests, refactoring — all of it.

### When You Are Unsure

Ask via a direct question **before** work, not after. Once you understand the
intent, execute it as stated. Do not hedge or reinterpret in execution.

---

## RULE 3: Automatically Harvest All API Keys

**Every API key pattern recognized by HSE must be automatically detected,
extracted, and banked whenever HSE processes any data — whether from breach
dumps, stealer logs, response bodies, or any other source. No key detection is
optional; no pattern goes unharvested.**

### Why

An API key is not just a credential — **which provider it belongs to is itself
intelligence.** A key for Shodan, Dehashed, Hunter, OathNet, SeekNow, or any
OSINT provider found in a victim's data says the holder **runs OSINT**. They are
a fellow practitioner, an investigator, a researcher, or an adversary doing
reconnaissance. That makes the key a first-class OSINT **pivot**: from the
key's provider you learn the holder's tradecraft, tooling, and likely intent.

Missing a harvestable key is missing a lead. Every pattern, every time, always.

### What It Means

- **Automatic extraction:** Every module that processes external data (breach
  results, API responses, HTML, JSON, logs, emails, etc.) must call the key
  harvester for API key patterns.
- **No skipping:** Do not decide "this field isn't where keys usually live" or
  "this provider is unlikely to include API keys". Extract from every data
  point.
- **Recognise 80+ patterns:** HSE's key catalogue covers Shodan, Hunter, Dehashed,
  IntelX, OathNet, SeekNow, WiGLE, HIBP, VirusTotal, Censys, ZoomEye, and many
  others. Use the authoritative pattern set in `core::keys::PATTERNS` or the
  equivalent live pattern catalogue.
- **Bank every find:** Each harvested key is stored with its provider
  classification, source context (module, endpoint, timestamp), and usage status.
  The key becomes a dossier pivot — an entity in its own right.
- **Surface intent signals:** A harvested key's provider category (breach-leak,
  attack-surface, threat-intel, email-people, ip-geo, domain-cert, social-link-analysis)
  tags the holder's operational profile. Wire this signal into correlations so
  the operator knows "this entity was running Shodan recon" or "this email was
  in a stealer log alongside a hunter.io key".

### When You Cannot Harvest

If an API key pattern exists but HSE does not yet recognize it:

1. Document it plainly: `// Unrecognised API key pattern found in response:
   <description>. Pattern not yet in HSE's catalogue.`
2. Log its presence (not its value) with source context.
3. Add the pattern to the roadmap so it gets integrated in the next cycle.

Never silently drop a key because HSE doesn't recognize it yet. Make the
absence visible.

---

# OPERATIONAL DOCUMENTATION

## Installation (Termux Android aarch64, no root)

The **one-line install** — it always tracks the latest `main`, does everything,
and is safe to re-run (re-running upgrades an existing install in place):

**Termux prerequisite:** Install from
[F-Droid](https://f-droid.org/packages/com.termux/) or [GitHub
release](https://github.com/termux/termux-app/releases) — not the Play Store
(abandoned 2020, broken packages).

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

It installs the toolchain (Rust, clang, binutils, git), clones or updates the
source, builds the release binary, installs `hse` to `$PREFIX/bin`, sets up
`hse-bg` background wrapper + optional Termux:Boot autostart, and runs `hse
doctor` to verify. Existing installs are fully handled — your `~/.huntsman.env`
keys are preserved, the binary swaps atomically, and a running `hse-bg` restarts
on the new build. Idempotent.

**No-build fast path:** Prefers a precompiled aarch64 binary from Downloads or
GitHub Releases (size + ELF + `.sha256` verified) over a source compile. This
is also the fallback if the on-device build fails (e.g. broken Termux `rust`
package). After a source build, the binary is cached to Downloads for the next
install. Knobs: `HSE_PREBUILT=/path/to/hse`, `HSE_PREBUILT_TAG=vX.Y.Z`,
`HSE_NO_DOWNLOAD=1`, `HSE_PREFER_BUILD=1`, `HSE_KEEP_MIRROR=1`.

Also works on Debian/Ubuntu and macOS. Full log at `~/.cache/hse-install.log`.
See `docs/INSTALL.md` for every install path, knob, and Termux quirk.

### After Install

```bash
hse --version        # confirm install
hse doctor           # environment report
hse-bg start         # start web server with Android wake-lock
# Open Chrome → http://127.0.0.1:8080
```

### Web UI

Launch the UI:

```bash
hse serve   # binds 127.0.0.1:8080 (loopback only)
```

Open **Chrome** on the phone and go to `http://127.0.0.1:8080`. You get a
dark-console UI — **Dashboard · New Scan · Scans · Live · Engines · Settings**
— where **New Scan** drives the engine. Each scan's results page tabs through a
sortable entity browser, a D3 force graph, severity-tagged correlations, and a
real-time (SSE) event log. The **Settings** page lets you paste & save API keys
straight from the browser (loopback-only, keys never leave the device).

**Web & API scans are as thorough as the CLI.** A scan launched from the Chrome
SPA's **New Scan** wizard, or via `POST /api/v1/scans`, uses the same
comprehensive defaults as `hse scan` — depth 3, expansion floor 0.20, entity cap
2500 — so you get the full seed → identifiers → pivots → infrastructure sweep
without tuning anything.

**Termux battery & background (required for long scans):** Android Settings →
Apps → Termux → Battery → **Unrestricted** and enable "Allow background data".
Without this Android kills Termux mid-scan.

---

## Setup & Configuration: SeekNow API

HSE **automatically** uses the SeekNow API for breach + stealer + OSINT
intelligence across 212M+ records and 70+ data sources. Just add your API key
— HSE handles everything else: endpoint routing, budget management, credit
detection, error recovery, request caching, and response archiving.

**Official SeekNow API:** https://see-know.eu/api/v1 (24 endpoints, 99.97% uptime)

### Quick Start (2 minutes)

**1. Get Your SeekNow API Key**

1. Sign up at [see-know.eu](https://see-know.eu/signup) and verify your account.
2. Go to **Account → API Dashboard**: https://see-know.eu/account/dashboard.
3. Copy your active key (starts with `seek-`, typically 64+ characters).
4. Check your **plan tier** (Beginner/Pro/PremiumHQ/Enterprise) and daily credit
   limit.

**2. Add Your Key to HSE (Automatic Setup)**

```bash
echo 'export HUNTSMAN_SEEKNOW_KEY="seek-your-api-key-here"' >> ~/.huntsman.env
```

HSE **automatically**:
- Uses the official `https://see-know.eu/api/v1` endpoint.
- Detects your daily credit limit (via `/credits` endpoint — free, no budget
  consumed).
- Routes queries to optimal endpoints by target type.
- Caches responses to avoid duplicate lookups.
- Archives all responses for audit/replay.
- Handles quota exhaustion gracefully.
- Manages request timeouts (75s curl, 78s outer).
- Identifies 80+ API key patterns in leaked data.

**3. Verify the Setup**

```bash
hse doctor

# Expected output:
# ✓ SeekNow: key present
# ✓ SeekNow: quota probe successful — daily limit 15000, scan cap 750
```

**Done!** Run your first scan:

```bash
hse scan --kind email --value test@example.com --depth 1
```

### SeekNow Endpoint Coverage (18 of 24 documented endpoints wired)

| Category | Endpoints | Credits | Status |
|----------|-----------|---------|--------|
| **Search** | `/search` | 1 | **Wired** — the universal call, dispatched for every target kind |
| **Search** | `/search/deep` | 1 | **Wired** — fallback when fast `/search` draws a blank on a TYPED query |
| **Stealer Logs** | `/stealer` | 2 | Removed — live-verified 404 against the real API |
| **Social/Gaming** | `/username/{github,twitter,tiktok,reddit,social,history}`, `/discord/{user,to-roblox}`, `/gaming/{xbox,roblox,minecraft,steam}` | 1 each | **Wired** (10 endpoints) |
| **Network** | `/network/{ip,email-check,phone}` | 1 each | **Wired** (3 endpoints) |
| **Domain** | `/domain/{intel,whois}` | 1 each | **Wired** (2 endpoints) |
| **Enterprise** | `/enterprise/discord/{history,messages,export}` | 5 each | Not implemented — Enterprise-plan-gated |
| **Meta** | `/credits` | 0 | **Wired** — used for quota probing and scan-cap scaling |
| **Meta** | `/status` | 0 | Not implemented — informational only |

---

## Troubleshooting

### Installation Errors

**`awk: fatal: attempt to access field -2` during sanity checks**

Seen on Termux 0.118.x where `df -m $HOME` emits a row with too few fields.
Fixed in commit `4ee49ec`. If you still hit it, you're on an older `install.sh`.
Pull the latest and retry, or use the manual install path in `docs/INSTALL.md`
which skips the probe.

**`pkg update: failed`**

- **No network:** Confirm with `ping 1.1.1.1`. Switch to Wi-Fi if on flaky cell.
- **Mirror outage:** Use `termux-change-repo` to pick a different mirror.
- **DNS broken:** Try `pkg --check-mirror update` or set DNS manually:
  `echo 'nameserver 1.1.1.1' > $PREFIX/etc/resolv.conf`.

The installer auto-retries `pkg update` 4 times with exponential backoff.

**`cargo build` fails with `linker 'cc' not found`**

You're missing the C toolchain. On Termux:

```bash
pkg install -y clang make pkg-config
```

The installer does this automatically.

**Build OOMs (`signal: 9, SIGKILL: kill`)**

Cargo runs `rustc` jobs in parallel. On phones with < 1.5 GB free RAM, this
exhausts memory. Workarounds:

```bash
# Limit to one job (slower but reliable):
CARGO_BUILD_JOBS=1 cargo build --release --locked

# Or re-run install.sh — it auto-detects RAM and sets this for you.
```

**`failed to authenticate with the remote: SSL_ERROR_SYSCALL`**

System clock is wrong → TLS handshake fails. Fix:

```bash
pkg install termux-tools
date -s "$(curl -fsSL https://www.google.com -I | awk -F': ' '/^[Dd]ate:/ {sub(/\r$/,""); print $2}')"
```

Then retry the install.

**`error: package XYZ has been yanked from the registry`**

Stale `Cargo.lock`. Update:

```bash
cd ~/.local/share/hse && cargo update && cargo build --release
```

**`Out of disk space`**

Build artifacts and cargo cache can reach 2 GB. Free up:

```bash
rm -rf ~/.cache/hse-build ~/.cargo/registry/cache ~/.cargo/git
```

---

## OSINT API Reference

An extensive, categorised reference of OSINT-relevant APIs for HSE: what each
provider gives you, whether it has a free tier, its API-key shape (for detection
in stealer logs), and HSE's integration/detection status.

### Legend — HSE Status

| Mark | Meaning |
|---|---|
| **M** | Dedicated HSE collector module (queries the provider) |
| **K** | Key-gated — recognised `HUNTSMAN_*` env var / BYO key |
| **D** | Key **detected & banked** when found in a victim/stealer log |
| **C** | Candidate — relevant, not yet integrated |

### Free Tiers

Free tiers and pricing change constantly — *verify before relying on them*. Key
shapes are detection aids, not guarantees: many providers mint bare hex/alnum/UUID
tokens with no distinctive prefix (HSE attributes those by provider domain/context,
not shape alone).

### Key Providers

**Breach / leak / credential exposure**

- Have I Been Pwned (HIBP): M K D
- Dehashed: M K D
- Intelligence X (IntelX): M K D
- Hudson Rock (Cavalier): M D
- OathNet: M K D
- SeekNow (see-know.eu): M K D

**Attack-surface / internet-wide host scanners**

- Shodan: M K D
- Censys: M K D
- ZoomEye: M K D
- Netlas: M K D
- Criminal IP: M K D
- LeakIX: M K D

**Threat intelligence / reputation**

- VirusTotal: M K D
- AbuseIPDB: M K D
- GreyNoise: M K D
- ThreatFox: M K D

**Email / identity / people search**

- Hunter.io: M K D
- Clearbit: M K D
- Pipl: M K D
- Seon: M K D

**Network / IP / geolocation**

- IPinfo: M K D
- IP2Location: M K D
- MaxMind: M K D
- WiGLE: M K D

**Social / username analysis**

- Epieos: M K D

---

## Security Policy

### Supported Versions

The latest tagged release on `main` receives security fixes. Older tags are not
maintained.

### Reporting a Vulnerability

Please report security vulnerabilities **privately** — not via public issues.

Use GitHub's *Report a vulnerability* button on the repository's **Security**
tab (private advisory), or contact the repository owner directly. Include:
- Reproduction steps
- Affected version/commit
- Impact assessment

We aim to acknowledge within a few business days and coordinate disclosure
responsibly.

### Scope and Responsible Use

Huntsman Search Engine is an OSINT/GEOINT and breach-intelligence tool intended
for **authorised use only** — security testing, fraud prevention, due diligence,
and investigations conducted with a lawful basis.

Processing personal data without a lawful basis, or using the tool to harass or
surveil individuals, is outside its intended use and may be unlawful under:
- Australian *Privacy Act 1988*
- EU GDPR
- Your local equivalent

The maintainers provide the software for legitimate use and disclaim
responsibility for misuse.

---

**All three rules are binding. Follow them all. If you cannot, the work is not ready.**
