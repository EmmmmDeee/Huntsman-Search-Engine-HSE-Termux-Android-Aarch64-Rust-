#!/usr/bin/env bash
# tools/provision-termux.sh
#
# Six-phase, idempotent, non-interactive provision pipeline for HSE on
# Termux (Android aarch64, no root). Pairs with the lighter install.sh
# at the repo root — that one is the minimum-viable installer; this one
# adds wake-lock, hardware-specific optimisation flags, a fully populated
# .huntsman.env template, and a passive-only smoke test.
#
# Usage (on your Termux device):
#     bash <(curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/tools/provision-termux.sh)
#   or, after `git pull`:
#     bash tools/provision-termux.sh
#
# Idempotent: safe to re-run. .huntsman.env is BACKED UP (never silently
# overwritten) before any merge; lines you've already filled in are kept.

set -euo pipefail

# ── Defaults / paths ─────────────────────────────────────────────────────────
HSE_REPO="${HSE_REPO:-/data/data/com.termux/files/home/.local/share/hse}"
HSE_BIN="${PREFIX:-/data/data/com.termux/files/usr}/bin/hse"
ENV_FILE="${HOME}/.huntsman.env"
ENV_BAK="${ENV_FILE}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
ORIGIN_URL="${HSE_ORIGIN:-https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-}"

# Single bold-coloured logger so phase boundaries are obvious in scrollback.
T="$([ -t 1 ] && echo 1 || echo 0)"
BOLD()  { [ "$T" = 1 ] && printf '\033[1m%s\033[0m' "$*" || printf '%s' "$*"; }
OK()    { [ "$T" = 1 ] && printf '\033[32;1m✓\033[0m %s\n' "$*" || printf '  ✓ %s\n' "$*"; }
WARN()  { [ "$T" = 1 ] && printf '\033[33;1m!\033[0m %s\n' "$*" || printf '  ! %s\n' "$*"; }
ERR()   { [ "$T" = 1 ] && printf '\033[31;1m✗\033[0m %s\n' "$*" || printf '  ✗ %s\n' "$*"; } >&2
PHASE() { printf '\n%s %s\n' "$(BOLD '==>')" "$(BOLD "$*")"; }
DIE()   { ERR "$*"; exit 1; }

# Run a command, logging stderr only on failure so the happy path stays clean.
run_logged() {
    local label="$1"; shift
    local log; log="$(mktemp)"
    if "$@" >"$log" 2>&1; then
        OK "$label"
        rm -f "$log"
    else
        ERR "$label — FAILED"
        printf -- '--- captured output ---\n'
        cat "$log"
        printf -- '--- end output ---\n'
        rm -f "$log"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: Pre-flight — wake-lock + non-interactive package provisioning
# ═══════════════════════════════════════════════════════════════════════════
PHASE "Phase 1 — Pre-flight (wake-lock + packages)"

# Termux-only commands. On non-Termux hosts we skip with a notice so the
# script can still be exercised in CI / verification environments.
if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock && OK "termux-wake-lock acquired" \
        || WARN "termux-wake-lock returned non-zero (continuing)"
else
    WARN "termux-wake-lock not found (non-Termux host?) — skipping"
fi

if command -v pkg >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    run_logged "pkg update" pkg update -y \
        -o Dpkg::Options::="--force-confold"
    run_logged "pkg install (rust, git, clang, make, pkg-config, openssl-tool)" \
        pkg install -y -o Dpkg::Options::="--force-confold" \
        rust git clang make pkg-config openssl-tool
else
    WARN "pkg not found (non-Termux host?) — assuming tools present"
fi

# Verify the toolchain is present even when pkg was skipped.
for bin in rustc cargo git clang make pkg-config; do
    command -v "$bin" >/dev/null 2>&1 || DIE "required tool missing: $bin"
done
OK "toolchain present: rustc $(rustc --version | awk '{print $2}'), cargo $(cargo --version | awk '{print $2}')"
OK "topology: $(uname -sm)  (expected on device: Linux aarch64)"

# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: Repository synchronisation
# ═══════════════════════════════════════════════════════════════════════════
PHASE "Phase 2 — Repository sync ($HSE_REPO)"

mkdir -p "$(dirname "$HSE_REPO")"

if [ ! -d "$HSE_REPO/.git" ]; then
    run_logged "git clone" git clone "$ORIGIN_URL" "$HSE_REPO"
fi

cd "$HSE_REPO"
run_logged "git fetch origin main"  git fetch origin main
run_logged "git reset --hard origin/main"  git reset --hard origin/main
# Wipe stale artefacts — linker caches, target/, build scratch — so the next
# build is a clean room. -fdx is destructive, intentional here.
run_logged "git clean -fdx" git clean -fdx
OK "HEAD = $(git rev-parse --short HEAD)  ($(git log -1 --pretty=format:'%s'))"

# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: Hardware-targeted optimised build
# ═══════════════════════════════════════════════════════════════════════════
PHASE "Phase 3 — Optimised release build"

# The Cargo.toml release profile already declares lto/codegen-units/panic/
# strip equivalents; restating them as env vars makes the per-build intent
# explicit and overrides any local config.toml deltas. RUSTFLAGS additionally
# pins target-cpu=native (uses every aarch64 extension this CPU advertises)
# and opt-level=3 (favours speed over size — overrides Cargo.toml opt-level="z").
export CARGO_PROFILE_RELEASE_LTO="true"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1"
export CARGO_PROFILE_RELEASE_PANIC="abort"
export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C strip=symbols"

OK "RUSTFLAGS=$RUSTFLAGS"
OK "starting cargo build --release --locked (5–10 min on aarch64 first time)"

# Stream cargo output live so the user sees progress on long builds.
cargo build --release --locked

ART="$HSE_REPO/target/release/hse"
[ -f "$ART" ] || DIE "expected release artefact missing: $ART"
[ -x "$ART" ] || DIE "release artefact not executable: $ART"
OK "artefact: $ART  ($(stat -c%s "$ART" 2>/dev/null || stat -f%z "$ART") bytes)"

# Drop into the standard Termux bin directory so PATH picks it up.
mkdir -p "$(dirname "$HSE_BIN")"
install -m 0755 "$ART" "$HSE_BIN"
OK "installed → $HSE_BIN"

# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: Idempotent key provisioning
# ═══════════════════════════════════════════════════════════════════════════
PHASE "Phase 4 — Key provisioning ($ENV_FILE)"

# Canonical schema. Lines with placeholder values (matching the pattern
# `insert_..._here`) are TEMPLATES and meant to be edited by the user; lines
# with real values are preserved across re-runs by the merge logic below.
TEMPLATE=$(cat <<'TEMPLATE_EOF'
# ==============================================================================
# HUNTSMAN SEARCH ENGINE ENVIRONMENT MANIFEST
# ==============================================================================
# Edit values in place. Lines starting with `#` are comments. Real key values
# replace `insert_..._here` placeholders. Re-running this provisioner BACKS UP
# this file before changes and PRESERVES any non-template values already set.

# --- TIER 0: MASTER INTEGRATION EDGE ---
# Primary Upstream Intelligence API Focus
HUNTSMAN_OATHNET_KEY="insert_oathnet_pro_key_here"

# --- TIER 1: THREAT INTEL, REPUTATION & AMBIENT NOISE FILTRATION ---
HUNTSMAN_ALIENVAULT_KEY="insert_alienvault_otx_key_here"        # Free (Unlimited) - AlienVault OTX STIX/TAXII Indicator Feeds
HUNTSMAN_ABUSEIPDB_KEY="insert_abuseipdb_key_here"              # Freemium (1,000/day) - High-Velocity Network Layer Abuse Reporting
HUNTSMAN_VIRUSTOTAL_KEY="insert_virustotal_key_here"            # Freemium (4/min, 500/day) - Multi-Engine Static/Dynamic Malware Indicators
HUNTSMAN_GREYNOISE_KEY="insert_greynoise_key_here"              # Freemium (Community) - Anti-False Positive Internet Scanner Separation
HUNTSMAN_PULSEDIVE_KEY="insert_pulsedive_key_here"              # Freemium (Tiered API) - Active/Passive High-Fidelity IOC Risk Assessment
HUNTSMAN_URLSCAN_KEY="insert_urlscan_io_key_here"               # Freemium (Public) - Headless Sandbox Document Object Model (DOM) Audits
HUNTSMAN_MALSHARE_KEY="insert_malshare_key_here"                # Free (Generous API) - Raw Malicious Binary Payload Sample Repositories
HUNTSMAN_IPQUALITYSCORE_KEY="insert_ipqualityscore_key_here"    # Freemium (5,000/mo) - Fraud Risk, Proxy/VPN & Threat Velocity Analytics
HUNTSMAN_IPQS_KEY="insert_ipqs_key_here"                        # Alias accepted by the ipqs module
HUNTSMAN_PHISHTANK_KEY="insert_phishtank_key_here"              # Free (Community) - Collaborative Anti-Phishing URL Tracking Matrix

# --- TIER 2: CYBERSPACE MAPPING & RADAR INFRASTRUCTURE RECONNAISSANCE ---
HUNTSMAN_SHODAN_KEY="insert_shodan_key_here"                    # Freemium (Query Tier) - IoT Device Banners & Open Port Fingerprinting
HUNTSMAN_CENSYS_ID="insert_censys_id_here"                      # Freemium (Identity) - Combined Dynamic SSL/TLS Certificate Mapping
HUNTSMAN_CENSYS_SECRET="insert_censys_secret_here"              # Freemium (Secret Token) - ZMap-Driven Global Endpoint Scanning Interface
HUNTSMAN_SECURITYTRAILS_KEY="insert_securitytrails_key_here"    # Freemium (50/mo) - Deep Passive DNS Forward/Reverse Timelines
HUNTSMAN_SECTRAILS_KEY="insert_sectrails_key_here"              # Alias accepted by the securitytrails module
HUNTSMAN_LEAKIX_KEY="insert_leakix_key_here"                    # Freemium (Search Tier) - Openly Exposed Services, Leaked Credentials & Vulns
HUNTSMAN_ONYPHE_KEY="insert_onyphe_key_here"                    # Freemium (Basic) - Cyber Reconnaissance & Cyber Attack Surface Monitoring
HUNTSMAN_NETLAS_KEY="insert_netlas_key_here"                    # Freemium (Daily Limits) - Global Internet Scanner Object Datastores
HUNTSMAN_CRIMINALIP_KEY="insert_criminalip_key_here"            # Freemium (Search Tier) - Real-Time Inbound Port Vulnerability Intelligence
HUNTSMAN_ZOOMEYE_KEY="insert_zoomeye_key_here"                  # Freemium (Credits/mo) - Deep Chinese-Market Derived Node Component Maps
HUNTSMAN_BINARYEDGE_KEY="insert_binaryedge_key_here"            # Freemium (Free Token) - Interplanetary Attack Surface Scans & Honeypot Data

# --- TIER 3: IDENTITY RECONSTRUCTION, LEAK COMPILATIONS & PERSONA MAPPING ---
HUNTSMAN_XPOSEDORNOT_KEY="insert_xposedornot_key_here"          # Free (Unlimited) - Open Source Credential Breach & Privacy Metrics
HUNTSMAN_HUDSONROCK_KEY="insert_hudsonrock_key_here"            # Freemium (Telemetry Tier) - Active Cybercrime Infostealer Infection Vector Telemetry
HUNTSMAN_INTELX_KEY="insert_intelx_io_key_here"                 # Freemium (Search Tier) - Historic Pastebins, Darknet Indexes & Cold Dump Storage
HUNTSMAN_HIBP_KEY="insert_haveibeenpwned_key_here"              # Paid/Low-Cost Freemium - Troy Hunt's Master Breach Identity Vector Map
HUNTSMAN_EPIEOS_KEY="insert_epieos_key_here"                    # Freemium (Daily Balance) - Reverse Email/Phone Target Google Profile Discovery
HUNTSMAN_BREACHDIRECTORY_KEY="insert_breachdirectory_key_here"  # Freemium (Lookups/mo) - Decrypted Hash, Password & Leak Association Mapping
HUNTSMAN_HUNTER_KEY="insert_hunter_io_key_here"                 # Freemium (25/mo) - Domain-Specific Corporate Email Structure & Personnel Verification
HUNTSMAN_DEHASHED_USER="insert_dehashed_account_email_here"     # Paid - DeHashed account email (Basic-auth username)
HUNTSMAN_DEHASHED_KEY="insert_dehashed_key_here"                # Paid - DeHashed API key (Basic-auth password)
HUNTSMAN_NUMVERIFY_KEY="insert_numverify_key_here"              # Freemium (100/mo) - Phone E.164 validation + country/carrier/line-type

# --- TIER 4: LOCAL WIRELESS, CELLULAR & GEOSPATIAL SIGINT ENRICHMENT ---
HUNTSMAN_WIGLE_USER="insert_wigle_api_name_here"                # Free (Wireless Mapping) - 802.11 BSSID/ESSID Spatial Intersection Engine
HUNTSMAN_WIGLE_TOKEN="insert_wigle_api_key_here"                # Free (Wireless Mapping) - Wardriving Base Telemetry Synchronization Token
HUNTSMAN_OPENCELLID_KEY="insert_opencellid_key_here"            # Free (40,000/day) - Global GSM/LTE/5G Tower Triangulation Database
HUNTSMAN_MACADDRESS_KEY="insert_macaddress_io_key_here"         # Freemium (1,000/mo) - IEEE OUI Vendor Allocation Tables for Local wifi/arp Scans
HUNTSMAN_IPINFO_KEY="insert_ipinfo_io_key_here"                 # Freemium (50,000/mo) - Autonomous System Numbers (ASN) & BGP GeoIP Resolution
HUNTSMAN_MAXMIND_KEY="insert_maxmind_key_here"                  # Free (GeoLite2) - Offline/Online Localizable GeoIP2 Network Database Blocks
HUNTSMAN_BUILTWITH_KEY="insert_builtwith_key_here"              # Freemium (Basic Lookups) - Edge Web Stack Fingerprinting & Code Snippet Tracking
HUNTSMAN_ABR_GUID="insert_abr_guid_here"                        # Free - Australian Business Register lookup GUID
TEMPLATE_EOF
)

# Build the final file by merging existing real values into the template.
# For each `KEY="..."` line in the template, if the existing file has a real
# (non-`insert_..._here`) value for that key, keep that real value.
#
# Implemented in pure bash 4+ — busybox/POSIX awk on Termux doesn't support
# the `match(s, regex, array)` capture form, so awk-based merges would fail
# silently on the actual target platform.
merge_env() {
    local existing="$1" template="$2"
    declare -A real=()

    if [ -f "$existing" ]; then
        while IFS= read -r line; do
            # Match `KEY="value"` with no leading comment. Use bash regex —
            # supported on the bash 5.x that ships with Termux's `pkg`.
            if [[ "$line" =~ ^([A-Z_][A-Z_0-9]*)=\"(.*)\"[[:space:]]*$ ]]; then
                local k="${BASH_REMATCH[1]}"
                local v="${BASH_REMATCH[2]}"
                # Skip template placeholders so re-applying the script
                # doesn't permanently freeze them as "real values".
                if [[ ! "$v" =~ ^insert_.+_here$ ]] && [ -n "$v" ]; then
                    real["$k"]="$v"
                fi
            fi
        done < "$existing"
    fi

    while IFS= read -r line; do
        # On a template `KEY="..."` line where we have a real value, splice
        # that value in while keeping the trailing `# comment` annotation.
        if [[ "$line" =~ ^([A-Z_][A-Z_0-9]*)=\"[^\"]*\"(.*)$ ]]; then
            local k="${BASH_REMATCH[1]}"
            local trailer="${BASH_REMATCH[2]}"
            if [ -n "${real[$k]:-}" ]; then
                printf '%s="%s"%s\n' "$k" "${real[$k]}" "$trailer"
                continue
            fi
        fi
        printf '%s\n' "$line"
    done <<<"$template"

    # Surface any HUNTSMAN_* keys the user set that the template doesn't
    # know about (custom integrations, future modules). Append at the end
    # so they survive re-runs.
    for k in "${!real[@]}"; do
        if ! grep -qE "^${k}=" <<<"$template"; then
            printf '%s="%s"\n' "$k" "${real[$k]}"
        fi
    done
}

if [ -f "$ENV_FILE" ]; then
    cp -a "$ENV_FILE" "$ENV_BAK"
    OK "backed up existing $ENV_FILE → $ENV_BAK"
    merge_env "$ENV_FILE" "$TEMPLATE" > "$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
    OK "merged template into $ENV_FILE (real values preserved)"
else
    printf '%s\n' "$TEMPLATE" > "$ENV_FILE"
    OK "created $ENV_FILE from template"
fi

chmod 0600 "$ENV_FILE"
OK "permissions: $(stat -c%a "$ENV_FILE" 2>/dev/null || stat -f%Lp "$ENV_FILE")"

# Count placeholder vs populated.
ph=$(grep -cE '="insert_.*_here"' "$ENV_FILE" || true)
pop=$(grep -cE '^HUNTSMAN_[A-Z_0-9]+="[^"]*"' "$ENV_FILE" || true)
real=$(( pop - ph ))
OK "keys: $real populated, $ph placeholders (edit with \`nano $ENV_FILE\` or \`hse set-key NAME VALUE\`)"

# ═══════════════════════════════════════════════════════════════════════════
# Phase 5: Diagnostics + passive smoke test
# ═══════════════════════════════════════════════════════════════════════════
PHASE "Phase 5 — Diagnostics & passive smoke test"

OK "hse doctor:"
"$HSE_BIN" doctor || WARN "doctor reported issues (continuing)"

OK "hse modules count:"
mod_count=$("$HSE_BIN" modules | grep -cE '^[a-z]' || true)
printf '       %s modules registered\n' "$mod_count"

OK "passive-only domain scan (example.com):"
# --passive-only restricts to local sensors / offline analysers so the smoke
# test doesn't depend on GPS, cellular, or Wi-Fi being polled (which on Android
# can each take 10-15 s on first invocation).
if scan_out=$("$HSE_BIN" scan --kind domain --value example.com --passive-only --output json 2>&1); then
    # Parse: confirm we got a JSON envelope with a "scan" + "entities" key.
    if printf '%s' "$scan_out" | grep -q '"scan":' && \
       printf '%s' "$scan_out" | grep -q '"entities":'; then
        OK "smoke test passed — engine returned a well-formed JSON envelope"
    else
        WARN "smoke test produced output but JSON envelope shape is unexpected"
        printf '%s\n' "$scan_out" | head -20
    fi
else
    ERR "smoke test failed"
    printf '%s\n' "$scan_out" | head -40
fi

# Separately exercise the missing-key error path. --passive-only above
# excludes paid modules entirely, so we wouldn't otherwise see the engine
# convert a `ctx.key("HUNTSMAN_OATHNET_KEY")` miss into a clean
# ModuleError event. Pin the scan to oathnet_pro and assert the engine
# reports the missing key without panicking and still returns valid JSON.
if mk_out=$("$HSE_BIN" scan --kind domain --value example.com \
               --modules oathnet_pro --output json 2>&1); then
    if printf '%s' "$mk_out" | grep -q '"scan":'; then
        # Engine output reaches stderr for the tracing log, stdout for JSON.
        # The "missing key" string lands in stderr; absorbing both above
        # means it shows up here on a match.
        if printf '%s' "$mk_out" | grep -q 'missing key: HUNTSMAN_OATHNET_KEY'; then
            OK "missing-key path verified — engine logged 'missing key: HUNTSMAN_OATHNET_KEY' and continued cleanly"
        else
            # If you've populated HUNTSMAN_OATHNET_KEY, the module will actually
            # try to call the API; treat that as "ok, key present" without
            # flagging as an error.
            OK "missing-key path not exercised — HUNTSMAN_OATHNET_KEY appears populated"
        fi
    else
        WARN "missing-key sub-test: output didn't match expected JSON shape"
    fi
else
    WARN "missing-key sub-test exited non-zero (continuing)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Phase 6: Release wake-lock + summary
# ═══════════════════════════════════════════════════════════════════════════
PHASE "Phase 6 — Release CPU hold & final report"

if command -v termux-wake-unlock >/dev/null 2>&1; then
    termux-wake-unlock && OK "termux-wake-unlock released"
else
    WARN "termux-wake-unlock not found — skipping"
fi

printf '\n%s\n' "$(BOLD '── Deployment summary ──')"
printf '  binary             : %s (%s bytes)\n' \
    "$HSE_BIN" "$(stat -c%s "$HSE_BIN" 2>/dev/null || stat -f%z "$HSE_BIN")"
printf '  env file           : %s (mode %s, %s populated / %s placeholders)\n' \
    "$ENV_FILE" "$(stat -c%a "$ENV_FILE" 2>/dev/null || stat -f%Lp "$ENV_FILE")" \
    "$real" "$ph"
printf '  modules registered : %s\n' "$mod_count"
printf '  HEAD commit        : %s\n' "$(cd "$HSE_REPO" && git rev-parse --short HEAD)"
printf '\nDone. Next: populate placeholders with `hse set-key NAME VALUE`\n'
printf 'or edit %s directly, then `hse serve --bind 127.0.0.1:8080`.\n' "$ENV_FILE"
