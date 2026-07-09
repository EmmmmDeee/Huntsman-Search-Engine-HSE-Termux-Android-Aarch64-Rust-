# HSE API Key Acquisition Guide

This is the operator checklist for provisioning HSE's keyed modules. It is
derived from the canonical registry in `src/util/keys/constants.rs`
(`KNOWN_KEYS` + `signup_hint()`), not hand-maintained — regenerate the "still
needed" section any time from code via `keys::acquisition_status()`.

> **Zero-config baseline.** HSE runs out of the box. The ~128 free modules need
> no keys at all, and five keyed modules ship a working **embedded default**
> (below). Everything else is optional enrichment — add a key and that module
> lights up on the next scan; skip it and HSE simply routes around it.

## Live-verified status (2026-07-09)

Validated from this build environment against each provider's real endpoint:

| Module | Env var | Auth | Status |
|--------|---------|------|--------|
| HIBP | `HUNTSMAN_HIBP_KEY` | `hibp-api-key` header | ✅ **200 — live** (embedded default) |
| WiGLE | `HUNTSMAN_WIGLE_USER` / `_TOKEN` | HTTP Basic | ✅ **200 — live** (embedded default; returns operator profile) |
| SeekNow | `HUNTSMAN_SEEKNOW_KEY` | `X-API-Key` | ✅ **200 — live** (embedded default, rotated 2026-07-09) |
| OathNet | `HUNTSMAN_OATHNET_KEY` | `X-API-Key` | ⚠️ **unverifiable here** — provider is behind a Cloudflare JS challenge (HTTP 403 "Just a moment…") from this sandbox; verify on the operator device with `hse doctor` |

> **SeekNow rotation note.** The previously embedded default
> (`seek-fd18f1…`) tested **DEAD (HTTP 401 `invalid_api_key`)**. It has been
> superseded by the operator's live key and moved to a `SEEKNOW_SUPERSEDED_KEY_*`
> slot so any stale `~/.huntsman.env` upgrades in place. Fresh zero-config
> installs now ship a working SeekNow key.

## Keys that ship zero-config (no action needed)

- `HUNTSMAN_HIBP_KEY` — Have I Been Pwned
- `HUNTSMAN_OATHNET_KEY` — OathNet Pro
- `HUNTSMAN_WIGLE_USER` + `HUNTSMAN_WIGLE_TOKEN` — WiGLE
- `HUNTSMAN_SEEKNOW_KEY` — SeekNow

## Optional keys — free tier available

Each of these has a free signup; obtaining one is a human step (account
creation + ToS acceptance) that cannot be automated. Paste the key into
`~/.huntsman.env` (chmod 0600) as `export HUNTSMAN_<NAME>=<value>` or via
`hse serve` → Settings, and it loads automatically on the next run.

| Env var | Provider — free signup |
|---------|------------------------|
| `HUNTSMAN_SHODAN_KEY` | Shodan — https://account.shodan.io/register |
| `HUNTSMAN_SECTRAILS_KEY` | SecurityTrails — https://securitytrails.com/app/signup |
| `HUNTSMAN_HUNTER_KEY` | Hunter.io — https://hunter.io/users/sign_up |
| `HUNTSMAN_GREYNOISE_KEY` | GreyNoise — https://viz.greynoise.io/signup |
| `HUNTSMAN_URLSCAN_KEY` | urlscan.io — https://urlscan.io/user/signup |
| `HUNTSMAN_LEAKIX_KEY` | LeakIX — https://leakix.net/auth/register |
| `HUNTSMAN_INTELX_KEY` | Intelligence X — https://intelx.io/signup |
| `HUNTSMAN_EMAILREP_KEY` | EmailRep — https://emailrep.io/key |
| `HUNTSMAN_CRIMINALIP_KEY` | Criminal IP — https://www.criminalip.io/register |
| `HUNTSMAN_IPQS_KEY` | IPQualityScore — https://www.ipqualityscore.com/create-account |
| `HUNTSMAN_CENSYS_ID` + `HUNTSMAN_CENSYS_SECRET` | Censys — https://accounts.censys.io/register |
| `HUNTSMAN_WHOISXML_KEY` | WhoisXML — https://whois.whoisxmlapi.com |
| `HUNTSMAN_ONYPHE_KEY` | ONYPHE — https://www.onyphe.io/login/#register |
| `HUNTSMAN_NETLAS_KEY` | Netlas — https://app.netlas.io/registration |
| `HUNTSMAN_PULSEDIVE_KEY` | Pulsedive — https://pulsedive.com/about/api |
| `HUNTSMAN_ABUSEIPDB_KEY` | AbuseIPDB — https://www.abuseipdb.com/register |
| `HUNTSMAN_VIRUSTOTAL_KEY` | VirusTotal — https://www.virustotal.com/gui/join-us |
| `HUNTSMAN_ABUSECH_KEY` / `HUNTSMAN_THREATFOX_KEY` | abuse.ch — https://auth.abuse.ch |
| `HUNTSMAN_NUMVERIFY_KEY` | numverify — https://numverify.com/product |
| `HUNTSMAN_HLR_KEY` | HLR Lookups — https://hlrlookups.com |
| `HUNTSMAN_OPENCNAM_KEY` | OpenCNAM — https://www.opencnam.com/register |
| `HUNTSMAN_OPENCELLID_KEY` | OpenCelliD — https://opencellid.org/register.php |
| `HUNTSMAN_OPENCORP_KEY` | OpenCorporates — https://opencorporates.com/api_accounts/new |
| `HUNTSMAN_TROVE_KEY` | NLA Trove — https://trove.nla.gov.au/about/create-something/using-our-apis/api-technical-guide |
| `HUNTSMAN_EXA_KEY` | Exa AI — https://dashboard.exa.ai/api-keys |

## Optional keys — paid / invite only

| Env var | Provider |
|---------|----------|
| `HUNTSMAN_DEHASHED_KEY` | DeHashed — paid v2 API, needs an active search subscription (https://dehashed.com) |
| `HUNTSMAN_PROXYCURL_KEY` | Proxycurl — paid (https://nubela.co/proxycurl) |
| `HUNTSMAN_SEON_KEY` | SEON — free trial (https://seon.io) |
| `HUNTSMAN_EPIEOS_KEY` | Epieos (https://epieos.com) |

## How loading works

1. **Embedded defaults** compiled from `keys::constants` — written to the env
   file by `ensure_hardcoded_keys` if absent; stale/rotated values upgrade in
   place via the `SUPERSEDED` table.
2. **`~/.huntsman.env`** (chmod 0600) — the operator vault; `populate_and_load`
   exports it into the process environment at startup.
3. **Process environment** — any `HUNTSMAN_*` var set in the shell wins over the
   embedded default (`resolve_or_default`: a non-empty explicit key always
   overrides).

A key is considered **"still needed"** only when it has no embedded default and
no environment value — exactly what `KeyAcquisition::needs_acquisition()`
reports.

> **Why the rest can't be auto-provisioned.** Obtaining a provider key means
> creating an account, accepting that provider's Terms of Service, and (for paid
> tiers) arranging billing — a human authorisation step, per provider. HSE
> automates everything downstream of that: the moment a key is present, it is
> loaded, validated against the live endpoint, and routed to its module with no
> further configuration.
