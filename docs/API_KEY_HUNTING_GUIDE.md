# API Key Hunting with Huntsman Search Engine

A practical guide to finding raw API keys, credentials, and tokens
using HSE's force-multiplication chain. Read this end-to-end before
running scans — the ordering matters.

## TL;DR

```bash
# The single command that yields the most keys per OathNet lookup:
hse scan --kind domain --value <target.com> --depth 3 -A
```

That's it. The rest of this guide explains *why* that works, what each
link in the chain produces, and how to tune it.

---

## The unhelpful truth (read this first)

**Browser-based stealer logs almost never contain raw API keys.** They
contain dashboard *login credentials* — the password you typed at
shodan.io/login, censys.io/login, etc. The actual API key is *displayed*
on the dashboard after login. It is never typed into any form, so the
stealer never sees it.

Empirical measurement against 844 OathNet stealer records targeting the
top 9 OSINT-service domains:

| Source | Records | API-key prefix matches | URL-token captures |
|--------|---------|------------------------|---------------------|
| oathnet.org | 100 | 0 | 0 |
| see-know.eu | 47 | 0 | 0 |
| dehashed.com | 100 | 0 | 0 |
| snusbase.com | 100 | 0 | 0 |
| leakcheck.io | 99 | 0 | 0 |
| intelx.io | 99 | 0 | 0 |
| shodan.io | 100 | 0 | 0 |
| censys.io | 100 | 0 | 0 |
| breach test@ex.com | 99 | 0 | 0 |
| **Total** | **844** | **0** | **0** |

What was actually in those records: 756 plaintext dashboard passwords,
4 bcrypt hashes, 2 SHA-1 hashes, 1 OAuth code, 1 Fernet token. Useful
intelligence, but not API keys.

**So where ARE the raw keys?** In exposed config files on the public
internet. Specifically `.env`, `.git/config`, `wp-config.php.bak`,
`/api/config`, `/.aws/credentials`, etc. — left behind by developers.
Browser stealers never see them. Shodan does.

---

## The chain that actually yields keys

```
                ┌──────────────────────┐
                │  oathnet_pro (R0)    │  Paid, 1 lookup, session-bundled
                │  breach + stealer    │
                └──────────┬───────────┘
                           │ extracts: IPs, domains, emails,
                           │ usernames, hashes, addresses,
                           │ (rarely) keys in URL params
                           ▼
                ┌──────────────────────┐
                │  HOT-INJECT          │  ctx.keys refreshed from pool
                │  Phase 1 → Phase 2   │  before concurrent modules spawn
                └──────────┬───────────┘
                           │
                           ▼
   ┌─────────────┬─────────┴──────────┬──────────────────┐
   ▼             ▼                    ▼                  ▼
 shodan       censys             securitytrails       virustotal
 (paid path,  (paid, cert       (paid, historical    (paid,
  IP enrich)   SAN expansion)    DNS subdomains)      related URLs)
   │             │                    │                  │
   └─────────────┴─────────┬──────────┴──────────────────┘
                           │ produces: IPs + Domain entities
                           │ (subdomains, PTRs, cert SANs)
                           ▼
                ┌──────────────────────┐
                │  EXPANSION R1 → R5   │  free modules unlimited
                │  on every new        │  (dns_intel, cert_intel,
                │  Domain entity       │   crtsh, securitytrails)
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐  THIS IS WHERE THE KEYS ARE
                │  web_crawler         │  108 config-file paths
                │  probe_config_leaks  │  per Domain, parallel
                │  (R1+ per domain)    │  semaphore=16
                └──────────┬───────────┘
                           │ fetches /.env, /.git/config,
                           │ /wp-config.php.bak, /api/config,
                           │ /.aws/credentials, /actuator/env,
                           │ /credentials.json, ...
                           ▼
                ┌──────────────────────┐
                │  identify_api_key    │  80+ prefix patterns
                │  scan body bytes     │  (sk-ant-, AKIA, ghp_,
                │                      │   AIzaSy, eyJ, ...)
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  ApiKey entity       │  tagged "force-multiplier"
                │  + pool storage      │  if Multiplier-tier service
                │  + AU-021 correlation│
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  HOT-INJECT (again)  │  newly discovered key now
                │  → unlocks more      │  in ctx.keys → cascade
                │  paid modules        │  continues
                └──────────────────────┘
```

The chain compounds: every discovered key unlocks a paid module
whose output feeds web_crawler on more domains, which finds more
keys, which unlock more modules. Depth-5 expansion is where this
explodes.

---

## What's in the chain (per file)

### `src/modules/oathnet_pro/mod.rs`
- 1 OathNet lookup per scan (session-bundled breach + stealer)
- page_size 100 for identity targets, 50 for IP/Domain
- Extracts 12 entity types: Email, Username, Phone, Person,
  IpAddress, Address, Discord, Instagram, LinkedIn, email_domain,
  password_hash, ApiKey
- Force-multiplier tagging on Multiplier-tier discovered keys

### `src/modules/oathnet_pro/key_harvest.rs`
- Scans 20 password-like fields per record
- Scans URL query parameters for `?key=`, `?token=`, `?api_key=`
- Scans the `extra` JSON object
- Scans the `username` field (some logs store keys as usernames)
- Matches against 80+ prefix patterns
- Matches against 165+ service-domain URLs
- Promotes discovered keys to the `force-multiplier` tag when
  the service is a Multiplier-tier (Shodan, Censys, etc.)

### `src/modules/web_crawler/crawl_util.rs`  **← where the magic happens**
- `probe_config_leaks` fires on every Domain entity
- 108 config-file paths probed in parallel (semaphore=16)
- 3-second timeout per request
- Body cap: 1 MB
- Skips HTML responses (catches the silent-redirect-to-login case)
- Each discovered key → ApiKey entity → pool → AU-021 correlation

### `src/core/engine.rs` — hot-inject
- Two-phase concurrent dispatch:
  - Phase 1 (synchronous): all Paid modules run, ctx refreshed after each
  - Phase 2 (concurrent): all Free + KeyGated modules spawn with key-rich ctx
- Sequential dispatch path also refreshes ctx after every module
- Both paths log the ROI tier when injecting (Multiplier / Expansion / Terminal)

### `src/util/key_roi.rs`
- Classifies each service into one of three tiers:
  - **Multiplier**: Shodan, Censys, SecurityTrails, Hunter, Proxycurl,
    HIBP, Dehashed, IntelX, OathNet itself, see-know.eu, snusbase,
    leakcheck, leakpeek, leak-lookup, hashes.com, etc. (services that
    lead to MORE keys via their outputs)
  - **Expansion**: OpenCorporates, ABN, Wigle, OpenCelliD, Mailchimp,
    Twilio (many entities per target, but no key chain)
  - **Terminal**: AbuseIPDB, GreyNoise, IP2Location, IPInfo, NumVerify,
    Pulsedive (single-shot scoring/geo data)

---

## Operational playbooks

### Find keys for a specific domain

```bash
hse scan --kind domain --value target.com --depth 3 -A --max-concurrent 4
```

This runs:
1. R0: oathnet_pro (1 lookup) + every free identity/infra module
2. web_crawler probes all 108 config-file paths on the apex
3. Hot-inject any discovered keys
4. R1-R5: every discovered subdomain → web_crawler again → more probes

Expected output filters:
```bash
# Just the keys discovered
hse scan ... --output json | jq '.entities[] | select(.kind=="api_key")'

# Force-multiplier keys only (the high-ROI finds)
hse scan ... --output json | jq '.entities[] | select(.tags | index("force-multiplier"))'

# Config-leak source paths
hse scan ... --output json | \
  jq '.entities[] | select(.tags | index("config-leak")) |
      {service: .tags, path: .evidence[].attributes.exposure_path}'
```

### Find keys for a target's email

```bash
hse scan --kind email --value user@target.com --depth 3 -A
```

R0 produces emails + domains + IPs. R1 runs web_crawler on every
domain discovered. Same chain, different seed.

### Maximise breadth (multi-target)

```bash
for d in target1.com target2.com target3.com; do
  hse scan --kind domain --value "$d" --depth 3 -A --output json \
    > /tmp/scan_$d.json
done

# Aggregate all discovered keys across scans
jq -s '.[] | .entities[] | select(.kind=="api_key")' /tmp/scan_*.json
```

### Find OathNet keys specifically

The most likely path to discover an OathNet API key is:
1. Run oathnet_pro's stealer search for `domain[]=oathnet.org`
   (which the radar mode and seed search do automatically)
2. The stealer records contain login credentials for OathNet
   dashboard accounts — these are NOT the API keys
3. To actually find OathNet keys, target dev infrastructure:
   - GitHub/GitLab dorks for `HUNTSMAN_OATHNET_KEY` or
     `OATHNET_KEY=` (HSE doesn't currently dork — manual step)
   - Shodan search for IPs serving exposed `.env` files →
     web_crawler probes them automatically once Shodan returns them

### Tune for max key yield

```bash
# Per-scan budget (lift the per-scan cap if you have a high quota)
HUNTSMAN_OATHNET_SESSION_CAP=500 hse scan ...

# Concurrent module dispatch (default 4 — raise on big servers)
hse scan ... --max-concurrent 16

# Confidence floor for expansion (lower = more aggressive expansion)
hse scan ... --min-expand-confidence 0.30
```

---

## Targeted services (force-multiplier tier)

Discovering a key for any of these UNLOCKS more key discovery. They
are auto-prioritised in the ROI classification.

### Self-discovery
- `oathnet.org` (+ api/dashboard/docs subdomains)

### Direct OathNet competitors
- `see-know.eu` (api/app/dashboard subdomains) — Bearer-token auth,
  `/api/v1/stealer`, `/api/v1/breachhub/search`
- `snusbase.com`, `api.snusbase.com`
- `leakcheck.io / .net`, `api.leakcheck.net`
- `leakpeek.com`
- `leak-lookup.com`, `api.leak-lookup.com`
- `hashes.com`
- `psbdmp.ws`
- `ghostproject.fr`
- `scylla.so / .sh`
- `weleakinfo.to / .com`
- `hackcheck.io`, `api.hackcheck.io`
- `scrubd.com`
- `nuclearleaks.com`
- `breachforums.is / .st`
- `inteltechniques.com`
- `dehashed.com`, `app.dehashed.com`, `api.dehashed.com`
- `intelx.io`, `2.intelx.io`, `free.intelx.io`
- `breachdirectory.org`

### Infrastructure intelligence
- `shodan.io`, `account.shodan.io`
- `censys.io`, `search.censys.io`
- `securitytrails.com`
- `fullhunt.io`, `binaryedge.io`, `app.binaryedge.io`
- `passivetotal.org`, `onyphe.io`, `zoomeye.org`, `fofa.info`
- `netlas.io`, `pulsedive.com`, `urlscan.io`, `leakix.net`

### Identity enumeration
- `hunter.io`, `nubela.co` (proxycurl), `epieos.com`
- `emailrep.io`, `seon.io`

### Source-code leaks
- `github.com`, `gitlab.com`

### Breach data
- `haveibeenpwned.com`
- All the breach services listed above

---

## API key prefix patterns recognised (80+)

| Prefix | Service | Min length |
|--------|---------|-----------|
| `sk-ant-` | Anthropic | 40 |
| `sk-proj-` | OpenAI (project key) | 40 |
| `sk-` | OpenAI / Stripe | 20 |
| `AIzaSy` | Google API | 39 |
| `AKIA` | AWS IAM | 16 |
| `ASIA` | AWS STS (temporary) | 16 |
| `ghp_` | GitHub Personal Access Token | 36 |
| `gho_` | GitHub OAuth | 36 |
| `ghs_` | GitHub App installation | 36 |
| `github_pat_` | GitHub fine-grained PAT | 40 |
| `glpat-` | GitLab Personal Access Token | 20 |
| `SG.` | SendGrid | 50 |
| `xkeysib-` | Brevo / SendinBlue | 40 |
| `sk_live_` | Stripe (live secret) | 24 |
| `pk_live_` | Stripe (live publishable) | 24 |
| `sk_test_` | Stripe (test) | 24 |
| `rk_live_` | Stripe restricted key | 24 |
| `whsec_` | Stripe webhook secret | 24 |
| `hf_` | HuggingFace | 30 |
| `r8_` | Replicate | 30 |
| `pplx-` | Perplexity | 30 |
| `sntrys_` | Sentry | 40 |
| `glc_` | Grafana Cloud | 20 |
| `NRAK-` | New Relic | 20 |
| `dapi` | Databricks PAT | 30 |
| `cfut_` | Cloudflare user token | 40 |
| `cfat_` | Cloudflare account token | 40 |
| `shpat_` | Shopify Access Token | 30 |
| `ntn_` | Notion Integration Token | 40 |
| `lin_api_` | Linear API | 30 |
| `tfp_` | Typeform | 30 |
| `fo1_` | Fly.io | 30 |
| `sbp_` | Supabase project | 30 |
| `pul-` | Pulumi | 30 |
| `ATATT3` | Atlassian API Token | 40 |
| `xoxb-` | Slack bot token | 50 |
| `xoxp-` | Slack user token | 50 |
| `xapp-` | Slack app-level token | 50 |
| `EAA` | Facebook | 40 |
| `AC` (34-char) | Twilio Account SID | 34 |
| `dop_v1_` | DigitalOcean Personal | 60 |
| `nvapi-` | NVIDIA NGC | 30 |
| `eyJ` | JWT (any) | 100 |
| `npm_` | npm Access Token | 36 |
| `pypi-` | PyPI | 30 |
| `op_` | 1Password Connect | 20 |
| `sq0atp-` | Square Access | 20 |
| `ya29.` | Google OAuth Refresh | 40 |
| `goog_` | Google Service | 40 |
| `phc_` | PostHog | 20 |
| `rnd_` | Render | 30 |
| `re_` | Resend | 20 |
| `LTAI` | Alibaba Cloud Access | 16 |
| `do-api-` | DigitalOcean legacy | 30 |
| `AGE-SECRET-KEY-` | age encryption | 60 |
| ...plus 25 more covering Mailchimp, Discord bots, Azure, Square, Atlassian variants |

Full canonical list lives in
`src/modules/oathnet_pro/key_harvest.rs::KEY_PATTERNS`.

---

## Config-file paths probed (108)

Full list in `src/modules/web_crawler/crawl_util.rs::CONFIG_LEAK_PATHS`.

Categories:
- 18 `.env` variants (apex + /api, /admin, /private, /backend, /server)
- 9 generic config files (config.js, secrets.yml, credentials.json, ...)
- 9 VCS/IDE leaks (.git/config, .gitlab-ci.yml, .vscode/settings.json, ...)
- 5 WordPress backup files
- 8 cloud/container credentials (.aws/, .kube/, terraform, serverless)
- 11 framework-specific (Next.js, Nuxt, build/, dist/, static/)
- 11 debug/introspection endpoints (/debug, /server-status, /actuator/env)
- 6 package manifests (.npmrc, .yarnrc, pip.conf)
- 10 CI/CD config (Dockerfile, .travis.yml, .circleci/, Jenkinsfile)
- 10 API surface (swagger.json, graphql, /actuator/heapdump)
- 5 backup files (backup.sql, dump.sql)

---

## Quotas and budgets

| Resource | Default cap | Where set |
|----------|-------------|-----------|
| OathNet queries per scan | 4 | `src/util/oathnet.rs::MAX_QUERIES_PER_SCAN` |
| OathNet queries per process session | 30 | `HUNTSMAN_OATHNET_SESSION_CAP` env var |
| OathNet record page size | 100 (50 for infra) | `src/modules/oathnet_pro/mod.rs::page_size` |
| Wigle queries per scan | 3 geo + 2 BSSID | `src/modules/wigle.rs` |
| Web crawler pages per scan | 60 | `src/modules/web_crawler/mod.rs::MAX_PAGES` |
| Web crawler max depth | 3 | `src/modules/web_crawler/mod.rs::MAX_DEPTH` |
| Web crawler config-probe concurrency | 16 | `src/modules/web_crawler/crawl_util.rs` |
| Concurrent modules per dispatch | 4 | `--max-concurrent` CLI flag |
| Free modules | unlimited | (intentional) |

To run with maximum throughput:
```bash
HUNTSMAN_OATHNET_SESSION_CAP=500 \
  hse scan --kind domain --value target.com --depth 3 -A \
           --max-concurrent 16 --min-expand-confidence 0.30
```

---

## Verifying a discovered key

When `web_crawler` discovers an exposed key, it's stored in the pool
as `Untested`. The `api_key_probe` module validates it against the
service's live test endpoint:

```bash
# All probes happen automatically when an ApiKey entity is expanded
hse scan --kind api_key --value <DISCOVERED_KEY>
```

Test endpoints used (defined in `src/util/service_defs.rs`):
- Shodan: `GET /api-info?key=<KEY>`
- HIBP: `GET /api/v3/breaches` with `hibp-api-key: <KEY>`
- Censys: HTTP Basic Auth against `/api/v2/hosts/1.1.1.1`
- VirusTotal: `x-apikey: <KEY>` against `/api/v3/urls`
- AbuseIPDB: `Key: <KEY>` against `/api/v2/check`
- See `src/util/service_defs.rs` for the full list (40 services)

A 200/201/204/3xx response confirms the key is live and adds it as
`Active` to the pool. A 401/403/429 marks it `Invalid` or rate-limited.

---

## Force-multiplication: what to expect

| Stage | Output |
|-------|--------|
| 1 OathNet lookup | 100 breach + 100 stealer records |
| Direct entity extraction | 50-150 entities |
| Domains discovered → web_crawler | 108 config probes × N domains |
| Per leaky domain | typically 1-5 exposed `.env` keys |
| Per Multiplier-tier key found | unlocks an entire module |
| Expansion depth-5 cascade | 500-1500 entities final total |

**Realistic key yield**: 0-3 actual API keys per scan. The hit rate
depends entirely on the target's infrastructure hygiene. A small
startup with a misconfigured staging server can yield 10+ keys. A
mature enterprise might yield zero.

---

## Ethics and authorization

This tool finds publicly-exposed credentials. Public exposure does NOT
authorize use. Discovering a key only tells you that some operator made
a mistake.

If you intend to use a discovered key (test it against the issuing
service, use it operationally), you need:
1. A bug bounty scope that covers credential discovery, OR
2. A written engagement with the credential's owner, OR
3. Your own key (which is the entire point — find your *own* leaks first)

The `api_key_probe` module hits each service's own "who am I" endpoint
ONCE per key to confirm it's live. That single test request is what
your authorization needs to cover. Anything beyond that — actual data
queries, payment authorizations, repo access — is on you to justify.

---

## See also

- `docs/OATHNET_API_GUIDE.txt` — complete OathNet API reference
- `src/util/key_roi.rs` — ROI tier classification source
- `src/modules/oathnet_pro/key_harvest.rs` — key pattern matchers
- `src/modules/web_crawler/crawl_util.rs::probe_config_leaks` — the 108-path probe
- `src/core/engine.rs::dispatch_target_concurrent` — Phase 1 / Phase 2 hot-inject
- `tests/smoke.rs::key_chaining_*` — load-bearing tests for the chain
