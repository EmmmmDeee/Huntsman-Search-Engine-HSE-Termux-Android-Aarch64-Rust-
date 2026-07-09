# HSE + SeekNow: Automated OSINT Workflows

Enterprise-grade OSINT profiles that automatically optimize SeekNow endpoint routing, budget allocation, and entity correlation based on target type and threat profile.

---

## Quick-Start Workflows

### 1. Email Investigation (Fast)
**Profile:** Compromise assessment, credential exposure, breach discovery  
**Depth:** 1 | **Budget:** 50–100 credits | **Time:** 10–30 seconds

```bash
hse scan --kind email --value target@company.com --depth 1 --full
```

**SeekNow routing (automatic):**
1. `/search` — Email query (1 credit) → Extract breach records + stealer logs + OSINT
2. `/network/email-check` — Email verification (1 credit) → Deliverability, disposable, breach count
3. **Auto-correlation** → Deduplicate by hash, enrich with geolocation + IP reputation

**Expected output:**
- Breach/stealer records containing target email
- Linked social media profiles
- Company email domain footprint
- Password hashes (if any)
- API key candidates

---

### 2. Username Reconnaissance (Social Multi-Platforming)
**Profile:** Threat actor, sock puppet, alternate account discovery  
**Depth:** 2 | **Budget:** 150–300 credits | **Time:** 1–2 minutes

```bash
hse scan --kind username --value alice_92 --depth 2 --full
```

**SeekNow routing (automatic):**
1. `/search` — Username query (1 credit) → Breach + stealer records
2. `/username/social` — 70+ platforms (1 credit) → Platform presence (GitHub, Twitter, Reddit, etc.)
3. `/username/history` — Username changes (1 credit) → Alt accounts, naming patterns
4. `/discord/user` or Discord ID pivot (if found) → Linked emails, server activity
5. **Depth 2 auto-expansion:**
   - Email extracted → `/network/email-check` + `/search` on email
   - Domain extracted → `/domain/intel` + `/domain/whois` (free modules expand)
   - IP extracted → `/network/ip` + geolocation

**Expected output:**
- All social platforms where username exists
- Breach mentions across multiple sources
- Email addresses linked to username
- Historical usernames and naming patterns
- Linked Discord/gaming profiles
- IP geolocation history

---

### 3. Domain Threat Assessment (Infrastructure Footprint)
**Profile:** Corporate domain, malware C2, phishing infrastructure  
**Depth:** 3 | **Budget:** 300–750 credits | **Time:** 2–5 minutes

```bash
hse scan --kind domain --value acme.com --depth 3 --full
```

**SeekNow routing (automatic):**
1. `/search` — Domain query (1 credit) → Breach + stealer records for domain
2. `/domain/intel` — Infrastructure (1 credit) → DNS, MX, subdomains, tech stack
3. `/domain/whois` — Registration data (1 credit) → Registrar, dates, registrant
4. **Depth 2 auto-expansion (free modules):**
   - DNS records → A/AAAA IPs → `/network/ip` for each
   - Email addresses extracted → `/network/email-check` + `/search` on emails
   - Subdomains discovered → Recursive `/domain/intel` on each
   - web_crawler → Probes 103 config paths on each domain (finds .env, credentials, API keys!)
5. **Depth 3 expansion:**
   - API keys found → Force-multiplier cascade (auto-unlock Shodan, Censys, SecurityTrails)
   - Employee emails found → Depth 2 expansion on each

**Expected output:**
- Complete DNS infrastructure (A, MX, NS, TXT records)
- All known subdomains
- Technology stack (Nginx, CloudFlare, AWS, etc.)
- Domain registration details (registrant, registrar, dates)
- Breach history (credentials, employee records)
- Exposed configuration files (.env, .git/config, credentials.json, /actuator/env)
- Discovered API keys (force-multiplier cascade unlocks infrastructure modules)
- Employee directory (names, emails, social profiles)

---

### 4. IP Address Recon (Geolocation + Hosting Attribution)
**Profile:** Server fingerprinting, hosting provider detection, abuse score  
**Depth:** 2 | **Budget:** 100–200 credits | **Time:** 1 minute

```bash
hse scan --kind ip --value 192.0.2.1 --depth 2 --full
```

**SeekNow routing (automatic):**
1. `/search` — IP query (1 credit) → Breach + stealer records mentioning IP
2. `/network/ip` — IP intelligence (1 credit) → Geolocation, ASN, ISP, VPN/Tor, abuse score, breach count
3. **Depth 2 auto-expansion:**
   - ASN discovered → netblock module for CIDR ranges
   - Breach mentions → `/search` on exposed domains (if any)
   - Reverse DNS (free) → Domain → `/domain/intel` + `/domain/whois`

**Expected output:**
- Geolocation (country, city, lat/lon)
- ASN + CIDR range
- ISP + hosting provider
- VPN/Tor/Proxy detection
- Abuse score (spam, malware, DDoS history)
- Breach mention count
- Associated domains (reverse DNS)
- Related IPs in CIDR range (from netblock)

---

### 5. Phone OSINT (Carrier + Breach Correlation)
**Profile:** Phone number attribution, carrier identification, breach exposure  
**Depth:** 1 | **Budget:** 20–50 credits | **Time:** 10 seconds

```bash
hse scan --kind phone --value +1-555-0123 --depth 1 --full
```

**SeekNow routing (automatic):**
1. `/search` — Phone query (1 credit) → Breach + stealer records with phone
2. `/network/phone` — Phone OSINT (1 credit) → Carrier, country, line type, breach mentions

**Expected output:**
- Carrier name + country
- Line type (mobile, landline, VoIP)
- Breach record count
- Leaked passwords/usernames associated with phone
- Account registrations linked to phone

---

### 6. Person Profile (Comprehensive Dossier)
**Profile:** Target reconnaissance, employee profiling, identity verification  
**Depth:** 3 | **Budget:** 500–1000 credits | **Time:** 5–10 minutes

```bash
hse scan --kind name --value "John Doe" --depth 3 --full
```

**SeekNow routing (automatic):**
1. `/search` — Name query with auto-detect (1 credit) → All records mentioning name
2. **Depth 2 expansion (auto-triggered on extracted entities):**
   - Email found → `/network/email-check` + `/search` + `/username/social` (if email has username part)
   - Phone found → `/network/phone` + `/search` on phone
   - Username found → `/username/social` + `/username/history` + social platform checks
   - Address found → Domain extraction → `/domain/intel`
3. **Depth 3 expansion (API key cascade):**
   - Any API keys found → Force-multiplier unlock (Shodan, Censys)
   - web_crawler probes domains for exposed configs

**Expected output:**
- All breach records mentioning name
- Associated email addresses
- Phone numbers
- Social media profiles
- Physical addresses
- Employment history (if leaked)
- Education records (if leaked)
- Credentials (if any)
- API keys (if any)
- Complete person dossier with entity correlations

---

## Advanced Workflows

### 7. Threat Actor Profile (Low-Signal Hunting)
**Profile:** Hunting for APT activity, alternative identities, OPSEC failures  
**Depth:** 3 | **Budget:** 1000+ credits | **Time:** 10–15 minutes

```bash
# Iterative hunting: run multiple identity searches
for identity in alice_92 alice.92 alice92 alice_security; do
  hse scan --kind username --value $identity --depth 3 --full
done

# Correlate results manually or via HSE's entity deduplication
hse query --entity-kind person --filter "breach_mentions > 5"
```

**Strategy:**
- Generate username variants (hyphens, dots, numbers)
- Run depth 3 scans on each variant (auto-correlates across scans)
- HSE deduplicates entities by hash (same person, multiple usernames = 1 Person entity)
- Force-multiplier cascade unlocks all downstream APIs
- Manual review of correlations

**Expected output:**
- All identities linked to the same person
- Complete OPSEC failure timeline
- Associated infrastructure
- Discovered API keys / credentials
- Social graph (associates, contacts, group memberships)

---

### 8. Incident Response (Breach Scope Assessment)
**Profile:** Quantify breach impact, identify exposed data, downstream risk  
**Depth:** 2 | **Budget:** 200–500 credits | **Time:** 2–5 minutes

```bash
# Scan the breach source domain
hse scan --kind domain --value breached-company.com --depth 2 --full

# Extract all emails found
# Then bulk-scan them
hse scan --kind email --value admin@breached-company.com --depth 2 --full
hse scan --kind email --value support@breached-company.com --depth 2 --full
# ... (repeat for all extracted emails)
```

**Metrics HSE calculates:**
- Total unique emails in breach
- Unique passwords/hashes leaked
- Unique IP addresses (geographic spread)
- Unique usernames (for username reuse detection)
- Linked social media profiles
- Downstream risk (API keys found? Company infrastructure exposed?)

**Expected output:**
- Scope: X employees, Y customer records, Z API keys
- High-risk findings: Admin credentials, database backups, config files
- Downstream exposure: Linked vendor accounts, partner infrastructure
- Recommendation: Breach impact score, priority remediation

---

### 9. API Key Discovery (Credential Hunting)
**Profile:** Hunt leaked API keys in breach data, credential spraying prep  
**Depth:** 3 | **Budget:** 750–1500 credits | **Time:** 5–10 minutes

```bash
# Target a company known to be in breaches
hse scan --kind domain --value api.target-company.com --depth 3 --full

# Or scan a breach for all API key patterns
hse scan --kind domain --value target-company.com --depth 3 --full
# web_crawler probes config files (finds /api/config, .env, credentials.json)
# HSE extracts 80+ API key patterns (sk-ant-, AKIA, ghp_, etc.)
```

**Key extraction pipeline:**
1. SeekNow `/search` extracts breach records
2. web_crawler probes 103 config paths on discovered domains
3. api_key_probe recognizes 80+ key patterns in:
   - Breach record fields (password, extra, notes)
   - Fetched config files (.env, /api/config, .git/config, /.aws/credentials, etc.)
   - URL parameters (?key=, ?token=, ?api_key=)
4. Found keys auto-tagged as force-multiplier
5. Force-multiplier cascade unlocks Shodan, Censys, SecurityTrails (if keys work)

**Expected output:**
- All discovered API keys with source (breach, config file, URL)
- Validation (force-multiplier = tested and working)
- Infrastructure unlocked (if valid keys found)
- High-risk metrics: valid keys, compromised vendor access

---

## Workflow Chaining (Sequential Optimization)

For complex investigations, chain workflows:

```bash
# Phase 1: Email investigation (50 credits)
hse scan --kind email --value target@company.com --depth 1 --full

# Phase 2: Extract and expand on found username (100 credits)
# (Username auto-extracted from email or breach records)
hse scan --kind username --value found_username --depth 2 --full

# Phase 3: Expand on found domain (300 credits)
# (Domain auto-extracted from email domain or DNS)
hse scan --kind domain --value company.com --depth 3 --full

# Phase 4: Correlate all results
hse query --entity-kind person --sort breach_mentions DESC
hse query --entity-kind api-key --filter "validated: true"
```

**Total budget:** ~450 credits (out of 15,000 daily limit)  
**Scope:** Complete person dossier + infrastructure + API keys

---

## Budget Optimization

| Scan Type | Depth | Budget | Time | ROI |
|-----------|-------|--------|------|-----|
| Email (single) | 1 | 50–100 | 30s | High (fast, focused) |
| Username (multi-platform) | 2 | 150–300 | 2m | High (broad coverage) |
| Domain (full footprint) | 3 | 300–750 | 5m | Very High (complete picture) |
| Person (dossier) | 3 | 500–1000 | 10m | Very High (actionable) |
| Threat actor (hunting) | 3 | 1000+ | 15m | High (requires iteration) |
| Incident response | 2 | 200–500 | 5m | Critical (time-sensitive) |

**Your daily limit:** 15,000 credits = ~15 deep domain scans, or ~50–100 email/username scans

---

## Advanced Features (Built-In)

### Auto-Deduplication
- Same person discovered via multiple usernames? → 1 Person entity
- Same domain via multiple sources? → 1 Domain entity
- Entity dedup by SHA-256 hash (deterministic)

### Force-Multiplier Cascade
- API key found → Auto-validated (test against endpoint)
- Valid key → Immediately unlocks downstream module (Shodan, Censys, etc.)
- Cascade continues recursively through all depths

### Caching
- In-process cache (1,024 entries)
- Same query twice = 0 credits (2nd time is cached)
- Useful for cross-scan deduplication

### Response Archiving
- All responses saved to `~/.hse/raw_archive/see-know/`
- Audit trail for findings (proves data source)
- Replay capability (re-extract from original response)

### Error Recovery
- Rate limit (429) → Auto-backoff, continues next round
- Auth error (401) → Logs and disables for scan
- Timeout (>78s) → Graceful degradation, continues with other modules
- Transient errors → Auto-retry 3x with exponential backoff

---

## Usage Summary

```bash
# Fast email investigation
hse scan --kind email --value target@company.com --depth 1 --full

# Username multi-platform search
hse scan --kind username --value suspect_user --depth 2 --full

# Full domain infrastructure assessment
hse scan --kind domain --value target.com --depth 3 --full

# Person reconnaissance dossier
hse scan --kind name --value "John Doe" --depth 3 --full

# Threat actor hunting (multiple variants)
for variant in alice_92 alice92 alice.92; do
  hse scan --kind username --value $variant --depth 3 --full
done

# Incident response scope assessment
hse scan --kind domain --value breached.com --depth 2 --full

# Query results
hse query --entity-kind person --sort breach_mentions DESC
hse query --entity-kind api-key --filter "valid: true"
hse query --relationship family_name:Doe --min-strength 0.8
```

**All workflows are automatic.** HSE handles endpoint routing, budget optimization, error recovery, caching, archiving, deduplication, and entity correlation. You just pick a target and depth — SeekNow does the rest.
