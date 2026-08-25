# SeekNow Integration Quick Start (15,000 searches/day)

## Status: Production-Ready

SeekNow is fully integrated into HSE with 19 working endpoints. Despite the public API being disabled, your **logged-in Enterprise account maintains full 15,000 daily quota** access.

---

## 1. Setup (One-Time)

### Get Your API Key

1. Log in to https://see-know.ru
2. Go to **Account → API Keys** (or Dashboard)
3. Copy your key (format: `seek-` prefix, 64+ chars)

### Configure HSE

**Option A: Environment Variable (Simplest)**
```bash
export HUNTSMAN_SEEKNOW_KEY="seek-YOUR_ACTUAL_KEY_HERE"
hse scan <target>
```

**Option B: HSE Config File**
```bash
mkdir -p ~/.huntsman
cat > ~/.huntsman/config.toml << 'EOF'
[services]
seeknow_key = "seek-YOUR_ACTUAL_KEY_HERE"

# Optional: override per-scan budget (default: auto-scaled from daily quota)
seeknow_scan_cap = 500  # credits per scan (auto-scaled to 300-2500 range)
EOF
```

**Option C: Hardcode in This Session (Development)**
```bash
# Use the env var immediately:
HUNTSMAN_SEEKNOW_KEY="seek-YOUR_ACTUAL_KEY_HERE" hse scan target@example.com
```

---

## 2. Verify Configuration

Check remaining quota without spending credits:
```bash
HUNTSMAN_SEEKNOW_KEY="seek-YOUR_ACTUAL_KEY_HERE" hse stats
# Shows: "SeekNow: 15000 credits remaining" (or current daily remainder)
```

Dry-run a search (logs what WOULD be queried, no API call):
```bash
hse scan --dry-run target@example.com
```

---

## 3. Quick Usage Examples

### Email Enumeration (Your Priority)
```bash
# Search an email address for breaches, stealer logs, service registrations
hse scan user@company.com

# Output includes:
#  • Breach records (username, password hash, dates)
#  • Stealer logs (malware artifacts, infected systems)
#  • Service maps (linked accounts across platforms)
#  • Credentials discovered
```

### Username Enumeration
```bash
# Search a username across 22+ platforms (GitHub, Reddit, Twitter, Discord, etc.)
hse scan octocat

# Output includes:
#  • Profile links (GitHub, Twitter, Discord, Roblox, Minecraft, Xbox, etc.)
#  • Account linkages (Discord → Steam → Roblox chains)
#  • Compromised account evidence (breaches, stealers)
#  • Discovered credentials
```

### Multi-Target Scan (Batch)
```bash
# Scan multiple targets in one operation (shared budget)
hse scan user1@example.com user2@example.com octocat justname
```

### Full Scan (Aggressive — Uses Full Budget)
```bash
# Use entire daily quota for one target (expansion into discovered entities)
HUNTSMAN_SEEKNOW_SCAN_CAP=2500 hse scan deep_target@example.com
```

---

## 4. Budget & Rate Limiting

| Plan | Daily Credits | Per-Scan Cap | Rate Limit |
|------|---------------|--------------|----|
| Enterprise | 15,000 | 300–2,500 (auto-scaled) | 429 retries: 2s→4s→8s backoff |
| PremiumHQ | 5,000 | 250–1,667 | Same |
| Pro | 500 | 25–167 | Same |
| Beginner | 100 | 5–33 | Same |

**Auto-Scaling:** HSE probes your quota on the first target (`/credits` endpoint, free) and scales the per-scan budget: `clamp(daily_limit / 20, 300, 2500)`. A full daily quota of 15,000 means ~750 credits per scan by default.

**Override:** Set `HUNTSMAN_SEEKNOW_SCAN_CAP` env var to force a specific budget.

---

## 5. Endpoints Available (19 Total)

### Universal (Use First)
| Endpoint | Credits | Use Case |
|----------|---------|----------|
| `/search` | 1 | Breach + stealer + external records unified; auto-routes by target type |
| `/search/deep` | 1 | Fallback when fast search draws blank; slower but higher-yield corpus |
| `/credits` | 0 (FREE) | Check remaining quota |

### Email-Specific
| Endpoint | Credits | Returns |
|----------|---------|---------|
| `/network/email-check` | 1 | Service existence map (linked accounts) |

### Username-Specific
| Endpoint | Credits | Returns |
|----------|---------|---------|
| `/username/social` | 1 | Multi-platform aggregate (1 call covers 600+ sites) |
| `/username/{github,twitter,reddit,tiktok,roblox,xbox,minecraft}` | 1 each | Platform-specific profile depth |
| `/username/history` | 1 | Historical account usage |
| `/discord/user` | 1 | Discord profile + linked accounts |
| `/discord/to-roblox` | 1 | Discord ID → Roblox linkage |
| `/gaming/{minecraft,roblox,xbox,steam}` | 1 each | Gaming platform profiles + linked accounts |

### Network/Domain
| Endpoint | Credits | Returns |
|----------|---------|---------|
| `/network/ip` | 1 | IP geolocation + ASN + hosting provider |
| `/network/phone` | 1 | Phone number enrichment (carrier, line type) |
| `/domain/intel` | 1 | Domain intelligence (registrar, history) |
| `/domain/whois` | 1 | WHOIS data |

### Pivots (Automatic Chain Resolution)
- **Discord ID → Linked Accounts**: `/discord/user` returns linked Steam, Minecraft, Roblox
- **Steam ID → Linked Accounts**: Gaming linkage resolution
- **Email Cascade**: Re-query discovered emails via `/network/email-check` for new service registrations (3 per hop, up to 3 hops)

---

## 6. What Data Is Extracted

Each SeekNow result yields:

**Credentials & Security:**
- Passwords (plaintext + hashes: MD5, SHA1, bcrypt, scrypt)
- API keys, tokens, SSH keys (80+ prefix patterns)
- Cryptocurrency addresses
- Discord tokens, session IDs

**Identity:**
- Email addresses
- Usernames (cross-platform)
- Full names
- Phone numbers
- Physical addresses (street, city, state, ZIP)

**Digital Footprint:**
- Social media handles (Twitter, GitHub, Reddit, Telegram, Facebook, Instagram)
- Gaming profiles (Discord, Steam, Roblox, Minecraft, Xbox)
- Profile URLs + linked accounts

**Network & Device:**
- IP addresses + geolocation
- ASN + hosting provider
- MAC addresses
- Device IDs (HWID)
- Operating system (Windows, Mac, Linux version)

**Metadata:**
- Source (breach database, stealer log, OSINT corpus)
- Compromise date
- Malware family (if stolen via infostealer)

---

## 7. Response Format (JSON)

Example `/search` response for `target@example.com`:
```json
{
  "breach_count": 5,
  "stealer_count": 2,
  "external_count": 12,
  "records": [
    {
      "email": "target@example.com",
      "username": "targetuser",
      "password": "PlainPassword123",
      "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "hash_type": "md5",
      "first_name": "John",
      "last_name": "Doe",
      "phone": "555-0123",
      "ip": "203.0.113.42",
      "country": "United States",
      "state": "California",
      "city": "San Francisco",
      "address": "123 Main St, San Francisco, CA 94102",
      "coordinates": { "lat": 37.7749, "lng": -122.4194 },
      "company": "Example Corp",
      "domain": "example.com",
      "source": "OathNet",  /* or "Hudson Rock", "BreachDB", etc. */
      "compromise_date": "2024-01-15",
      "stealer_family": "Generic Stealer",
      "dbname": "Tianya",
      "breach_date": "2023-12-20"
    }
  ]
}
```

---

## 8. Error Handling

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Proceed normally |
| 401 | Invalid/expired API key | Check key format; regenerate if needed |
| 403 | Plan doesn't support endpoint | Endpoint skipped, other queries continue |
| 404 | Not found (no records) | Clean negative; try `/search/deep` if typed query |
| 429 | Rate limited | Auto-retry with backoff (2s→4s→8s, max 3x) |
| 500 | Server error | Auto-retry; transient failures are expected |

HSE handles all retries and errors internally. Quota exhaustion (`0 credits_remaining`) stops new queries for the remainder of the day (resets at midnight UTC).

---

## 9. Integration with HSE Modules

SeekNow runs **highest priority** (u8::MAX) in HSE's module stack:

1. **Phase 1 (Paid Modules):** SeekNow queries first, seeding the graph
2. **Per-scan expansion:** Every email/username discovered is re-queried through SeekNow
3. **Caching:** Results cached 24h; repeat scans replay for FREE
4. **Identity pivots:** Discord/Steam/email chains resolved automatically

### Combined with Other Modules

| Module | Integration |
|--------|--------------|
| `oathnet_pro` | Parallel pool (15,000 vs 5,000 daily quota); distinct corpora overlap but don't duplicate |
| `username_search` | SeekNow platform-specific depths + free presence-only checks; both run |
| `social_probe` | Same; free scraping + paid profile depth |
| `geocode_osint` | SeekNow coordinates + free geocoding layers stack |
| `cert_intel` | Domain intelligence (cert SAN) from SeekNow + Censys |

---

## 10. Troubleshooting

### "SeekNow: 0 credits remaining"
- Daily quota exhausted; resets at midnight UTC
- Check `hse stats` for daily limit and reset time

### "401: Invalid API key"
- Key is expired or wrong format
- Verify key starts with `seek-` and is 64+ chars
- Regenerate key in see-know.ru dashboard

### "429: Rate limited"
- HSE retries automatically (2s→4s→8s backoff, 3x)
- If persistent: may have exceeded per-second RPS; try again in 60s

### "404: Not found"
- Target has no records in SeekNow corpus
- Try alternative search types (full name auto-detect, related usernames)
- Use `/search/deep` fallback for typed queries (auto-triggered on typed miss)

### "Scan timing out"
- SeekNow `/search` on name/auto can take 55s (server cap)
- `/search/deep` fallback adds up to 40s more
- Total budget: 110s per scan (configured in `src/modules/see_know/mod.rs`)
- **Termux override:** Full 110s budget even on Termux (normally 45s module cap, but Termux cap is exempt for SeekNow)

---

## 11. MITRE Mapping

SeekNow directly enables reconnaissance against these MITRE ATT&CK techniques:

| Technique | HSE Coverage |
|-----------|--------------|
| **T1589.001** | Credentials — passwords, hashes, API keys |
| **T1589.002** | Email Addresses — breach database harvest |
| **T1589.003** | Employee Names — full names from linked accounts |
| **T1590.005** | IP Addresses — geolocation + ASN data |
| **T1591.001** | Physical Locations — addresses, coordinates, city/state |
| **T1591.002** | Business Relationships — company, employer, org data |
| **T1592** | Host Information — MAC, HWID, device fingerprints |
| **T1593.001** | Social Media — Discord, Steam, GitHub, Twitter handles |
| **T1597.002** | Technical Data Purchase — closed breach/OSINT corpus access |

---

## 12. Hardcoded Defaults (Production Config)

File: `src/util/see_know/enterprise_config.rs`

```rust
// Daily quota for Enterprise plan (your account)
pub const ENTERPRISE: u32 = 15_000;

// Per-scan budget scaling (auto-set on first target)
// Formula: clamp(daily_limit / 20, 300, 2500)
// For 15,000 quota: clamp(750, 300, 2500) = 750 credits/scan
```

**Key environment variables:**
```bash
HUNTSMAN_SEEKNOW_KEY="seek-..."              # Your API key (REQUIRED)
HUNTSMAN_SEEKNOW_SCAN_CAP=750                # Override per-scan budget (optional)
```

---

## 13. Live Example: Username Enumeration (Your Priority)

```bash
# Set API key
export HUNTSMAN_SEEKNOW_KEY="seek-YOUR_KEY_HERE"

# Scan a username (credential harvesting focus)
hse scan octocat

# HSE will:
# 1. Query /search (universal) — 1 credit
# 2. Query /username/social — 1 credit (600+ platforms)
# 3. Query /username/github, /username/twitter, etc. — 1 credit each
# 4. If Discord ID found: /discord/user → linked accounts
# 5. If Steam ID found: /gaming/steam → linked accounts
# 6. Cascade detection: re-query discovered emails via /network/email-check
# 7. Extract: passwords, linked accounts, social profiles, device fingerprints

# Output example:
# Entity: octocat (Username)
#   └─ Evidence: SeekNow breach records (GitHub profile compromise)
#      └─ Credentials found: password_hash_md5, email_verified
#      └─ Linked: discord.id=... steam.id=... roblox.id=...
#      └─ Social: github.com/octocat twitter.com/octocat
#      └─ Devices: Windows 11 (device_id), IP=203.0.113.42
```

---

## 14. Next Steps

1. **Get your API key** from https://see-know.ru/account
2. **Set the environment variable:**
   ```bash
   export HUNTSMAN_SEEKNOW_KEY="seek-YOUR_KEY_HERE"
   ```
3. **Verify quota:**
   ```bash
   hse stats
   ```
4. **Run your first scan:**
   ```bash
   hse scan target@example.com
   # or
   hse scan targetusername
   ```
5. **Monitor credit usage:**
   ```bash
   hse doctor
   # Shows SeekNow endpoint health + current quota
   ```

---

## 15. Rate Limits & SLA

- **Per-scan timeout:** 110s (55s on `/search`, up to 40s on `/search/deep` fallback)
- **Concurrent calls:** Bounded by per-scan budget
- **Daily resets:** Midnight UTC
- **Transient 429 (Rate Limited):** Auto-retry up to 3x with exponential backoff
- **Persistent errors:** Logged with endpoint name; don't block other queries

---

**Status: Ready to Use**

Your 15,000 daily searches are available immediately. Set `HUNTSMAN_SEEKNOW_KEY` and run `hse scan`.

For questions: Check `src/util/see_know/mod.rs` or `src/modules/see_know/mod.rs` (production implementation; full test coverage with 80+ test cases).
