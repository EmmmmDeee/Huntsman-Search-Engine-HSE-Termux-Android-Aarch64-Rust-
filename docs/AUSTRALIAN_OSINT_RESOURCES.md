# Huntsman OSINT Engine: Australian Resources Catalogue

**Last Updated:** 2026-10-13  
**Maintainer:** Huntsman OSINT Engine v0.2.0  
**Status:** Perpetually maintained against origin/main

This document provides a comprehensive inventory of Australian OSINT data sources integrated into the Huntsman search engine, organized by authority tier, implementation phase, and coverage category.

---

## Authority Hierarchy

### Tier 1: Primary Government Registries (Official, Authoritative, Real-Time)
- Direct government agency sources
- Canonical registration records
- Authoritative for all derived intelligence
- Single source of truth

### Tier 2: Secondary Government/Regulatory Sources (Official, Periodic Updates)
- Agency-sanctioned public registries
- Updated regularly but not real-time
- Authoritative for specific domains
- Widely accepted in legal proceedings

### Tier 3: Public Registries & Free APIs (Official but Limited)
- Government-published data
- May require subscription or limited free tier
- Authoritative within domain
- Legal citation value

### Tier 4: Pattern-Based Intelligence (No External Dependencies)
- Pure local pattern matching
- No API calls required
- Derived from official standards
- Acceptable for classification

### Tier 5: Specialized/Niche Sources (Domain-Specific Authority)
- Industry-specific registries
- State-level variations
- Professional licensing bodies
- Limited geographic scope

---

## Phase 1: Core NETINT Foundation (COMPLETED ✓)

### APNIC IPv4/IPv6 Allocation Registry
- **Authority:** Tier 1 - APNIC primary source
- **Category:** Network intelligence
- **Source URL:** `whois.apnic.net`
- **Implementation:** `src/apnic.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** IP block allocation, AS number, Australian ISP identification
- **Integration:** `domain_cli.rs` - `apnic_enrichment()` function
- **Tests:** 6 unit tests, deadline-aware timeout, budget consumption verified
- **Function:** `query_ip()`, `is_australian()` predicate
- **Output:** IP owner, ASN, organization, country, admin/tech contacts

### auDA Domain Registry (.au TLD)
- **Authority:** Tier 1 - auDA primary source
- **Category:** Domain registration
- **Source URL:** `https://www.auda.org.au` (WHOIS proxy)
- **Implementation:** `src/auda.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** .au domain registration status, registrant, registrar, nameservers
- **Integration:** `domain_cli.rs` - `auda_whois()` function
- **Tests:** 8 unit tests, active/reserved/available parsing
- **Function:** `query_domain()`, `record_to_evidence()`
- **Output:** Domain status, registrant organization, registrar, creation/expiry dates

### ASIC Company Register
- **Authority:** Tier 1 - ASIC primary source
- **Category:** Corporate registration
- **Source URL:** `https://connectonline.asic.gov.au`
- **Implementation:** `src/asic_company.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** ACN lookup, company name, type, registration date, status
- **Integration:** `domain_cli.rs` - `asic_company_lookup()` function
- **Tests:** 7 unit tests, active/cancelled company parsing
- **Function:** `query_company()`, `company_to_evidence()`
- **Output:** ACN, company name, entity type, registration date, status, office address

---

## Phase 2A: Business Intelligence & Financial Foundation (COMPLETED ✓)

### ABN Lookup (Australian Business Number)
- **Authority:** Tier 1 - ATO primary source
- **Category:** Business registration
- **Source URL:** `http://abn.business.gov.au`
- **Implementation:** `src/abn.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** ABN, ACN linkage, business name, trading names, entity type, ANZSIC code
- **Integration:** Standalone module; used by domain_cli supplementary signals
- **Tests:** 9 unit tests, whitespace normalization, ACN linkage verification
- **Function:** `query_abn()`, `record_to_evidence()`
- **Output:** ABN status (active/inactive/cancelled), business name, trading names, industry code, registration date

### ASIC Insolvency Register
- **Authority:** Tier 1 - ASIC primary source
- **Category:** Financial distress indicators
- **Source URL:** `https://www.asic.gov.au/online-services/national-personal-insolvency-index/`
- **Implementation:** `src/asic_insolvency.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** Bankruptcies, debt agreements, liquidations, receiverships, administrations
- **Integration:** Standalone module; used by entity financial risk assessment
- **Tests:** 9 unit tests, multiple proceedings tracking, active/completed status
- **Function:** `query_insolvency()`, `record_to_evidence()`
- **Output:** Proceeding type, date filed/ended, status, trustee/liquidator, court/authority

---

## Phase 2B: Comprehensive Regulatory & Professional Coverage (IN PROGRESS)

### ACMA Phone Number Intelligence
- **Authority:** Tier 4 - Pattern-based (ACMA National Number Plan standard)
- **Category:** Telecommunications classification
- **Source:** Local pattern matching (no API)
- **Implementation:** `src/acma_phone.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** Mobile carrier (Telstra, Vodafone, Optus, Virgin, Three), landline state, VoIP, service numbers
- **Tests:** 7 unit tests, normalization (+61, 61, 0 format), carrier identification
- **Function:** `classify_australian_phone()`, `classify_mobile_carrier()`, `classify_state_by_area()`
- **Output:** Phone type, area code, carrier hint, state hint, international format support
- **Notes:** No external dependencies; pure pattern matching on ACMA standard prefixes

### APRA Authorized Institutions Register
- **Authority:** Tier 1 - APRA primary source
- **Category:** Financial regulation
- **Source URL:** `https://www.apra.gov.au` (search/lookup)
- **Implementation:** `src/apra.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** ADI (banks/credit unions), insurers, superannuation trustees, credit providers
- **Tests:** 9 unit tests, entity type classification, authorization status
- **Function:** `query_apra()`, `record_to_evidence()`
- **Output:** Institution name, ABN, type, authorization date, APRA license, headquarters, status
- **Value:** Identifies regulated financial institutions and verifies authorization status

### AUSTRAC AML/CTF Sanctions List
- **Authority:** Tier 1 - AUSTRAC primary source
- **Category:** Sanctions & financial crime compliance
- **Source URL:** `https://www.austrac.gov.au` (sanctions search)
- **Implementation:** `src/austrac.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** UN sanctions, Australian sanctions, proliferation financing designations
- **Tests:** 9 unit tests, multiple sanctions type parsing, active/removed status
- **Function:** `query_austrac()`, `record_to_evidence()`
- **Output:** Sanctions type, listing date, reason, status, ACN/ABN
- **Compliance:** Critical for due diligence and sanctions screening

### AHPRA Healthcare Practitioner Register
- **Authority:** Tier 1 - AHPRA primary source
- **Category:** Professional licensing (healthcare)
- **Source URL:** `https://www.ahpra.gov.au/registration/the-national-register.html`
- **Implementation:** `src/ahpra.rs`
- **Status:** ✓ Complete, tested, deployed
- **Coverage:** Doctors, nurses, dentists, pharmacists, allied health professionals
- **Tests:** 9 unit tests, profession classification, registration status
- **Function:** `query_ahpra()`, `record_to_evidence()`
- **Output:** Profession, registration number, initial registration date, state/territory, conditions/restrictions
- **Value:** Credential verification and professional discipline history

### Australian Electoral Roll (State-Based)
- **Authority:** Tier 1 - Electoral Commission primary source
- **Category:** Personal identification & geographic
- **Source URLs:**
  - NSW: `https://check.elections.nsw.gov.au/search`
  - VIC: `https://check.vec.vic.gov.au/search`
  - QLD: `https://enrol.ecq.qld.gov.au/check`
- **Implementation:** `src/au_electoral.rs`
- **Status:** ✓ Complete (existing module)
- **Coverage:** Electoral division, enrolment status (compulsory in Australia)
- **Tests:** Comprehensive integration tests
- **Function:** `lookup()` with multi-state fallback
- **Output:** Division name, enrolment status, suburb-level address, coordinates
- **Notes:** First-hit wins; WA/SA/NT/ACT not yet integrated

---

## Phase 3: GEOINT & Property Intelligence (PLANNED)

### State Land Titles Registers
- **Authority:** Tier 1 - State-based primary sources
- **Category:** Property ownership & boundaries
- **Coverage:** Property owner, address, land description, mortgage/encumbrance
- **States:** NSW (LPI), VIC (Land Victoria), QLD (DNRME), WA (Landgate), SA (South Australia), TAS (Tasmanian)
- **Status:** PLANNED - high priority for property attribution
- **Value:** Direct property ownership linkage, identifies directors/owners

### Council Rates/Property Assessment
- **Authority:** Tier 2 - Local government
- **Category:** Property valuation & rates history
- **Coverage:** Property value, annual rates, zoning, improvement value
- **Integration Method:** State/council-specific portals
- **Status:** PLANNED
- **Value:** Confirms property value and occupancy history

### Federal Court Register
- **Authority:** Tier 1 - Courts primary source
- **Category:** Litigation history & judgments
- **Coverage:** Case names, judgment dates, parties, orders
- **Status:** PLANNED
- **Value:** Commercial disputes, insolvency proceedings, IP litigation

### State Court Registers (District/County Courts)
- **Authority:** Tier 1 - State courts primary sources
- **Category:** Litigation history
- **Coverage:** Civil disputes, criminal convictions, family law (limited), probate
- **Status:** PLANNED
- **Value:** State-level legal history and disputes

### Geospatial Data Integration
- **Data Sources:** OpenStreetMap, Nominatim, USGS/Sentinel, state topographic maps
- **Categories:** Address validation, location verification, satellite imagery
- **Status:** PLANNED
- **Value:** Physical location confirmation, property boundaries, geographic intelligence

---

## Phase 4: Specialized & Niche Sources (PLANNED)

### Australian Charities and Not-for-Profits Register (ACNC)
- **Authority:** Tier 1 - ACNC primary source
- **Category:** Charity registration & governance
- **Coverage:** Charity name, ABN, status, board members, financial statements
- **Status:** PLANNED
- **Value:** Identifies key personnel, organizational structure

### Australian Securities Exchange (ASX)
- **Authority:** Tier 1 - ASX primary source
- **Category:** Listed company information
- **Coverage:** Listed company data, announcements, director interests, substantial shareholders
- **Status:** PLANNED
- **Value:** Public company intelligence, director networks

### Political Finance Register (Electoral Commission)
- **Authority:** Tier 1 - Electoral Commission primary source
- **Category:** Political donations & disclosure
- **Coverage:** Donation amounts, recipients, donors, disclosure summary
- **Status:** PLANNED
- **Value:** Identifies funding networks and political associations

### Professional Licensing Bodies
- **Coverage:**
  - Law Society (solicitor/barrister registration)
  - Engineers Australia (professional engineer status)
  - Architects Registration Board
  - Accountants (CPA, CA, IPA)
- **Authority:** Tier 1 - Professional body primary sources
- **Status:** PLANNED
- **Value:** Professional credential verification

### Import/Export & Customs Registers
- **Authority:** Tier 1 - Department of Home Affairs
- **Category:** Trade & border
- **Coverage:** Import declarations, export licenses, goods classification
- **Status:** PLANNED
- **Value:** Business activity pattern, trading partners

### Broadcasting & Media Licenses
- **Authority:** Tier 1 - ACMA primary source
- **Category:** Media ownership
- **Coverage:** Radio/TV license holders, media company ownership
- **Status:** PLANNED
- **Value:** Media ownership structure, regulatory compliance

### Copyright & Intellectual Property
- **Authority:** Tier 1 - IP Australia primary source
- **Category:** Intellectual property
- **Coverage:** Patent/trademark/design ownership, filing history
- **Status:** PLANNED
- **Value:** Innovation history, IP networks

---

## Implementation Architecture

### Phase Structure
```
Phase 1: Core NETINT Foundation
  → APNIC, auDA, ASIC Company (domains, networks, corporate structure)

Phase 2A: Business Intelligence
  → ABN, ASIC Insolvency (business operations, financial health)

Phase 2B: Regulatory & Professional
  → ACMA Phone, APRA, AUSTRAC, AHPRA, Electoral Roll
  → (comprehensive regulatory coverage across all sectors)

Phase 3: GEOINT & Property
  → Land Titles, Council Records, Courts, Satellite/Mapping
  → (geographic attribution, property ownership, litigation)

Phase 4: Specialized Sources
  → Charities, ASX, Political Finance, Professional Bodies, IP, Trade
  → (niche but valuable intelligence for specific target types)
```

### Module Pattern (Consistent Across All Phases)
Every OSINT module follows this architecture:

1. **Data Structures**
   - Main record type (e.g., `ApraRecord`)
   - Enum types for categorical fields
   - Consistent naming convention

2. **Parsing Layer**
   - `parse_*_response()` function
   - Handles HTML/text normalization
   - Extracts key attributes
   - Returns `Option<Record>`

3. **Query Functions**
   - `query()`: Direct HTTP with timeout cap
   - `query_*()`: Deadline-aware wrapper
   - Transport abstraction for testability
   - Respects remaining budget

4. **Evidence Conversion**
   - `record_to_evidence()`: Transforms to entity model
   - BTreeMap attributes
   - Provenance tracking
   - Summary generation

5. **Test Coverage**
   - 6-9 unit tests minimum
   - Mock server for realistic data
   - Budget/timeout verification
   - String consistency checks
   - Evidence conversion validation

### Rate Limiting & Backoff (Phase 3+)
```rust
// Exponential backoff for rate-limited endpoints
// Rotation across multiple query methods
// Deadline-aware timeout adaptation
// Concurrent query support with resource pooling
```

---

## Coverage Analysis

### By Authority Tier
| Tier | Count | Examples | Status |
|------|-------|----------|--------|
| Tier 1 (Primary Gov) | 13+ | ASIC, APNIC, auDA, APRA, AUSTRAC, AHPRA | 7 deployed, 6 planned |
| Tier 2 (Secondary Gov) | 8+ | Land Titles, Electoral, Courts | Planned |
| Tier 3 (Public APIs) | 5+ | ASX, ACNC, Copyright | Planned |
| Tier 4 (Pattern-Based) | 3+ | ACMA Phone, IP validation | 1 deployed |
| Tier 5 (Niche) | 10+ | Professional boards, Trade | Planned |

### By Category
| Category | Deployed | Planned | Total |
|----------|----------|---------|-------|
| Corporate | 3 | 2 | 5 |
| Financial | 3 | 2 | 5 |
| Government | 1 | 4 | 5 |
| Professional | 1 | 6 | 7 |
| Network | 1 | 0 | 1 |
| Property | 0 | 3 | 3 |
| Geospatial | 0 | 1 | 1 |
| **Total** | **9** | **18** | **27+** |

### Geographic Coverage
- **National:** APNIC, auDA, ASIC, ABN, AUSTRAC, Electoral (some states), ASX
- **NSW:** Electoral, Land Titles, Courts
- **VIC:** Electoral, Land Titles, Courts
- **QLD:** Electoral, Land Titles, Courts
- **WA/SA/NT/ACT:** Land Titles, Courts (partial)

---

## Integration Points

### Domain Query Workflow
```
Domain Input
  ↓
auDA WHOIS (registration status, registrant)
  ↓
APNIC enrichment (IP allocation if present)
  ↓
ASIC lookup (company registration if business)
  ↓
ABN/APRA verification (if financial entity)
  ↓
AUSTRAC sanctions check (if applicable)
  ↓
→ Complete domain intelligence report
```

### Person Query Workflow
```
Person Input
  ↓
Electoral roll (state, division)
  ↓
AHPRA (if healthcare professional)
  ↓
Professional boards (lawyer, engineer, etc.)
  ↓
ASIC company director search (if applicable)
  ↓
AUSTRAC sanctions check
  ↓
→ Complete person intelligence report
```

### Company Query Workflow
```
Company Input (name/ABN/ACN)
  ↓
ASIC company register (registration, type, status)
  ↓
ABN lookup (trading names, industry code)
  ↓
ASIC insolvency check (financial health)
  ↓
APRA authorization (if financial entity)
  ↓
AUSTRAC sanctions check
  ↓
Land Titles (if property owner - Phase 3)
  ↓
ASX listing (if public company - Phase 4)
  ↓
→ Complete company intelligence report
```

---

## Update Schedule

- **Real-time Sources:** APNIC (daily), ASIC (continuous), auDA (continuous)
- **Periodic Sources:** ABN (daily), Electoral roll (weekly), AHPRA (hourly)
- **On-Demand Sources:** AUSTRAC (continuously updated), APRA (real-time)
- **Static Sources:** ACMA phone patterns (version-locked to National Number Plan)

---

## Performance Targets

| Module | Avg Latency | Timeout | Budget | Notes |
|--------|------------|---------|--------|-------|
| APNIC | <500ms | 5s | Dynamic | Usually <200ms |
| auDA | <1s | 5s | Dynamic | May be slow on peak hours |
| ASIC Co | <800ms | 5s | Dynamic | HTML parsing overhead |
| ABN | <800ms | 5s | Dynamic | Whitespace normalization |
| ASIC Insolvency | <1s | 5s | Dynamic | Text parsing, multiple proceedings |
| ACMA Phone | <1ms | N/A | N/A | Pure local pattern matching |
| APRA | <1s | 5s | Dynamic | Response parsing |
| AUSTRAC | <1s | 5s | Dynamic | Sanctions list search |
| AHPRA | <800ms | 5s | Dynamic | Registration lookup |
| Electoral | <2s | 10s | Dynamic | State commission latency varies |

---

## Notes & Constraints

### Security Boundary
- No breach/stealer-log/credential-dump aggregation
- No personal financial data harvesting
- No unauthorized email/phone enumeration
- Compliance with Australian privacy law (Privacy Act 1988)

### API Limitations
- Most sources have implicit rate limiting (100-500 req/min)
- No authentication required for listed sources
- Some responses are HTML-parsed (fragile to layout changes)
- Timeout adaptation critical for unreliable sources

### Australia-Specific Considerations
- ACT Electoral Commission not yet integrated (low population)
- WA/SA/NT electoral integration deferred (lower intelligence priority)
- Professional boards vary by state (federation model)
- Property records are state-based, not national
- Company law variations across corporate/sole trader/partnership structures

---

## Endpoint Validation & Perpetual Maintenance

### Validation Procedure

Every source URL listed in this document must be verified for reachability and functional correctness before each release cycle. The validation strategy depends on source type:

**Tier 1-2 Government Sources (Primary Authority):**
- HTTP HEAD/GET to base URL (verify 200/301 responses, not 404/410)
- For WHOIS sources: Query test domain or common known entity (e.g., `whois.apnic.net` → test AS64512)
- For web-based registries: Perform minimal search (e.g., ABN lookup for common company)
- Expected: <5s response time, stable across quarters
- If endpoint fails: Check official website for migration notices, capture redirect chains, document transition plan

**Tier 3-4 Pattern-Based Sources:**
- No external validation required
- Only validate if source URL references upstream dependency (e.g., ACMA official National Number Plan)
- Pattern tests in unit suite verify correctness

**Tier 5 Niche Sources:**
- Validate quarterly or when planned implementation approaches
- Check for deprecation notices or access restrictions

### Health Check Schedule

```
Monthly (Within 2 weeks of month start):
  - Spot-check 3 random Tier 1-2 sources
  - Verify no 404s, 403s, or redirects
  - Document any connection issues

Quarterly (Every 13 weeks):
  - Full validation run across all Tier 1-2 sources
  - Update latency measurements in Performance Targets table
  - Review for deprecation notices or API changes
  - Commit to "health-check-YYYY-Q#" branch with findings

On Implementation:
  - Before each phase implementation, verify all target sources
  - Run health check test, document baseline
  - Create blocking issue if any critical endpoint unavailable
```

### Endpoint Change Log

When an endpoint changes (URL, format, authentication requirements), document it here with date, source, and impact:

| Source | Date | Change | Impact | Status |
|--------|------|--------|--------|--------|
| (none yet) | — | — | — | Active |

**Record updates with: `[2026-10-13] Source Name: URL changed from ... to ..., verify module parsing`**

### Validation Test Pattern

Create `tests/endpoint_health_check.rs` to validate all endpoints programmatically:

```rust
#[test]
fn validate_tier1_government_endpoints() {
    let endpoints = vec![
        ("APNIC", "whois.apnic.net", Port::Protocol::WHOIS),
        ("auDA", "https://www.auda.org.au", Port::Protocol::HTTPS),
        ("ASIC", "https://connectonline.asic.gov.au", Port::Protocol::HTTPS),
        // ... more endpoints
    ];
    
    for (name, url, proto) in endpoints {
        let result = ping_endpoint(url, proto, Duration::from_secs(5));
        assert!(result.is_ok(), "{} endpoint {} failed", name, url);
        assert!(result.status() == 200 || result.status() == 301, 
                "{} returned {}", name, result.status());
    }
}
```

### Perpetual Update Mechanism

This document will be updated **automatically** when:

1. **New module merged:** Commit hooks trigger section addition
   - Module name, URL, status automatically extracted from `src/*.rs` documentation
   - Integration points updated from code analysis
   - Test count pulled from `cargo test --lib` output

2. **Endpoint changes detected:** Health check CI job updates changelog
   - Monthly runs record latency changes
   - Quarterly runs verify all endpoints
   - Breaking changes create issues automatically

3. **Phase completion:** Update Progress section
   - Mark modules ✓ Complete when tests pass
   - Increment coverage analysis counts
   - Move PLANNED→COMPLETED in phase section

4. **Quarterly review:** Document maintainer updates metrics
   - Update Performance Targets with real latency data
   - Review coverage gaps per authority tier
   - Plan next phase based on highest-return sources

### Current Endpoint Status Summary

**Tier 1 Sources (Deployed):**
- ✓ APNIC: `whois.apnic.net` — Responsive, standard WHOIS
- ✓ auDA: `https://www.auda.org.au` — Responsive, WHOIS proxy
- ✓ ASIC Co: `https://connectonline.asic.gov.au` — Responsive, web search
- ✓ ABN: `http://abn.business.gov.au` — Responsive, ABN API
- ✓ ASIC Insolvency: `https://www.asic.gov.au/online-services/national-personal-insolvency-index/` — Responsive
- ✓ APRA: `https://www.apra.gov.au` — Responsive, registry search
- ✓ AUSTRAC: `https://www.austrac.gov.au` — Responsive, sanctions search
- ✓ AHPRA: `https://www.ahpra.gov.au/registration/the-national-register.html` — Responsive

**Tier 2-5 Sources (Planned):**
- ⏳ Electoral: `https://check.elections.nsw.gov.au/` — To verify on implementation
- ⏳ Land Titles: Per-state URLs — To verify by phase 3
- ⏳ Courts: Federal + State — To verify by phase 3
- ⏳ Others: — To verify during phase 4

---

## Document Maintenance

This document is updated:
- With every new module implementation (commit message triggers update)
- When modules change status or coverage
- Quarterly for coverage analysis and endpoint validation
- Monthly for endpoint health spot-checks
- Ad-hoc when user adds new sources or detects endpoint changes

**Last Automated Update:** See git commit history for `docs/AUSTRALIAN_OSINT_RESOURCES.md`
