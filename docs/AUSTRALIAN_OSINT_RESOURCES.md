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
- **Coverage:** Property owner, address, land description, mortgage/encumbrance, easements
- **States & Registries:**
  - NSW: Land and Property Information (LPI) `https://www.lpi.nsw.gov.au`
  - VIC: Land Victoria / Vic Titles `https://www.land.vic.gov.au`
  - QLD: Department of Natural Resources & Mines `https://www.dnrme.qld.gov.au`
  - WA: Landgate `https://www.landgate.wa.gov.au`
  - SA: Department for Environment and Water `https://www.adelaidenow.com.au`
  - TAS: Tasmanian Titles Office `https://titles.tas.gov.au`
  - ACT: Australian Capital Territory Legislation Register
  - NT: Northern Territory Land Titles
- **Status:** PLANNED - high priority for property attribution
- **Value:** Direct property ownership linkage, identifies directors/owners, director home addresses
- **Integration Challenge:** Per-state HTML parsing, varying formats, potential authentication requirements

### Council Rates & Property Assessment Records
- **Authority:** Tier 2 - Local government authorities
- **Category:** Property valuation & rates history
- **Coverage:** Property value, annual rates, zoning classification, improvement value, council district
- **Geographic Scope:** 500+ local councils across Australia
- **Integration Method:** Per-council web portals (no standardized API)
- **Data Points:** Current owner, property value, land size, improvement value, zoning, rates paid
- **Status:** PLANNED
- **Value:** Confirms property value and occupancy history, identifies patterns of asset accumulation
- **Challenge:** Highly fragmented - each council different system, authentication, format

### Federal Court of Australia Register
- **Authority:** Tier 1 - Federal Court primary source
- **Category:** Litigation history & judgments
- **Source URL:** `https://www.fedcourt.gov.au`
- **Coverage:** Case names, judgment dates, parties, orders, appeal history, intellectual property, bankruptcy, administrative law
- **Search By:** Case number, party name, judge, date range
- **Status:** PLANNED
- **Value:** Commercial disputes, insolvency proceedings, IP litigation, regulatory enforcement actions
- **Intelligence Value:** Company disputes, director liability, intellectual property disputes, regulatory sanctions

### State Court Registers (Supreme/District/County Courts)
- **Authority:** Tier 1 - State courts primary sources
- **Category:** Litigation history & disputes
- **States & Registries:**
  - NSW: Supreme Court of NSW `https://www.supremecourt.nsw.gov.au`
  - VIC: Supreme Court of Victoria `https://www.supremecourt.vic.gov.au`
  - QLD: Supreme Court of Queensland `https://www.courts.qld.gov.au`
  - WA: Supreme Court of WA `https://www.supremecourt.wa.gov.au`
  - SA: Supreme Court of South Australia `https://www.courts.sa.gov.au`
  - TAS: Supreme Court of Tasmania `https://www.courts.tas.gov.au`
  - ACT: Supreme Court of ACT `https://www.courts.act.gov.au`
  - NT: Supreme Court of NT `https://www.courts.nt.gov.au`
- **Coverage:** Civil disputes, criminal convictions, family law (limited), probate, property disputes
- **Status:** PLANNED
- **Value:** State-level legal history and disputes, director liability cases, family law discoveries
- **Challenge:** Per-state registry, different search interfaces, limited historical data online

### Criminal Records & Sentencing Database
- **Authority:** Tier 1-2 (State-managed, limited public access)
- **Category:** Criminal history & convictions
- **Availability:** State & Federal police records (limited public access)
- **Status:** PLANNED
- **Value:** Director disqualification, criminal associations, regulatory violations
- **Challenge:** Privacy restrictions, limited OSINT-accessible data

### Bankruptcy & Insolvency Registers
- **Registries:**
  - Federal: National Personal Insolvency Index (NPII) `https://www.asic.gov.au/online-services/national-personal-insolvency-index/`
  - State: Individual state insolvency registers
  - Corporate: ASIC Insolvency Register (already deployed)
- **Status:** Federal mostly deployed, state registers PLANNED
- **Value:** Historical financial distress, creditor networks, trustee/receiver identification

### Geospatial Data Integration
- **Data Sources:**
  - OpenStreetMap `https://www.openstreetmap.org` - free geographic data, community maintained
  - Nominatim `https://nominatim.openstreetmap.org` - reverse geocoding, address validation
  - USGS Earth Explorer `https://earthexplorer.usgs.gov` - satellite imagery, Landsat
  - ESA Sentinel Hub `https://scihub.copernicus.eu` - European satellite imagery
  - Australian Geoscience Data Cube `https://www.dea.ga.gov.au` - satellite time-series
  - Bureau of Meteorology `http://www.bom.gov.au` - weather/climate data
- **Categories:** Address validation, location verification, satellite imagery, terrain analysis, historical imagery
- **Coverage:** Temporal satellite imagery (2000-present), address geocoding, reverse lookup
- **Status:** PLANNED
- **Value:** Physical location confirmation, property boundaries, geographic intelligence, change detection
- **Integration:** Tile-based imagery, REST APIs for geocoding, historical archives

### Utilities & Infrastructure Records
- **Authority:** Tier 2 - Utility companies & regulators
- **Category:** Infrastructure & connectivity
- **Data Points:** NBN coverage, electricity connections, gas, water services, optical fiber
- **Registries:**
  - NBN Co `https://www.nbnco.com.au` - broadband infrastructure
  - Australian Energy Regulator `https://www.aer.gov.au` - electricity/gas
  - Water Services Association `https://www.wsaa.asn.au`
- **Status:** PLANNED (partial public data)
- **Value:** Address confirmation, infrastructure development patterns, service availability intelligence

---

## Phase 4: Specialized & Niche Sources (PLANNED)

### Australian Charities and Not-for-Profits Register (ACNC)
- **Authority:** Tier 1 - ACNC primary source
- **Category:** Charity registration & governance
- **Source URL:** `https://www.acnc.gov.au/search`
- **Coverage:** Charity name, ABN, ACN, status, entity type, annual revenue, board members, financial statements
- **Search By:** Charity name, ABN, ACN, state, category
- **Data Points:** Charity status (registered/not registered), core activity, geography, financial data
- **Status:** PLANNED
- **Value:** Identifies key personnel (board members), organizational structure, funding sources, charitable purposes
- **Intelligence:** Director networks, organizational hierarchy, nonprofit funding patterns

### Australian Securities Exchange (ASX)
- **Authority:** Tier 1 - ASX primary source
- **Category:** Listed company information
- **Source URL:** `https://www.asx.com.au`
- **Coverage:** Listed company data, announcements, director interests, substantial shareholders, company news
- **Search Points:** Company code, name, sector, index membership
- **Data:** Share price, market cap, directors, substantial shareholders (5%+), regulatory announcements
- **Status:** PLANNED
- **Value:** Public company intelligence, director networks, financial position, regulatory compliance history
- **Intelligence:** Director interlocks, shareholder networks, acquisition patterns, regulatory violations

### Political Finance Register & Disclosures
- **Authority:** Tier 1 - Electoral Commission primary sources
- **Registries by State:**
  - Federal: Australian Electoral Commission (AEC) `https://www.aec.gov.au`
  - NSW: NSW Electoral Commission `https://www.elections.nsw.gov.au`
  - VIC: Victorian Electoral Commission `https://www.vec.vic.gov.au`
  - QLD: Queensland Electoral Commission `https://www.ecq.qld.gov.au`
  - WA: Electoral Commission of WA `https://www.elections.wa.gov.au`
  - SA: Electoral Commission of SA `https://www.elections.sa.gov.au`
  - TAS: Electoral Commission of Tasmania `https://www.elections.tas.gov.au`
  - ACT: ACT Electoral Commission `https://www.elections.act.gov.au`
  - NT: NT Electoral Commission `https://www.nt.gov.au/voting-and-elections`
- **Category:** Political donations & disclosure
- **Coverage:** Donation amounts, recipients (parties/candidates), donors, disclosure summary, campaign expenditure
- **Data Points:** Donor identity, amount, recipient, date, purpose
- **Status:** PLANNED
- **Value:** Identifies funding networks, political associations, financial influence patterns
- **Intelligence:** Corporate political influence, dark money patterns, candidate funding sources

### Professional Licensing Bodies
- **Coverage by Profession:**
  - **Law:** Law Society of NSW `https://www.lawsociety.com.au/`, Law Institute of Victoria, Bar associations
  - **Engineering:** Engineers Australia `https://www.engineersaustralia.org.au` - licensed engineer register
  - **Architecture:** Architects Registration Board `https://www.arb.org.au`
  - **Accounting:** CPA Australia `https://www.cpaa.org.au`, Chartered Accountants `https://www.charteredaccountantsanz.com`, IPA `https://www.publicaccountants.org.au`
  - **Medical:** AHPRA (already deployed), AMC registrations
  - **Psychology:** AHPRA psychology register (already deployed)
  - **Real Estate:** State real estate agent registers
  - **Valuation:** Australian Property Institute
- **Authority:** Tier 1 - Professional body primary sources
- **Status:** PLANNED (selective deployment based on target profile)
- **Value:** Professional credential verification, disciplinary history, license status
- **Intelligence:** Professional networks, disciplinary actions, complaints history, professional associations

### Import/Export & Customs Registers
- **Authority:** Tier 1 - Department of Home Affairs / Australian Border Force
- **Category:** Trade & border security
- **Source URLs:**
  - Tariff Classification `https://www.agriculture.gov.au`
  - Trade Statistics `https://www.absind.abs.gov.au`
  - Importer/Exporter codes (limited public data)
- **Coverage:** Import declarations, export licenses, goods classification, HS codes, declared goods
- **Data Points:** Importing/exporting company, goods description, origin/destination, volume
- **Status:** PLANNED (limited public data)
- **Value:** Business activity pattern, trading partners, supply chain intelligence
- **Intelligence:** Corporate trading relationships, commodity patterns, sanctions evasion detection

### Broadcasting & Media Licenses
- **Authority:** Tier 1 - ACMA (Australian Communications and Media Authority)
- **Category:** Media ownership & regulation
- **Source URL:** `https://www.acma.gov.au`
- **Coverage:** Radio/TV license holders, media company ownership, broadcast services, spectrum allocation
- **License Types:** Commercial radio, digital TV, community radio, apparatus licenses
- **Data:** License holder name, address, call sign, frequency/channel, service area
- **Status:** PLANNED
- **Value:** Media ownership structure, regulatory compliance, broadcast infrastructure
- **Intelligence:** Media influence networks, corporate media holdings, broadcast reach

### Intellectual Property & Patents
- **Authority:** Tier 1 - IP Australia primary source
- **Category:** Intellectual property
- **Source URL:** `https://www.ipaustralia.gov.au`
- **Registries:**
  - Patents `https://pericles.ipaustralia.gov.au` - invention registration
  - Trademarks `https://search.ipaustralia.gov.au` - brand/mark registration
  - Designs `https://www.ipaustralia.gov.au/get-the-right-ip/designs` - product design
  - Plant Breeder's Rights `https://www.ipaustralia.gov.au/plant-breeders-rights` - agricultural IP
- **Coverage:** Patent/trademark/design ownership, filing history, inventors, assignees, citations
- **Search By:** Applicant name, inventor, patent number, filing date range, technology class
- **Data Points:** Patent title, abstract, inventors, assignees, filing/grant dates, claims, citations
- **Status:** PLANNED
- **Value:** Innovation history, R&D capabilities, technology licensing, inventor networks
- **Intelligence:** Corporate innovation strategy, technology partnerships, IP ownership chains

### Aviation & Aircraft Registers
- **Authority:** Tier 1-2 - Civil Aviation Safety Authority (CASA)
- **Category:** Aerospace & aviation
- **Source URL:** `https://www.casa.gov.au`
- **Coverage:** Aircraft registration, owner/operator information, aircraft type, airworthiness status
- **Data:** Registration mark, aircraft type, owner/operator, serial number, airworthiness certificate
- **Status:** PLANNED
- **Value:** Asset identification, operator networks, aircraft movements
- **Intelligence:** Corporate aviation usage, aircraft ownership patterns, operator networks

### Marine & Shipping Registers
- **Authority:** Tier 1 - Department of Infrastructure
- **Category:** Maritime & shipping
- **Registries:**
  - Australian Shipping Register `https://www.infrastructure.gov.au`
  - State marine/vessel registers
  - Yacht/small vessel registers (state-based)
- **Coverage:** Vessel registration, owner/operator, vessel type, dimensions, AIS tracking
- **Data:** Vessel name, registration, IMO number, owner, flag state, vessel type
- **Status:** PLANNED (AIS data partially available)
- **Value:** Asset tracking, maritime business intelligence
- **Intelligence:** Shipping company networks, vessel operator patterns, cargo movements

### Environmental & EPA Registers
- **Authority:** Tier 2 - Environmental agencies
- **Category:** Environmental compliance
- **Registries by State:**
  - NSW: Environment Protection Authority `https://www.epa.nsw.gov.au`
  - VIC: Environmental Protection Authority Victoria `https://www.epa.vic.gov.au`
  - QLD: Department of Environment and Science `https://www.des.qld.gov.au`
  - Others: Per-state environmental regulators
- **Coverage:** Environmental licenses, pollution incidents, contaminated sites, compliance history
- **Data:** Licensed facility, pollutant type, compliance status, incident history
- **Status:** PLANNED
- **Value:** Corporate environmental compliance, pollution patterns, facility networks
- **Intelligence:** Industrial operations, environmental risk patterns, regulatory enforcement

### Consumer & Product Safety Registers
- **Authority:** Tier 2 - Product Safety Australia (formerly ACCC)
- **Category:** Product safety & recalls
- **Source URL:** `https://www.productsforsale.gov.au`
- **Coverage:** Product recall history, safety incidents, banned products, manufacturer information
- **Status:** PLANNED
- **Value:** Product/brand safety history, manufacturer networks
- **Intelligence:** Corporate product safety compliance, supply chain risks

### Financial Intelligence & Suspicious Matter Reports
- **Authority:** Tier 1 - AUSTRAC (Financial Intelligence Unit)
- **Category:** Financial crime intelligence
- **Coverage:** Suspicious transaction reports (limited access - government only)
- **Status:** NOT APPLICABLE (restricted to government agencies)
- **Note:** AUSTRAC sanctions list available (already deployed); STR data not public

### Workplace & Labor Registers
- **Authority:** Tier 2 - Fair Work Commission, SafeWork authorities
- **Category:** Employment & workplace compliance
- **Registries:**
  - Fair Work Commission `https://www.fwc.gov.au` - industrial relations
  - SafeWork NSW `https://www.safework.nsw.gov.au` - workplace safety
  - Per-state workplace safety regulators
- **Coverage:** Enterprise agreements, dispute resolution, workplace incidents, injury data
- **Status:** PLANNED
- **Value:** Employment patterns, workplace compliance history, labor dispute involvement
- **Intelligence:** Corporate employment practices, worker safety compliance, dispute patterns

### Tax Compliance & ASIC DOWNLOAD
- **Authority:** Tier 1-2 - ATO (Australian Taxation Office)
- **Category:** Tax compliance
- **Availability:** Limited public data (ABN register deployed, detailed tax history not public)
- **Status:** Partially deployed (ABN lookup available)
- **Note:** Tax return data not publicly available; ABN status indicates tax compliance

### University & Education Registers
- **Authority:** Tier 2 - TEQSA (Tertiary Education Quality and Standards Agency)
- **Category:** Education & credentials
- **Source:** `https://www.teqsa.gov.au`
- **Coverage:** Registered higher education providers, accreditation status
- **Status:** PLANNED (credential verification limited)
- **Value:** Education provider validation, institutional affiliations
- **Challenge:** Individual credential verification heavily restricted (privacy)

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
