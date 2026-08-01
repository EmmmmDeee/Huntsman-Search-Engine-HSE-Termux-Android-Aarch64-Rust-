# OSINT API Reference (HSE)

An extensive, categorised reference of OSINT-relevant APIs for the Huntsman
Search Engine: what each provider gives you, whether it has a free tier, its
API-key shape (for detection in stealer logs), and HSE's integration/detection
status.

Use it to (a) see what HSE already covers, (b) decide which BYO-key providers to
light up, and (c) compare your own keys against what HSE will recognise.

## Legend — HSE status

| Mark | Meaning |
|---|---|
| **M** | Dedicated HSE collector module (queries the provider) |
| **K** | Key-gated — recognised `HUNTSMAN_*` env var / BYO key |
| **D** | Key **detected & banked** when found in a victim/stealer log (in the OSINT catalogue) |
| **C** | Candidate — relevant, not yet integrated |
| free | usable free tier · ltd | limited free · key | paid/keyed only |

> **Caveats.** Free tiers and pricing change constantly — *verify before relying
> on them*. Key shapes are detection aids, not guarantees: many providers mint
> bare hex/alphanumeric/UUID tokens with no distinctive prefix (HSE attributes
> those by the provider domain/identifier context, not shape alone). "32 alnum"
> = 32 alphanumeric chars, "40 hex" = 40 hex chars, etc.

---

## 1. Breach / leak / credential exposure

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **Have I Been Pwned (HIBP)** | breach + paste exposure for an email/domain | PwnedPasswords free; breach API paid | 32 hex | M K D |
| **Pwned Passwords** | k-anonymity password-hash exposure | free | — (no key) | M D |
| **Dehashed** | breached credentials (email/user/pass/IP/name) | search free, results paid | email + 32-alnum (basic auth) | M K D |
| **Intelligence X (IntelX)** | leaks, darknet, paste, WHOIS history | 50 searches/day | UUID | M K D |
| **Snusbase** | breach + stealer credential search | paid | login-gated | D |
| **LeakCheck** | breach lookups by email/user/domain | free public API + Pro | 40+ alnum | D |
| **LeakPeek** | breach credential search | ltd | — | D |
| **Leak-Lookup** | breach database search | key | 32 alnum | D |
| **BreachDirectory** | breached account/credential search | ltd (RapidAPI) | RapidAPI key | K D |
| **Hudson Rock (Cavalier)** | **stealer-log / infostealer** infections by email/domain | free email/domain endpoints | — | M D |
| **XposedOrNot** | breach exposure (free HIBP-style) | free | — | M D |
| **Scattered Secrets** | breach + credential monitoring | paid | — | D |
| **ProxyNova** | leaked combo/credential search | free (web) | — | D |
| **Hashes.com** | hash cracking + leak search | ltd | — | D |
| **PSBDMP** | pastebin dump search | free/key | — | M D |
| **GhostProject / Scylla / WeLeakInfo / HackCheck / Scrubd / NuclearLeaks** | breach/credential search (varied availability) | varies | — | D |
| **OathNet** | unified breach + stealer (HSE multiplier) | keyed plan | login-gated | M K D |
| **SeekNow (see-know.eu)** | unified breach + stealer + external (HSE multiplier) | keyed plan | login-gated | M K D |
| **NiamonX** | concurrent PBS v1/v2 breach search + ULP infostealer lookup | keyed | opaque | M K D |
| **OsintCat** | email footprint (100+ platforms), breach lookup, deep email OSINT | free preflight; paid deep search | `x-api-key` | M K D |
| **IntelTechniques** | OSINT tooling / search tools | — | — | D |

## 2. Attack-surface / internet-wide host scanners

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **Shodan** | host/port/banner/CVE, IoT, internet scan | ltd ($) | 32 alnum | M K D |
| **Censys** | hosts, certs, services | basic free | API ID (UUID) + secret (32 alnum) / PAT | M K D |
| **ZoomEye** | host/web fingerprint scan | ltd | 32 alnum / JWT | M K D |
| **BinaryEdge** | host/port/exposure scan | ltd | UUID | K D |
| **FOFA** | cyberspace asset search | ltd | email + 32-hex key | K D |
| **Netlas** | attack-surface / host & cert search | ltd | alnum | M K D |
| **Onyphe** | cyber-defense / exposure data | ltd | UUID/alnum | M K D |
| **FullHunt** | attack-surface management | ltd | alnum | K D |
| **Criminal IP** | host/IP/domain attack-surface + risk | ltd | alnum | M K D |
| **LeakIX** | indexed open services + leaks | free/key | base64url ~40 | M K D |
| **Spyse** *(defunct→merged)* | host/cert/domain (legacy) | — | — | D |
| **Quake (360)** | asset search (CN) | ltd | — | D |
| **Hunter.how** | exposure search engine | ltd | — | D |
| **ODIN** | internet scan / asset | ltd | — | D |

## 3. Threat intelligence / reputation

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **VirusTotal** | file/URL/domain/IP reputation | free (4/min) | 64 hex | M K D |
| **AbuseIPDB** | IP abuse reports/score | free (1k/day) | 80 alnum | M K D |
| **GreyNoise** | internet-scan noise / RIOT benign | community free | UUID / 32 alnum | M K D |
| **Pulsedive** | indicator/threat enrichment | free | alnum | K D |
| **ThreatFox (abuse.ch)** | IOCs (malware, C2) | free | abuse.ch key | M K D |
| **URLhaus (abuse.ch)** | malicious URL feed | free | — | M D |
| **MalwareBazaar (abuse.ch)** | malware-sample intel | free | abuse.ch key | D |
| **urlscan.io** | URL scan + screenshots + DOM | free | UUID | M K D |
| **AlienVault OTX** | open threat exchange pulses | free (keyless) | 64 hex | M K D |
| **Hybrid Analysis** | sandbox malware reports | free (vetted) | 64 alnum | D C |
| **ANY.RUN** | interactive sandbox | ltd | — | D C |
| **Maltiverse** | IOC intelligence | free/key | JWT/alnum | D C |
| **IBM X-Force Exchange** | threat intel | ltd | key + password | D C |
| **PolySwarm** | malware intel marketplace | ltd | 32 hex | D C |
| **ThreatMiner** | passive threat intel | free | — (no key) | D C |
| **PassiveTotal (RiskIQ)** | passive DNS, WHOIS, infra intel | ltd | email + key | K D |

## 4. Email / identity / people search

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **Hunter.io** | email finder/verifier, domain emails | 50/mo | 40 hex | M K D |
| **EmailRep** | email reputation/profile | free (ltd) | alnum | M K D |
| **Epieos** | email→linked accounts (Google, etc.) | ltd | alnum | M K D |
| **FullContact** | person/company enrichment | ltd | 32 alnum | M K D |
| **Proxycurl** | LinkedIn person/company data | paid | alnum | M K D |
| **Seon** | fraud/digital-footprint enrichment | trial | alnum | M K D |
| **OpenSanctions** | sanctions/PEP/watchlist screening (incl. Australia's DFAT list) | free trial/nonprofit | alnum | M K D |
| **OFAC (US Treasury)** | SDN + Consolidated sanctions-list screening | free | — (no key) | M D |
| **Snov.io** | email finder/verify, drip | ltd | client id+secret | D C |
| **Apollo.io** | B2B people/company | free (ltd) | alnum | D C |
| **RocketReach** | contact lookup | ltd | alnum | D C |
| **Pipl** | identity resolution (enterprise) | no | — | D C |
| **People Data Labs** | person/company enrichment | free (1k) | alnum | D C |
| **Clearbit** *(→HubSpot)* | enrichment (legacy) | — | `sk_` | D C |
| **Tomba** | email finder/verify | ltd | `ta_`/`ts_` | D C |
| **Anymail Finder / Voila Norbert / Dropcontact** | email finding/verify | ltd | alnum | D C |
| **Predicta Search / OSINT.Industries / Castrick** | email/username→accounts OSINT | paid | — | D C |
| **Skymem** | company email directory | free | — | D C |

## 5. Phone intelligence

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **Numverify** | number validation + carrier/line/geo | 100/mo | 32 hex | M K D |
| **NumLookup** | number validation/carrier | free/key | alnum | D C |
| **Veriphone** | number validation | free (ltd) | alnum | D C |
| **IPQualityScore (IPQS)** | phone + fraud + IP + email risk | ltd | 32 alnum | M K D |
| **HLR Lookups / OpenCNAM** | live HLR / caller-name | paid | key + secret | M K D |
| **AbstractAPI (phone)** | number validation | ltd | 32 hex | D C |
| *(offline)* **phone_au / phone_geo / phone_intl** | AU line-type/region, area-code geo, E.164 country | free | — | M |

## 6. IP geolocation / ASN / network

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **IPinfo** | IP geo/ASN/company/privacy | 50k/mo | hex token | M K D |
| **IP2Location** | IP geo (API + DB) | free (1k/day, keyless) | — | M D |
| **ipgeolocation.io** | IP geo/timezone/astronomy | 1k/day | alnum | D C |
| **ipstack** | IP geo | 100/mo | 32 hex | D C |
| **ipdata** | IP geo + threat | 1.5k/day | alnum | D C |
| **ipregistry** | IP geo + threat | ltd | `ira_`/alnum | M(ip_registry) D |
| **MaxMind GeoIP2** | IP geo (API + GeoLite2 free DB) | GeoLite free | account id + license | D C |
| **ipquery / ipapi / ip-api** | IP geo (keyless tiers) | free | — / key | M(ipquery) D |
| *(keyless infra)* **bgpview / ripestat / hackertarget / ip_whois_geo** | ASN/prefix/WHOIS-geo, no key | free | — | M |

## 7. Domain / WHOIS / DNS / certificate

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **SecurityTrails** | DNS/WHOIS history, subdomains | 50/mo | 32 alnum | M K D |
| **WhoisXML API** | WHOIS, DNS, subdomains, reverse | 500/mo | `at_`+alnum | M K D |
| **crt.sh** | certificate-transparency search | free | — | M |
| **Certspotter / cert_intel** | cert transparency monitor | free/key | — | M |
| **BuiltWith** | website tech profiling | ltd | alnum | K D |
| **C99.nl** | multi-tool (subdomain, etc.) | key | alnum | K D |
| **Whoxy** | WHOIS + reverse WHOIS history | ltd | alnum | D C |
| **DomainTools** | Iris WHOIS/DNS/infra | paid | api user + key | D C |
| **ViewDNS.info** | DNS/WHOIS/reverse tools | ltd | alnum | D C |
| **DNSDumpster / domainsdb** | subdomain/passive DNS | free / key-gated (domainsdb, 2026: anonymous access disabled) | domainsdb: alnum | M(domainsdb) K D |
| **IP2WHOIS** | WHOIS lookup | free (500/mo) | alnum | D C |
| *(keyless)* **dns_intel / doh_resolver / dns_axfr / rdap_domain / whois** | DNS records, DoH, AXFR, RDAP, WHOIS | free | — | M |

## 8. Search / SERP / scraping (recon)

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **Exa (metaphor)** | neural/semantic web search API | ltd | UUID/alnum | M K D |
| **SerpAPI** | Google/Bing/… SERP scraping | 100/mo | 64 hex | D C |
| **Serper.dev** | Google SERP API | 2.5k free | 40 hex | D C |
| **ZenSerp** | SERP API | ltd | alnum | D C |
| **Brave Search API** | independent web index | 2k/mo free | `BSA…` | D C |
| **Google Programmable Search (CSE)** | custom Google search | 100/day | `AIza…` + cx | D C |
| **Bing Web Search** *(retiring)* | Bing SERP | ltd | 32 hex | D C |
| **DataForSEO** | SERP/SEO data | paid | login+password | D C |
| **ScraperAPI / ScrapingBee** | proxy scraping | ltd | alnum | D C |
| *(keyless)* **search_engines** | multi-engine result scraping | free | — | M |

## 9. Social / username / profile

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| *(keyless)* **username_search / username_variants** | 150+ platform username checks | free | — | M |
| *(keyless)* **social_probe / social_location / profile_kit** | profile presence, geo, dossier | free | — | M |
| **GitHub / GitLab / Bitbucket / Gitea / Codeberg** | user/commit/code search | free + token | `ghp_`/`glpat-`/… | M K D |
| **Reddit / Mastodon / Bluesky / Nostr / Fediverse** | social profile/post data | free/token | varies | M |
| **Steam / gaming_profile / chess_profile / streaming_probe** | gaming & streaming identity | free/key | Steam key 32-hex | M |
| **Keybase / Gravatar / WikiData / Hacker News / Lobsters** | identity/avatar/knowledge | free | — | M |
| **Social Links / Maltego / Lampyre / SpiderFoot HX** | commercial link-analysis platforms | paid | — | D C |
| **Discord (snowflake) / discord token** | ID→timestamp; token detection | free | `discord` token | M D |

## 10. Corporate / business registry

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **OpenCorporates** | global company registry | ltd | alnum | M K D |
| **GLEIF (LEI)** | legal-entity identifiers | free | — | M |
| **ABN Lookup (ABR)** 🇦🇺 | Australian Business Register | free | GUID | M K |
| **ASIC** 🇦🇺 | company/officeholder/banned (via data.gov.au) | free | — | M |
| **ACNC** 🇦🇺 | charities register | free | — | M |
| *(see §13 for the full AU registry stack)* | | | | |

## 11. Wireless / cell / wifi geolocation

| Provider | What it gives | Free tier | Key shape | HSE |
|---|---|---|---|---|
| **WiGLE** | wifi/BT/cell wardriving DB | free (ltd) | API name + token | M K D |
| **OpenCellID** | cell-tower geolocation | free key | alnum | M K D |
| **Unwired Labs / Mylnikov** | cell/wifi geolocation | ltd/free | alnum | M(mylnikov) D |
| **Google/Combain geolocation** | wifi/cell→position | paid | `AIza…`/key | C |
| *(keyless)* **mls / cell_intel / wifi_intel** | offline cell/wifi context | free | — | M |

## 12. Code / repository / package registries (keyless)

| Provider | What it gives | HSE |
|---|---|---|
| **GitHub code search** | secrets/identity in code | M (K for rate) |
| **npm / PyPI / RubyGems / crates.io / Hex / CPAN / DockerHub / SourceForge / Launchpad** | package-author identity, email leaks | M |
| **dev.to / Stack Overflow / Codewars / HuggingFace** | developer profile/identity | M |

## 13. Australian-specific registries (HSE focus, mostly keyless) 🇦🇺

| Provider | What it gives | HSE |
|---|---|---|
| **ABR / ABN Lookup** | business number → entity, ACN | M |
| **ASIC** (persons, directors, business names, banned orgs) | company & officeholder records | M |
| **AHPRA** | registered health practitioners | M |
| **ACMA RRL** | radio/spectrum licences | M |
| **AEC / au_electoral** | electoral roll signals | M |
| **au_property / qld_cadastre / au_unclaimed** | property, cadastre, unclaimed money | M |
| **au_geo** | ABS statistical geography (postcode, suburb, LGA, electorates) | M |
| **AustLII** | case law / tribunal records | M |
| **Trove** | National Library archive | M K |
| *(offline)* **postcode_au / address_au / phone_au** | postcode→coord, address/state parse, line-type | M |

## 14. Other enrichment / utility

| Provider | What it gives | Free tier | HSE |
|---|---|---|---|
| **Gravatar** | email→avatar/profile | free | M |
| **EmailRep / disposable_check / email_locale / email_header_geo** | email reputation, disposable, locale, header geo | free | M |
| **Sunrise-Sunset / Overpass (OSM) / Photon / Geocode / Nominatim** | solar position, map features, geocoding | free | M |
| **EXIF geo** | image metadata → coordinates | free (offline) | M |
| **Wayback Machine / archive.org** | historical snapshots | free | M |
| **Blockchain OSINT** — Etherscan, BscScan, Blockchair, Bitquery, Chainalysis | wallet/tx intelligence | ltd/key | C |

---

## Lighting up BYO keys

HSE reads keys from `HUNTSMAN_*` env vars (or the UI Settings panel). Recognised
keyed providers include:

`OATHNET, NIAMONX, SEEKNOW, HIBP, DEHASHED, INTELX, HUNTER, EMAILREP, EPIEOS,
FULLCONTACT, PROXYCURL, SEON, OPENSANCTIONS, OSINTCAT, SHODAN, CENSYS (ID+SECRET),
ZOOMEYE, BINARYEDGE, FOFA, NETLAS, ONYPHE, FULLHUNT, CRIMINALIP, LEAKIX, GREYNOISE,
VIRUSTOTAL, ABUSEIPDB, ABUSECH, THREATFOX, ALIENVAULT, URLSCAN, PULSEDIVE,
PASSIVETOTAL, SECTRAILS, WHOISXML, DOMAINSDB, BUILTWITH, C99, BREACHDIR, NUMVERIFY,
HLR, OPENCNAM, IPQS, OPENCELLID, WIGLE (USER+TOKEN), OPENCORP, TROVE, EXA, ABR_GUID`.

Most are optional — ~79% of HSE modules need **no** key. Add a key only to escalate
a specific source; HSE never marks up provider pricing (pay the provider directly,
usually on a free tier).

## Keeping this list accurate

If a provider is missing, mis-categorised, or you know its key format, tell the
maintainer — three places make detection accurate:
`util/osint_providers` (category), `key_harvest/service_domains.rs` (domain
routing), and `key_harvest/osint_keys.rs` (prefix-less key shapes).
