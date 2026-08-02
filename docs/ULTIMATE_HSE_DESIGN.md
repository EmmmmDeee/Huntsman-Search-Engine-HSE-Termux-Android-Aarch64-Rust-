# The Ultimate HSE — Design & Capability Charter

> Status of this document. It is **partly a description of what HSE already is**
> and **partly a design for where it goes next**. Those two are kept explicitly
> separate throughout, per the Operational Constitution: claims about existing
> behaviour are marked **[implemented]**, verified additions from this cycle are
> marked **[implemented — this cycle, validated live]**, and forward work is
> marked **[proposed]**. Nothing here asserts a capability HSE does not have.
> The running software is the authority — cross-check with `hse --help`,
> `hse modules`, `hse selftest`, and `hse diagnostics`.

Huntsman Search Engine (`hse`) is an on-device, all-source OSINT / GEOINT /
NETINT reconnaissance engine in the SpiderFoot tradition — but without the
daemon, the Python runtime, the database server, or the desktop footprint. It is
pure Rust (edition 2024, MSRV 1.88), keyless-first, and forged to run entirely
inside **Termux on aarch64 Android with no root**, driven from a phone browser.

This charter explains why that design already makes HSE a more capable,
lower-friction alternative to SpiderFoot for the on-device operator, and lays out
the maximisation plan — with a deep focus on **GEOINT and people-centric
geolocation**.

---

## 1. HSE versus SpiderFoot — the design thesis

SpiderFoot is the reference bar for breadth: ~200 modules, a correlation layer,
and a web UI. HSE matches the shape and then changes the substrate to win where
it matters for an on-device operator:

| Axis | SpiderFoot | HSE | Why it matters |
|---|---|---|---|
| Runtime | Python + daemon + SQLite server | **Single static Rust binary** [implemented] | Deploys to Termux by copying one file; no interpreter, no service to keep alive |
| Footprint | Hundreds of MB of deps | Size-optimised binary, `opt-level=s` + LTO [implemented] | Fits a phone; survives a low-RAM device |
| TLS / native deps | OpenSSL / system libs | **rustls only, no C-linked deps** [implemented] | Cross-compiles clean for `aarch64-linux-android`; no NDK toolchain fights |
| Memory safety | — | `#![forbid(unsafe_code)]`, enforced in CI [implemented] | A hostile upstream can't turn a parse bug into memory corruption |
| Failure isolation | process-level | Per-module `catch_unwind` at the dispatch boundary [implemented] | One drifted upstream panicking can't take down `hse serve` |
| Determinism | varies | **No AI/ML/LLM/vector-DB compiled in**; every finding is deterministic Rust [implemented] | Findings reproduce byte-for-byte on Termux, Linux, and CI |
| Keys | many modules need keys | **~79% of modules need no key** [implemented] | Useful out of the box on a phone with zero configuration |
| Regional depth | generic | First-class **Australian public-records stack** (ABR/ASIC/AHPRA/ACMA/AEC/AustLII/Trove/cadastre) [implemented] | A whole intelligence surface SpiderFoot doesn't model |
| On-device sensing | none | **Termux sensor fusion** — GPS, Wi-Fi, cell, ARP — no root [implemented] | The phone itself becomes a GEOINT sensor |

The thesis: **breadth parity, plus a substrate (Rust + keyless + Termux + local
sensors) that SpiderFoot structurally cannot reach.** "More aggressive" here means
_more thorough passive collection from public sources_ — not intrusion. HSE is
defensive-only by charter (`SECURITY.md`): asset discovery, exposure assessment,
threat modelling, detection, remediation.

---

## 2. Architecture in one pass

```
                 seed (email│domain│ip│username│name│phone│coord│…)
                        │
                        ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Engine  (src/core/engine)                                     │
   │   • typed Target → dispatch index (consumes/produces graph)    │
   │   • bounded concurrency (2 workers, tuned for Termux)          │
   │   • per-module timeout + Termux cap + circuit breaker          │
   │   • per-module catch_unwind isolation                          │
   │   • expansion rounds: new entities re-injected as seeds        │
   └──────────────────────────────────────────────────────────────┘
        │                    │                      │
        ▼                    ▼                      ▼
   Module trait        Entity model            Correlator
   (src/core/module)   (GREATEST merge,        (src/core/correlator)
   ~170 collectors     SHA-256 UIDs,           identity / breach /
   1-file to add       confidence ladder)      location / org rules
        │                    │                      │
        └────────────┬───────┴──────────────────────┘
                     ▼
          Storage (SQLite, bundled)   ──►   Web UI (axum + SPA, 127.0.0.1)
          Dossier / GEXF / export            live SSE scan stream
```

Load-bearing invariants (asserted in `src/lib.rs` and `tests/architecture.rs` —
a change that trips them is a design decision, not a bug to silence):

- `#![forbid(unsafe_code)]`; no native-TLS / C-linked deps.
- GREATEST-semantics entity merge; SHA-256 deterministic entity UIDs.
- Runtime AI-independence (no ML/LLM/embedding/vector-DB compiled in).
- Every registered module declares a description, a category, and at least one
  valid **MITRE ATT&CK Reconnaissance** technique — so every scan produces an
  ATT&CK coverage report, and a new module can't silently contribute nothing.
- Adding a module is a **one-file change**: implement `Module`, `pub mod` it,
  push one `Arc::new(..)` into the registry.

---

## 3. The collection surface

Over 160 registered collector modules (authoritative list: `hse modules`),
grouped by `ModuleCategory`:

`DnsRecon · Breach · Infrastructure · Search · Geo · Social · Email · Phone ·
Corporate · Threat · Sensor · People · Web`

Coverage of the public-OSINT provider landscape is catalogued in
`docs/OSINT_API_REFERENCE.md` (14 categories, ~150 providers, with per-provider
free-tier / key-shape / integration status). The design rule for *which* sources
to add is explicit and unchanged:

1. **Keyless and free first.** A module that needs no key is worth more on a
   phone than a keyed one, because it works for every operator immediately.
2. **Multiple independent corpora per question.** Where one free source can go
   dark or miss, run a second and third against the same question (the
   `beacondb` + `mylnikov` BSSID precedent; the `geocode` + `photon` geocoder
   precedent). Corroboration is a first-class design goal, not duplication.
3. **Verifiable + permissible only.** A source is wired in only after its
   response is checked against a real query and its access terms are keyless /
   free-tier appropriate. Sources that 403 through a proxy, require gray-area
   scraping, or can't be validated are rejected (the `dogechain.info` rejection
   in `chain_intel` is the standing example).
4. **Honesty over completeness.** An evidence field is emitted only when the
   source actually returns it. Sampled/limited results are labelled as samples,
   never as exhaustive.

---

## 4. GEOINT & people-centric geolocation — the deep focus

Placing a **person** in the physical world is HSE's highest-value synthesis, and
the stack is already deep. This section maps it, then defines how to potentiate it
to the maximum.

### 4.1 The geolocation signal graph [implemented]

Every path below already exists and feeds one shared coordinate/address model
that the location correlator (`src/core/correlator/rules/location`) fuses:

```
 PERSON / IDENTITY                         PHYSICAL SIGNAL              MODULE
 ─────────────────                         ───────────────             ──────
 email ─┬─► gravatar profile "location" ──► Address ──┐               gravatar
        └─► header Received: geo ─────────► coarse geo │              email_header_geo
 username ─► social profile "location" ───► Address ───┤              social_location
            (github, reddit, gitlab, …)                │              github_user, …
 photo ────► EXIF GPS tags ───────────────► Coordinates│              exif_geo
 phone ────► E.164 prefix / area code ────► region ────┤              phone_geo, geo_intel
 ip ───────► geo (5+ providers) ──────────► Coordinates ┤             ip_geo, ipinfo, ip2location,
            ASN / netblock / whois-geo                 │              ipquery, ip_whois_geo, geo_intel
 breach ───► leaked address / timezone ───► Address ───┤             breach_timezone, see_know, dehashed
 device ───► GPS / Wi-Fi / cell / ARP ────► Coordinates│             device_sensors, signal_radar,
            (Termux, no root)                          │              wifi_intel, cell_intel
 SSID/BSSID► WiGLE / beacondb / mylnikov ─► Coordinates┤             wigle, beacondb, mylnikov, opencellid
 address ──► forward geocode ─────────────► Coordinates┤             geocode, photon, open_meteo_geo*
 coord ────► reverse geocode ─────────────► Address ───┤             geocode, photon
 coord ────► nearby places / infra ───────► context ───┘             wiki_geosearch, wikidata_geo, overpass
                                                        │
                                                        ▼
                              LOCATION CORRELATOR — cluster, weight by
                              region + accuracy + corroboration, suppress
                              hosting/registrant/CDN geo, rank a verdict
```

`*` = potentiated this cycle (see §5).

### 4.2 What makes it "people-centric"

Two rules keep the output about the **subject**, not their infrastructure —
already implemented and load-bearing:

- **Infrastructure suppression.** Coordinates that geolocate a hosting IP, a CDN
  edge, or a WHOIS-privacy registrant are tagged `hosting` / `platform-infra` /
  `registrant` and kept out of the person's physical footprint by the geo rules.
- **Regional weighting.** A fix inside the operator's area of interest (the AU
  bounding box, offline) is a strong anchor; one abroad is demoted to a
  `candidate` below the expansion floor — retained as a lead without polluting
  the verdict. This is a policy knob, not a hard limit (see §7 roadmap).

### 4.3 Potentiation plan — GEOINT to the maximum

**[implemented — this cycle]**
- **Third independent forward geocoder** (`open_meteo_geo`, §5.2): resolves the
  coarse, city-level place-names people self-report ("Golden, CO") and adds
  **timezone, population, place-class, elevation** — signals the two existing
  geocoders don't return. Timezone in particular corroborates `breach_timezone`,
  closing a loop between a leaked timezone and a self-reported city.

**[proposed — prioritised]**
1. **Geolocation fusion verdict as a first-class artifact.** The location
   correlator already clusters; surface a single ranked *"most-probable location"*
   with a confidence and the corroborating-source count, rendered on the web UI
   map view. Turns N scattered coordinates into one defensible answer.
2. **Plus Code (Open Location Code) enrichment, fully offline.** A deterministic
   coordinate↔code transform (pure Rust, no dep, no network) stamps every
   coordinate with a standard, shareable grid reference — Termux-perfect.
3. **Timezone → longitude-band inference as a coordinate-free prior.** Generalise
   `breach_timezone` so any observed IANA timezone (from `open_meteo_geo`, social
   profiles, or device) contributes a soft longitude/region prior to the fusion.
4. **More self-reported-location sources.** Extend `social_location`'s per-platform
   extractors (Launchpad, SourceForge, CPAN, and additional social APIs that
   expose a location field) so no fetched profile drops a location it revealed.
5. **Nearby-context expansion.** Complement `overpass`/`wiki_geosearch` with
   keyless POI density and admin-boundary lookups to sharpen "what is at this
   point" for a raw fix.

Each proposed item obeys §3's rules: keyless-first, corroborating, verifiable,
honest.

---

## 5. Supercharge increment — this cycle (validated live)

Two keyless, live-validated modules were added this cycle. Both follow the
established pattern: a **pure** response→entity mapper (unit-tested without the
network) behind a thin transport method; full trait metadata; registered; ATT&CK
mapped. Live-validation evidence is recorded in
`docs/API_VALIDATION_EVIDENCE.md`.

### 5.1 `mnemonic_pdns` — keyless historical passive DNS [implemented — validated live]

Mnemonic's public Passive DNS v3 API (`api.mnemonic.no/pdns/v3/`) is a keyless,
TLP:WHITE corpus of *observed* DNS answers. It answers what the live resolvers
(`dns_intel`, `doh_resolver`) structurally cannot:

- **Domain → historical IPs** — every A/AAAA a domain ever resolved to, not just
  the record live now, so infrastructure a target has rotated away from is still
  a lead.
- **IP → historical domains (reverse passive DNS)** — the co-hosting / shared-
  infrastructure pivot a single live PTR lookup misses.
- **CNAME / MX / NS graph** around a domain — related third-party infrastructure,
  scoped `subdomain` vs `external`.

Every edge is historical, so entities are emitted at `HIGH` (a reliable source,
not a live confirmation) and carry first/last-seen dates + observation count as
evidence, so recency is weighed downstream rather than assumed.

### 5.2 `open_meteo_geo` — keyless geocoder + GEOINT enrichment [implemented — validated live]

Open-Meteo's GeoNames-backed geocoding API
(`geocoding-api.open-meteo.com/v1/search`) is the third keyless forward geocoder,
alongside `geocode` (Nominatim) and `photon` (Komoot). It is *additive*, not
redundant: it returns **timezone, population, GeoNames feature-code/class,
elevation, and postcodes** the others don't, and excels at the coarse city-level
place-names people self-report on profiles — the exact `Address` entities
`social_location` / `gravatar` / developer-profile modules emit. Regional
weighting mirrors `geocode` (AU anchor `HIGH_PLUS`; abroad → `candidate`).

---

## 6. Termux / no-root / web-UI operability [implemented]

- **One binary, no service.** `hse serve` binds an axum HTTP server + a
  hand-rolled SPA to `127.0.0.1:8080` — localhost only, no LAN exposure — driven
  from Chrome/Firefox on the device. Live scans stream over SSE; the vendor
  bundle is served gzip-compressed to stay cheap on a mobile link.
- **Tuned for the phone.** 2 worker threads, a bounded blocking pool
  (`MAX_BLOCKING_THREADS`), a per-module Termux timeout cap that reclaims the dead
  tail of hung mobile requests, and body caps that stop a hostile upstream from
  OOMing a low-RAM device.
- **The phone as a sensor.** `device_sensors` / `signal_radar` fuse GPS, Wi-Fi,
  cell, and ARP via Termux APIs — no root — turning the handset itself into a
  GEOINT collector.
- **Fast on-device build profile** (`[profile.fast]`) cuts an on-phone build to
  ~4–6 min versus the full LTO release.

---

## 7. Roadmap beyond geo — prioritised, keyless-first

**[proposed]**, ordered by value-to-effort, all obeying §3:

1. **EPSS exploit-probability enrichment (correlation layer).** FIRST.org's EPSS
   API (`api.first.org/data/v1/epss`, keyless — validated reachable this cycle)
   scores the exploitation probability of a CVE. The `shodan` module already
   attaches CVE IDs to IP entities; an enrichment pass would annotate those CVEs
   with EPSS scores, turning an exposure list into a *prioritised* one. (Modelled
   as a correlator enrichment because there is no `Cve` `TargetKind` — a clean fit
   the module dispatch model cannot express today.)
2. **More keyless passive-DNS / CT corroboration** to sit beside `mnemonic_pdns`
   and `crtsh`, per the multi-corpus rule.
3. **Geolocation fusion verdict + map view** (§4.3 item 1).
4. **Offline Plus Code enrichment** (§4.3 item 2).
5. **Live-drift coverage** for every new upstream — the `#[ignore]`d
   `tests/live_drift.rs` suite is where a contract change in a wired API is
   caught before it reaches an operator.

---

## 8. Proof discipline

Per the Operational Constitution and `docs/PERSISTENT_INTELLIGENCE.md`:

- Every new module ships **pure, deterministic mappers** with unit tests built
  from **real captured responses**, so behaviour reproduces without the network.
- Every new upstream is **validated live** before wiring, and the evidence —
  the actual observed responses and status codes — is recorded in
  `docs/API_VALIDATION_EVIDENCE.md`. Where a candidate source failed validation
  (proxy 403, unreliable 5xx, gray terms), that outcome is recorded too, not
  hidden.
- CI (`.github/workflows/ci.yml`) gates every change on
  `cargo fmt --check`, `cargo clippy --all-targets --locked -D warnings`, and
  `cargo test --all --locked`, plus the architecture and smoke invariants above.

The measure of "ultimate" is not a module count — it is that every capability is
**keyless where it can be, corroborated where it matters, deterministic always,
and honest about what it does and doesn't know.**
