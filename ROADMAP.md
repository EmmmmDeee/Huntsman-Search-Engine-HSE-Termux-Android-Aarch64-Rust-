# Huntsman Search Engine — Development Roadmap

This roadmap reflects the deliberate, phased expansion of HSE beyond its
current 113-module baseline. Items are ordered by strategic value: data
density first, then coverage breadth, then workflow polish.

---

## Phase 1 — Australian Geolocation Corpus Acquisition (Highest Priority)

The goal is an **on-device, offline-capable corpus** of every Australian Wi-Fi
access point and cell tower in WiGLE and OpenCelliD, so that `Coordinates`,
`MacAddress`, and `DeviceId` lookups are fully air-gapped. This eliminates
the per-scan API quota constraint entirely and makes HSE viable in the field
without network access.

### 1A — WiGLE Australia Full Extract

WiGLE holds the world's largest crowd-sourced RF survey. The Australian subset
(bounding box: lat −10 to −44, lon 113 to 154) currently has several million
Wi-Fi networks, hundreds of thousands of Bluetooth devices, and a large LTE/NR
cell corpus. A one-time full pull, stored in a local SQLite table, turns every
BSSID lookup from a rate-limited API call into a sub-millisecond indexed read.

**Approach:**

1. **New command: `hse wigle-harvest`** — a resumable bulk downloader that
   tiles the Australian bounding box into a grid of 0.1° × 0.1° cells (≈ 3 100
   tiles for the populated regions). Each tile queries
   `GET /api/v2/network/search?latrange1=…&longrange1=…&resultsPerPage=1000`
   with paged continuation (`searchAfter` cursor). Tiles that return fewer than
   1 000 results are complete; tiles at capacity are subdivided and re-queued
   (adaptive tiling). Progress is checkpointed into the DB so an interrupted
   harvest resumes from the last completed tile rather than restarting.

2. **Schema extension:** new table `wigle_au` in `huntsman.db`:
   ```sql
   CREATE TABLE wigle_au (
       netid      TEXT PRIMARY KEY,   -- BSSID or cell identifier
       kind       TEXT NOT NULL,       -- 'wifi' | 'cell' | 'bluetooth'
       ssid       TEXT,
       lat        REAL NOT NULL,
       lon        REAL NOT NULL,
       accuracy   INTEGER,             -- WiGLE trilat accuracy (metres)
       last_seen  TEXT,                -- ISO-8601
       channel    INTEGER,
       encryption TEXT,
       country    TEXT DEFAULT 'AU',
       updated_at TEXT NOT NULL
   );
   CREATE INDEX wigle_au_geo  ON wigle_au (lat, lon);
   CREATE INDEX wigle_au_ssid ON wigle_au (ssid);
   ```

3. **Module integration:** `wigle/mod.rs` checks the local table before the
   remote API. Cache hit returns instantly at confidence `0.90`; cache miss
   falls through to the live API as today. The existing `QuotaBudget` caps
   only apply to live calls — local reads are unlimited.

4. **Refresh strategy:** WiGLE data ages. A background `--refresh-stale` flag
   re-queries tiles whose `updated_at` is older than 90 days, only for regions
   that have changed since the last pull (WiGLE's `lastupload` field in the
   tile metadata can gate this).

5. **Rate-limiting compliance:** WiGLE's free tier allows roughly 100 API
   queries per day. The harvester enforces a configurable `--rate` (default
   1 req/s) with exponential back-off on 429 responses, and persists the
   per-day counter in the DB so the limit is respected across restarts.

**Estimated corpus size:** 2–5 million rows at ~200 bytes each ≈ 400 MB–1 GB.
Store in `ATTACH`-able sidecar DB (`wigle_au.db`) to keep `huntsman.db` lean.

---

### 1B — OpenCelliD Australia Full Extract

OpenCelliD is the world's largest open cell tower database. The Australian
export (`mcc=505`) has approximately 500 000–800 000 tower records covering
GSM/UMTS/LTE/NR across all carriers. A local copy converts `cell_intel`'s
OpenCelliD API call from online-required to always-available.

**Approach:**

1. **New command: `hse opencellid-harvest`** — downloads the AU-filtered export
   from the OpenCelliD bulk API (`GET /downloads/cell_towers.csv.gz?token=…&mcc=505`),
   decompresses on the fly, and bulk-inserts into a local table. The full AU
   extract is ≈ 50 MB compressed; import takes < 30 seconds on-device.

2. **Schema extension:** new table `opencellid_au`:
   ```sql
   CREATE TABLE opencellid_au (
       radio      TEXT NOT NULL,       -- 'GSM' | 'UMTS' | 'LTE' | 'NR'
       mcc        INTEGER NOT NULL,    -- 505 for Australia
       mnc        INTEGER NOT NULL,
       lac        INTEGER NOT NULL,    -- or TAC for LTE
       cid        INTEGER NOT NULL,
       lat        REAL NOT NULL,
       lon        REAL NOT NULL,
       range_m    INTEGER,             -- accuracy estimate
       samples    INTEGER,             -- number of contributing measurements
       changeable INTEGER,             -- 1 = not an official source
       created    INTEGER,             -- Unix timestamp
       updated    INTEGER,
       avg_signal INTEGER,
       PRIMARY KEY (radio, mcc, mnc, lac, cid)
   );
   CREATE INDEX opencellid_au_geo ON opencellid_au (lat, lon);
   ```

3. **Module integration:** `cell_intel/helpers.rs::query_opencellid` checks the
   local table first (keyed on `radio, mcc, mnc, lac, cid`). Cache hit skips
   the HTTP call entirely; the confidence is scaled by `samples` (more
   observations → higher weight, floor `0.65`, cap `0.90`).

4. **Refresh strategy:** OpenCelliD publishes a full monthly dump and a delta
   feed. The harvester records the download timestamp and exposes
   `hse opencellid-harvest --update` to pull the delta since the last full
   download.

5. **Key requirement:** OpenCelliD bulk download requires an API key
   (`HUNTSMAN_OPENCELLID_KEY`). The existing key slot is reused. Without a key
   the command errors with a clear message pointing to
   `https://opencellid.org/register.php` (free registration).

**Estimated corpus size:** 800 000 rows at ~100 bytes each ≈ 80 MB. Light
enough to embed in `huntsman.db` directly.

---

### 1C — WiGLE Corpus Enrichment (Deferred — runs after 1A is complete)

The raw `wigle_au` table built by `hse wigle-harvest` is already a high-value
corpus, but every row can be enriched cross-referencing data already collected
by other HSE modules. This phase runs autonomously on the local DB — no
additional API quota required beyond what Phase 1A already spent.

**Enrichment actions (all scheduled as a background `hse wigle-enrich` command):**

1. **MAC OUI resolution.** The `netid` (BSSID) of every Wi-Fi record encodes a
   vendor OUI in the first 3 octets. Cross-reference the local IEEE OUI table
   (already used by `mac_lookup`) to populate a `vendor` column without any API
   call. This turns a raw BSSID into a router make/model hint (e.g.,
   `DC:A6:32` → Raspberry Pi Trading Ltd).

2. **Postcode ↔ suburb normalisation.** `postalcode` from WiGLE's reverse-geocode
   is often a raw postcode string. Cross-reference `src/util/postcode_au` to
   attach the official suburb name, SA2/SA3 statistical area, and
   state/territory code. Enables `GROUP BY suburb` analytics without re-querying.

3. **Cell-tower cross-reference.** For `kind = 'cell'` rows, parse the `netid`
   (WiGLE stores cell IDs as `MCC-MNC-LAC-CID` strings) and join against
   `opencellid_au` (Phase 1B) to attach the OpenCelliD `range_m`, `samples`,
   and `avg_signal` columns. Combined rows have both crowd-sourced location
   fixes from two independent sources — the fusion improves position accuracy.

4. **SSID pattern tagging.** Apply regex classifiers to `ssid` to populate a
   `tags` column: `isp_default` (e.g., `Telstra…`, `Optus…`, `TPG…`),
   `hidden` (null/empty SSID), `corporate` (matches known AU company name
   patterns from the local OathNet corpus), `residential`, `iot_device`
   (common IoT SSID patterns). Tags enable rapid cohort filtering.

5. **Stale-coordinates refresh trigger.** Records whose `last_updated` is older
   than 180 days and whose `harvest_count` == 1 (seen only once) are flagged
   with `needs_refresh = 1`. The next `hse wigle-harvest --refresh-stale` pass
   prioritises these tiles, updating position and metadata from the live API
   only for tiles that contain stale rows — not a full re-harvest.

6. **HSE entity back-linking.** For every `wigle_au` BSSID that appears as a
   `MacAddress` entity in `huntsman.db`, write a reverse link: update the
   entity's `evidence` JSON to include `{ "source": "wigle_au", "lat": …,
   "lon": …, "ssid": …, "last_seen": … }`. This surfaces WiGLE position data
   automatically in `hse scan` results without a separate lookup step.

**Schema additions for enrichment:**

```sql
ALTER TABLE wigle_au ADD COLUMN vendor        TEXT;   -- OUI → manufacturer
ALTER TABLE wigle_au ADD COLUMN suburb        TEXT;   -- normalised AU suburb
ALTER TABLE wigle_au ADD COLUMN sa2           TEXT;   -- ABS SA2 code
ALTER TABLE wigle_au ADD COLUMN state_code    TEXT;   -- 'NSW'|'VIC'|'QLD'|…
ALTER TABLE wigle_au ADD COLUMN tags          TEXT;   -- JSON array of tags
ALTER TABLE wigle_au ADD COLUMN needs_refresh INTEGER DEFAULT 0;
ALTER TABLE wigle_au ADD COLUMN oci_range_m   INTEGER; -- from opencellid_au join
ALTER TABLE wigle_au ADD COLUMN oci_samples   INTEGER;
```

**Automation:**

- `hse wigle-enrich` runs enrichment actions 1–5 in a single pass, updating
  only rows where the target column is NULL (idempotent re-runs are safe).
- Action 6 is triggered automatically on each `hse scan` that produces a
  `MacAddress` entity, as a post-processing hook in `wigle/mod.rs`.
- All enrichment is local-only: zero additional API quota, zero network access.

**Estimated enrichment time on-device:** < 10 minutes for 5 million rows
(bulk SQL joins, no per-row HTTP calls).

---

## Phase 2 — Australian Breach & People-Search Corpus Ingestion

The goal is a locally-indexed, offline-searchable corpus of every Australian
entry in OathNet and Seek-Search EU, enabling instant sub-second lookups with
no per-query API spend.

### 2A — OathNet Australia Deep Pull

OathNet holds breach and stealer data indexed by email, username, phone, and
domain. The Australian population skews toward `@gmail.com`, `@hotmail.com`,
`@outlook.com`, `@bigpond.com`, `@icloud.com`, `@optusnet.com.au`,
`@westnet.com.au`, `@aapt.net.au`, `@internode.on.net`, and the `.au` TLD
space. A targeted corpus pull strategy avoids pulling the global index
(impractical) while capturing near-complete AU coverage.

**Approach — intelligent algorithmic pull:**

1. **Domain-anchored pull.** For every known Australian ISP / freemail / work
   domain in a maintained seed list (`au_domains.txt`, ≈ 1 500 entries
   including all `.com.au`, `.net.au`, `.edu.au`, `.gov.au`, `.id.au` second-
   level labels with documented MX records), issue an OathNet `domain:` search
   and page through all results. This captures any address at those domains
   regardless of username.

2. **Phone-prefix pull.** Australian mobile prefixes (`04xx`, `+614xx`) and
   landline area codes are finite and enumerable at the prefix level. OathNet's
   `phone:` search supports prefix queries. Issuing `phone:04` subdivided to
   4-digit prefixes (`0400`, `0401`, … `0499`) pages the Australian mobile
   space systematically.

3. **Deduplicated result store.** Results are written to a local FTS5 table
   (`oathnet_au_cache`) keyed on a SHA-256 of `(source, record_id)` to survive
   restarts. This table is also the backing store for `hse scan` — any
   `oathnet_pro` lookup checks the local cache first and only calls the API for
   misses.

4. **Intelligent rate governor.** OathNet enforces per-session quotas. The
   harvester tracks the rolling budget window from the session headers and
   pauses automatically when the budget floor is reached, resuming in the next
   window. High-value domains (`.gov.au`, `.edu.au`, ISP domains) are
   prioritised first; freemail domains (gmail.com, hotmail.com) are deprioritised
   (high volume, low specificity) unless `--include-freemail` is passed.

5. **New command: `hse oathnet-harvest [--domains path] [--phones] [--max N]`.**

---

### 2B — Seek-Search EU Australia Pull

Seek-Search EU (SeekNow) indexes professional and social profile data. The
Australian slice is identified by AU-specific signals: `@` handles at AU
company domains, ABN-linked profiles, LinkedIn `.au` region, Seek job platform
IDs, and ASIC-registered entity names.

**Approach:**

1. **ABN/ACN-anchored pull.** ASIC's free company registry (already used by
   `asic_director`) lists every Australian registered entity with its ABN. Each
   registered entity name is a high-precision Seek-Search query. The ABN seed
   list is pre-built once from the ASIC bulk export and stored locally.

2. **Postcode-anchored pull.** Australian postcode centroids (≈ 9 000 postcodes)
   are already in `src/util/postcode_au`. Each centroid is submitted as a
   `location:` search with a 10 km radius, paging all results. This captures
   individuals not tied to a registered entity.

3. **Linked-entity enrichment.** For each returned profile, the harvester
   follows first-order links (employer → domain, domain → ASIC entity, ASIC
   entity → director names) via HSE's existing module chain, building a locally-
   indexed graph rather than one-off query results. This is the "intelligent
   algorithm" layer: each new entity becomes a query candidate, subject to a
   depth cap (default 2) and a novelty gate (skip entities already in the local
   index).

4. **New command: `hse seeknow-harvest [--abn] [--postcodes] [--depth 2] [--max N]`.**

---

## Phase 3 — Offline Identity Graph

Once Phases 1 and 2 are complete, the local DB contains enough data to answer
most Australian identity queries without any network call. Phase 3 makes this
explicit:

- **`hse scan --offline`** — resolves entirely from local corpus; fails cleanly
  if the corpus is absent rather than silently returning empty results.
- **Local FTS ranking improvements** — BM25 tuning for the `entities_fts` index
  to weight `source` recency and `confidence` into snippet ranking.
- **Graph-diff alerts** — `hse live --delta` triggers only when the local graph
  changes (new entity added, confidence shift > 0.1, new evidence source), not
  on every poll interval.

---

## Phase 4 — Module Expansion

| Module | Input | Output | Priority |
|--------|-------|--------|----------|
| `wigle_harvest` | CLI command | `wigle_au` local corpus | P1 |
| `opencellid_harvest` | CLI command | `opencellid_au` local corpus | P1 |
| `oathnet_harvest` | CLI command | `oathnet_au_cache` local corpus | P2 |
| `seeknow_harvest` | CLI command | local people graph | P2 |
| `signal_radar_au` | `Coordinates` | cell+wifi sweep for AU towers | P3 |
| `au_electoral_deep` | `FullName` | all six state AEC rolls (not just QLD) | P3 |
| `linkedin_public` | `FullName` / `Organisation` | `Username`, `Url` | P4 |
| `au_court_records` | `FullName` / `Organisation` | `Address`, `Url` | P4 |
| `tor_exit_realtime` | `IpAddress` | Tor relay classification (live consensus) | P4 |
| `ipv6_asn_expand` | `Asn` | full IPv6 prefix → CIDR entities | P4 |

---

## Phase 5 — Workflow & UX

- **`hse serve` map view** — Leaflet.js overlay rendering all `Coordinates` and
  `MacAddress` entities from the AU corpus on an offline tile base (MBTiles of
  Australia, ≈ 500 MB at zoom 0–14).
- **Progressive scan status** — streaming SSE events from `hse serve` so the
  browser updates entity cards in real time without polling.
- **Export to OSHINT formats** — MISP event XML, SpiderFoot SQLite, Maltego
  `.mtgx` graph, alongside the existing JSON/CSV/GEXF outputs.
- **Automated operator self-scan** — `hse self-scan` seeded from
  `HUNTSMAN_DEFAULT_SEED` (or interactively prompted), running on a schedule
  via Termux cron, producing a differential report of new exposure since the
  last run.

---

## Implementation Notes for Termux aarch64

All harvest commands must satisfy the same constraints as the rest of HSE:

- **No root.** All writes go to `$HOME/.huntsman/` or `$HOME/.cache/hse-build/`.
- **Storage budget awareness.** Before writing, estimate corpus size and warn if
  `df $HOME` shows less than 2× the estimated size free. Offer `--sidecar-db`
  to write to external storage (`/sdcard/huntsman/`) when internal is tight.
- **Build-time zero overhead.** Harvest commands are gated behind a Clap
  subcommand; they add no latency to `hse scan` or `hse serve`.
- **Resumable by default.** Every harvest loop checkpoints progress into the DB
  after each tile/page so Termux background-process kills (OOM killer, battery
  saver) lose at most one tile of work.
- **`--dry-run` flag on every harvest command.** Prints the query plan and
  estimated API budget without issuing any requests.
