# WiGLE Geolocation Synergy — Verified Integration Reference

**Status:** Corrected against the live `main` codebase and external endpoints **verified 2026-06-12**.
**Supersedes:** an earlier draft that used renamed/legacy module names, a fictional entity/target
model, a fabricated confidence-scoring ladder, a non-existent WiGLE quota endpoint, and several
wrong external URLs. The "what the draft got wrong" table at the end records the specifics.

This reference is constrained by what HSE actually is. Read §0 first — it determines the entire
design and is where the previous draft went off the rails.

---

## 0. Data-model constraints (these shape everything)

**Target kinds** (`src/core/scan/mod.rs`): `Email, Username, Phone, FullName, IpAddress, Domain, Url,
Asn, Cidr, Coordinates, Address, Organisation, AbnAcn, MacAddress, ApiKey, CryptoAddress`.

**Entity kinds** (`src/core/entity.rs`): `Person, Email, Phone, Username, Credential, ApiKey,
Password, IpAddress, Domain, Url, Asn, Cidr, Address, Coordinates, Organisation, AbnAcn, MacAddress,
DeviceId, TrackingId, CryptoAddress` (+ a few more).

Consequences that the design **must** obey:

1. **There is no `Note`, `GeoLocation`, `CellInfo`, `Property`, `BusinessEntity`, or `Manufacturer`
   kind.** Geolocation is `Coordinates` (`"lat,lon"`); an address is `Address`; a BSSID is
   `MacAddress`. Free-text findings attach as **`Evidence`** on an entity — HSE has no standalone
   "Note" entity to emit.
2. **A cell identifier is a `DeviceId` entity, and `DeviceId` is not a `TargetKind`**
   (`TargetKind::from_entity_kind` returns `None` for it). So a module **cannot** receive a cell
   tower as a downstream target. Cell→coordinates enrichment therefore belongs **inside
   `cell_intel`** (which already holds MCC/MNC/LAC/CID at capture), not in a new `cell_geo` module.
3. **Confidence is not an unbounded ladder.** `c_effective` is `min(1.0, C·(1 + 0.15·ln(distinct_sources)))`
   — **clamped to 1.0** (`src/core/scan/scoring.rs`). Corroboration beyond saturation only affects
   *expansion ranking*, via a separate **uncapped** `corroboration_prior = 1 + 0.25·ln(sources)`
   (coefficient **0.25**, not 0.15). There is no "1.27× C_eff" effect.
4. **Reuse, don't reinvent.** These already ship: `geocode` + `photon` (reverse-geocode
   `Coordinates → Address` via Nominatim/Photon), `au_property` (QLD/NSW/VIC land-title by name),
   `cell_intel` (on-device cell capture → `Coordinates`), `wigle` (priority **10**). OUI lookup is
   **offline and inline** (`crate::util::oui::classify_mac`), not an HTTP module.

---

## 1. WiGLE — existing module, facts as-built (`src/modules/wigle.rs`)

- **Base / auth:** `https://api.wigle.net/api/v2`, HTTP Basic — `HUNTSMAN_WIGLE_USER` (API name) +
  `HUNTSMAN_WIGLE_TOKEN`. **Both** are required.
- **Module:** `priority() == 10` (geolocation finaliser), `accepts` `Coordinates | MacAddress`,
  `cost == KeyGated`, 20 s timeout.
- **Search:** bbox via `latrange1/latrange2/longrange1/longrange2`, `resultsPerPage=100`,
  `type=wifi|cell|bluetooth`; adaptive box (±0.002° → widen to ±0.01° on zero hits).
- **Detail:** `network/detail?netid=<BSSID>&type=<wifi|cell|bluetooth>`.
- **No machine-readable quota endpoint exists.** `/profile/user` returns a `Person`
  (`userid`, `emailVerified`) and is used only to warn when an unverified account is being throttled.
  **Do not poll `/profile/apiUsage`** — it has never existed and always 404'd. Per-call limiting is
  done locally with `QuotaBudget` caps (geo 3/scan, bssid 5, cell 2, bluetooth 2).
- **Optional hardening (not currently present):** skip locally-administered / randomised MACs before
  a BSSID lookup. The bit test is sound and worth adding, since modern phones randomise MACs:
  ```rust
  fn is_locally_administered(bssid: &str) -> bool {
      bssid.split([':', '-']).next()
          .and_then(|o| u8::from_str_radix(o, 16).ok())
          .is_some_and(|b| b & 0x02 != 0)
  }
  // On true: tag the MacAddress "laa-randomised", skip the WiGLE detail lookup.
  ```

---

## 2. OpenCelliD — verified endpoint; fold into `cell_intel` (do not add `cell_geo`)

- **Verified:** `GET https://opencellid.org/cell/get?key=<k>&mcc=<i>&mnc=<i>&lac=<i>&cellid=<i>&format=json`
  (default format is **xml**, so `format=json` is mandatory). Optional `radio=GSM|UMTS|LTE|NR|CDMA`.
- **Response fields:** `lat`, `lon`, **`range`** (accuracy radius in metres — *not* `accuracy`),
  `samples`, `averageSignalStrength`, `changeable` (`1`=measured, `0`=precise). Licence **CC-BY-SA 4.0**;
  **commercial use requires whitelisting**.
- **AU:** MCC `505`; `mnc` is an **integer** — Telstra `1`, Optus `2`, Vodafone/TPG `3` (no leading zeros).
- **Integration (corrected):** `cell_intel` already captures MCC/MNC/LAC/CID and emits `Coordinates`.
  Add OpenCelliD as an **optional enrichment inside `cell_intel`**, gated on `HUNTSMAN_OPENCELLID_KEY`,
  emitting a corroborating `Coordinates` (tagged `source:opencellid`). A standalone downstream module
  is impossible (see §0.2 — cell ids aren't targets).

---

## 3. ACMA RRL — verified; offline SQLite sidecar (sound approach)

- **Bulk download:** `spectra_rrl.zip` from <https://www.acma.gov.au/radiocomms-licence-data>,
  refreshed daily by ~6am AEST. Importable to SQLite — there is real precedent
  (`github.com/kronicd/rrl_import`). **Do not scrape the live RRL site** (ToS-sensitive and brittle).
- **Use:** weekly refresh into a local `~/.huntsman_rrl.db`; at scan time query by coordinate bbox to
  get licensee + ABN, then feed the real **`abn_lookup`** module (`AbnAcn` target,
  `HUNTSMAN_ABR_GUID`). Emits `Organisation` + `AbnAcn` from a `Coordinates` input — viable as a
  `Coordinates`-accepting module or a sidecar store.
- **Caveat:** take the exact table/column names from the actual import — **do not hardcode a guessed
  schema** (the prior draft's `SITE_LAT`/`LICENCEE`/… are unverified).

---

## 4. Nominatim reverse — verified; already covered by `geocode`/`photon`

- **Verified:** `GET https://nominatim.openstreetmap.org/reverse?format=geocodejson&lat=&lon=&zoom=18&addressdetails=1`.
  `format` supports `geocodejson`; `zoom` 0–18 (18 = address level). Usage policy requires an
  identifying `User-Agent`/email for volume and **≤ 1 req/s**.
- **Integration:** `geocode` (Nominatim) and `photon` already do `Coordinates → Address`. **No new
  `reverse_geocode` module is needed.** If `geocodejson`'s stable admin levels are wanted, extend
  `geocode` rather than adding a module. (Use a real version string in the UA, e.g. the crate
  version — *not* a fabricated "9.0".)

---

## 5. QLD DCDB cadastre — verified; genuinely new, distinct from `au_property`

- **Verified host/layer:** `https://spatial-gis.information.qld.gov.au` (the draft's `spatial-img…`
  and `gisservices…` hosts are wrong), service
  `PlanningCadastre/LandParcelPropertyFramework/MapServer`, **Cadastral parcels = layer 4** (not 1).
- **Point-in-polygon query:**
  ```
  GET https://spatial-gis.information.qld.gov.au/arcgis/rest/services/
      PlanningCadastre/LandParcelPropertyFramework/MapServer/4/query
      ?geometry=<lon>,<lat>&geometryType=esriGeometryPoint
      &spatialRel=esriSpatialRelIntersects&outFields=*&returnGeometry=false&f=json
  ```
  No key. Returns lot/plan attributes. **Verify the exact `outFields` names against the live `/4`
  layer metadata before coding.**
- **Why it's distinct:** `au_property` is **name-keyed** (`full_name`); this is a **coordinate-keyed**
  lot/plan lookup — a different capability.
- **Status: shipped** as `src/modules/qld_cadastre.rs` (priority 18, free, `Geo`). Accepts
  `Coordinates`, gates on `au_state_for_coords == QLD` (no network off-state), and emits an enriched
  `Coordinates` (lot/plan/locality/tenure as evidence) plus a locality `Address`. The `outFields`
  were confirmed against the live `/4` layer: `lot, plan, lotplan, locality, shire_name, tenure,
  parcel_typ`.

---

## 6. NBN tech-type — verified undocumented; recommend *against* shipping by default

- **Real shape:** `GET https://places.nbnco.net.au/places/v1/nearby?lat=&lng=&source=website_rollout_map`
  → then `GET https://places.nbnco.net.au/places/v2/details/LOC<id>` (a `Referer` header is required).
  Fields: `techTypeDescription`, `serviceType`, `serviceStatus` (the draft's `/autocomplete?query=`
  shape and `technology_type` field names are wrong).
- **Assessment:** undocumented / reverse-engineered → **ToS and breakage risk**, and it produces only
  metadata (HSE has no `Note` entity — §0.1). **Recommendation: do not enable by default.** If added,
  make it opt-in and emit the tech type as **`Evidence`/tags on the `Coordinates` entity**, never as a
  standalone entity.

---

## 7. Corrected synergy chain (real kinds, real modules)

```
MacAddress (BSSID)
  └─ wigle (pri 10) ─────────────► Coordinates (+ Address, MacAddress, Organisation)
                                   │
Coordinates ───────────────────────┤
  ├─ geocode / photon ────────────► Address              (EXISTING — Nominatim/Photon)
  ├─ qld_cadastre (QLD) [SHIPPED] ► Coordinates + Address + lot/plan Evidence  (ArcGIS layer 4)
  └─ [new] acma_rrl sidecar ──────► Organisation + AbnAcn
                                      └─ abn_lookup ─────► Organisation / Address  (EXISTING)

On-device:
  cell_intel (captures MCC/MNC/LAC/CID) ─► Coordinates
     └─ [optional] OpenCelliD enrichment INSIDE cell_intel ─► corroborating Coordinates
```

**Corroboration semantics (corrected):** independent sources agreeing within tolerance increase the
distinct-source count. `c_effective` saturates at 1.0; the uncapped `corroboration_prior` (0.25)
only re-orders the expansion queue. A contradiction (e.g. OpenCelliD > 2 km from the WiGLE fix) is
recorded as **competing evidence on the entity** — never averaged, never an increment.

---

## 8. New components summary (corrected)

| Component | Type | Input → Output | Endpoint (verified) | Key |
|---|---|---|---|---|
| OpenCelliD enrichment | **inside `cell_intel`** | cell id → `Coordinates` | `opencellid.org/cell/get?…&format=json` (`range` field) | `HUNTSMAN_OPENCELLID_KEY` |
| `qld_cadastre` | **shipped** ✓ | `Coordinates(QLD)` → `Coordinates` + `Address` + lot/plan Evidence | `spatial-gis.information.qld.gov.au …/MapServer/4/query` | none |
| `acma_rrl` | new sidecar/module | `Coordinates` → `Organisation` + `AbnAcn` | offline SQLite from `spectra_rrl.zip` | none |
| ~~`reverse_geocode`~~ | **not needed** | — | already `geocode`/`photon` | — |
| ~~`cell_geo`~~ | **not viable** | — | cell ids aren't a `TargetKind` (fold into `cell_intel`) | — |
| ~~`oui`~~ | **not needed** | — | already inline `util::oui::classify_mac` | — |
| NBN tech-type | **opt-in, discouraged** | `Coordinates` → Evidence only | `places.nbnco.net.au` v1 nearby + v2 details | none (ToS risk) |

All new code must keep HSE conventions: `#![forbid(unsafe_code)]`, errors via
`Error::module(...)`, no credentials in evidence, per-source `QuotaBudget` caps, and `cargo fmt` +
`clippy -D warnings` clean.

---

## What the prior draft got wrong (for the record)

| Claim in draft | Reality |
|---|---|
| `TargetKind::Note` / `GeoLocation` / `CellInfo` / `Property` | None exist; geo is `Coordinates`, metadata is `Evidence` |
| `C_eff = clamp(C·(1+0.15·ln(n)))` rising to 1.27× | `c_eff` is clamped to **1.0**; ranking prior uses **0.25**, uncapped |
| WiGLE quota via `/profile/user` (`querycount`) / "halt if <5" | No quota endpoint; `/profile/user` is `userid`+`emailVerified` only |
| `wigle` priority 42; modules `cell_survey`, `forward_geocode`, `au_abr`, `dns_resolver`, `wifi_connect` | priority **10**; real names `cell_intel`, `geocode`/`photon`, `abn_lookup`, `dns_intel`, `wifi_intel` |
| New `oui` module → `macvendorlookup.com` | OUI is offline/inline (`util::oui::classify_mac`) |
| OpenCelliD `accuracy` field, `format` default json, `mnc=01` | field is `range`; default **xml**; `mnc` integer `1/2/3` |
| QLD `spatial-img…`/`gisservices…`, layer 1 | host `spatial-gis.information.qld.gov.au`, layer **4** |
| NBN `/autocomplete?query=`, `technology_type` | `/v1/nearby?lat&lng` + `/v2/details/LOC…`; `techTypeDescription` |
| UA `HuntsmanSearchEngine/9.0` | repo is v1.0.0 — use the real crate version |

---

## Sources (verified 2026-06-12)

- OpenCelliD API — <https://wiki.opencellid.org/wiki/API>, downloads/licence <https://opencellid.org/downloads/>
- Nominatim reverse — <https://nominatim.org/release-docs/latest/api/Reverse/>, policy <https://operations.osmfoundation.org/policies/nominatim/>
- ACMA RRL data — <https://www.acma.gov.au/radiocomms-licence-data>, offline tool <https://web.acma.gov.au/offline-rrl/>, import precedent <https://github.com/kronicd/rrl_import>
- QLD DCDB — <https://spatial-gis.information.qld.gov.au/arcgis/rest/services/PlanningCadastre/LandParcelPropertyFramework/MapServer>
- NBN (undocumented) — endpoints per community reverse-engineering (`github.com/LukePrior/nbn-service-check`); not an official API
- WiGLE — facts taken from `src/modules/wigle.rs` as-built; API <https://api.wigle.net/>
