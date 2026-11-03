# Queensland traffic camera catalogue (public GeoJSON)

Read-only, rootless Termux integration, based on the QLDTraffic API specification v1.10
(19 February 2025), section 2.1.1.1 and sections 4.4–4.5 and 5.3.

## Run

```sh
cargo run --locked -- traffic-cameras --limit 5
cargo run --locked -- traffic-cameras --district Metropolitan --limit 50
cargo run --locked -- traffic-cameras --district 'North Coast' --locality Nambour
```

The command requests the official GeoJSON collection **once** through Huntsman's
guarded HTTPS transport and prints a JSON report with provider total, filter
matches, returned rows, rejected features, collection timestamp and a typed
source outcome. The command does **not** download or refresh camera images.
It makes no HTTP requests until an operator explicitly executes it.

## Upstream sources and roles

| Source | Endpoint | Role |
| --- | --- | --- |
| TMR / QLDTraffic | https://api.qldtraffic.qld.gov.au/v1/webcams | Primary dynamic webcam metadata |
| TMR state-road GIS | https://spatial-gis.information.qld.gov.au/arcgis/rest/services/Transportation/StateRoadInformation/MapServer/4 | Separate GIS asset catalogue; *not* an image availability proof |
| Queensland OpenDataSoft | https://queensland.opendatasoft.com/explore/assets/live-traffic-cameras-gold-coast/ | Republished webcam data; different schema |
| Brisbane City Council | https://data.brisbane.qld.gov.au/explore/dataset/traffic-cctv-cameras/ | Municipality CCTV locations; **not** a public video feed |

The QLDTraffic public developer key is documented in the official API spec
and globally shared at **100 requests per minute**. A global limit is not
a per-device allowance: the CLI intentionally uses one request, with a paced
circuit breaker; repeated requests must be operator-controlled. A private key
must never be placed into the public-key constant. For production, register a
separate key with TMR and implement it via the existing origin-bound
`fetch::Credential` mechanism; do not interpolate user secrets into URLs.

## Live public-feed comparison, 2026-11-03 UTC

A direct API read returned **152** camera features; the OpenDataSoft
catalogue reported **152** records; the separate GIS query reported **158**.
Reconciling **camera IDs** returned:

* **123** IDs in both official API and ArcGIS.
* **29** IDs in the official API only.
* **35** IDs in ArcGIS only.

Thus the six-record difference in totals is *not* six extra live cameras.
Asset GIS and real-time web camera inventories have materially different
membership; no claim is made that GIS-only cameras have live imagery.
Counts can change at any time. Recompute them before displaying an operational
coverage percentage. Use provenance-qualified keys
`qldtraffic:ID` and `qld-state-gis:ID`, compare by camera ID, and use
coordinates only as spatial context, not as identity.

## Semantics and security

* GeoJSON positions are `[longitude, latitude]`. The feed returns an
  `EPSG:7844` CRS hint. Coordinate timestamps are not present.
* Reject malformed coordinates, duplicate identifiers, empty required fields,
  non-HTTPS or unapproved image hosts and malformed feature collections.
* The derived camera metadata URL uses the official fixed API origin.
  Untrusted URL fields must not become arbitrary HTTP fetch destinations.
* An HTTP 429, 403, timeout, WAF, parser error or partial/truncated response is
  **never** a verified zero-camera result.
* A camera `image_url` references the publisher's current JPEG location but
  is **not proof of freshness**, continuous live video, recording capability,
  face recognition, ANPR or access to internal municipal CCTV.
* Any later image checker must preserve time fetched, Last-Modified/ETag when
  present, digest, HTTP status and content type, use a positive JPEG signature,
  enforce size/time caps, and classify repeated image hashes as **unchanged**,
  not as evidence that the camera itself is offline.
* TMR's QLDTraffic website says imagery refreshes approximately every
  **60 seconds**, but a web page's schedule alone does not attest each image.
* Include attribution: © State of Queensland (Department of Transport and
  Main Roads), QLDTraffic API specification, licensed CC BY 4.0 AU.
  Check the applicable licence for each separate catalogue before combining.
* The Brisbane Council CCTV *location* dataset must never be interpreted as
  public permission to retrieve CCTV footage.

## Source-synergy and orthogonal reconciliation

Run `huntsman-recon traffic-cameras --reconcile` to compare two independent
*catalogue snapshots*, but not independently published facts: both come from
Queensland Transport and Main Roads.

- Dynamic public webcam GeoJSON (152 records observed on 2026-11-03).
- Static GIS state-road camera assets, MapServer layer 4 (158 observed).
  The fixed query requests `camera_id,description,direction,locality`, `outSR=4326`
  and `f=geojson`. GIS defaults to Web Mercator (metres), so the explicit
  WGS84 projection request is necessary for correct distance calculations.

This opt-in second request uses the same bounded, guarded transport and
typed outcome classification. Both complete inventories are reconciled
**before** locality or result-limit filtering. Result fields include exact
shared camera IDs, each source's unique IDs, shared-ID position conflicts
over 100 metres, same-ID compass-direction conflicts, and possible nearby *different-ID* camera candidates.
Different-ID candidates are never merged: proximity is not identity.
The candidate cross-product is capped at 256 by 256 records, and at most
64 candidate links are displayed with an explicit truncation flag.

The 2026-11-03 observations showed **123** shared IDs, **29** webcam-only
IDs, and **35** GIS-only IDs.
An independent same-day comparison also found **three** shared-ID location
conflicts over 100 metres: camera 136 (approximately 1886 metres), 39
(122 metres) and 135 (119 metres). Camera 136's orientation was **South**
in the webcam API but **North** in GIS, while camera 39 was **North**
in the API and **NorthWest** in GIS. These contradicting metadata assertions
are retained explicitly for review, not resolved automatically.
The difference between 152 and 158 totals
alone would mask 64 differing records. No camera presence, image freshness,
operational state, vehicle or person identity is inferred from catalogue
membership. Both sources belong to the same publisher family, and
`publisher_families=1` forbids falsely claiming independent corroboration.
OpenDataSoft is a republication, not an additional independent witness.
If either source is unavailable or incomplete, `reconciliation` is null
rather than a false zero.

```sh
cargo run --locked -- traffic-cameras --reconcile --limit 10
cargo run --locked -- traffic-cameras --reconcile --district 'North Coast' --limit 25
cargo test --locked qld_traffic_cameras
```

## Test and release gates

Offline module tests cover valid and empty FeatureCollections, coordinate
order, duplications, untrusted image URLs, malformed input, HTTP status
classification and one-shot guarded requests.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked qld_traffic_cameras
cargo run --locked -- traffic-cameras --limit 2
```

The final command is a **live network test** and must run on the actual
rootless Android Termux AArch64 target before claiming device support. No
claim that CI or a desktop build is a substitute for a phone validation.

## Web UI (manual collection, rootless Android)

The Radar page has an explicit **Compare live camera catalogues** button.
The page calls `GET /api/traffic/cameras`, which uses exactly the same
Rust `collect` and `collect_gis` functions as the CLI. The endpoint has:

- the existing bearer-token gate on non-loopback binds;
- same-origin and `X-Huntsman-Lookup: 1` request guards;
- a single bounded worker, a 40-second response deadline, no URL parameters,
  and no network request until the operator presses the button;
- source outcomes exposed individually rather than a fabricated empty list;
- concise disagreement tables and client-side JSON export of the complete
  retrieved metadata (no privileged device APIs or image downloads).

The response may contain sensitive investigation *context* if subsequently
combined with separate data; do not infer person/vehicle identity or
camera-operational status from metadata alone. The page only displays text
using DOM `textContent` and has no external JS, CSS or image dependencies.

**Delivered scope:** One-shot read-only Rust library, CLI, guarded API, manual
phone Web UI, exact ID/location/direction differences and structured JSON
export. Not delivered: persisted longitudinal change history, a dedicated
registered API-key slot, JPEG freshness validation, independent third-party
corroboration or municipal CCTV imagery.

**Native phone acceptance:** Once the exact reviewed feature revision has been built
and installed in rootless Termux, start the embedded Web UI locally and run:

```sh
pkg install jq curl
bash scripts/termux/traffic-camera-acceptance.sh
```

The script refuses non-Termux, non-AArch64 and root contexts, checks the
binary build SHA, exercises both guarded collectors from the CLI and the
live Web API, and independently verifies inventory arithmetic and publisher
family semantics. It writes temporary JSON with mode-700 containment and
removes it at exit; it makes no repeated/background source requests. Its
`PASS` is **on-device evidence** only when executed on the phone; adding the
script to GitHub does not constitute on-device testing. Only run it against
an intentional and verified checkout of the feature revision.

**Release acceptance:** `cargo gate full` on the tested commit; CI's Android
cross-build and browser tests; then a live one-shot camera request and
`huntsman-recon doctor serve` on the actual rootless Termux phone. Cloud
CI and an Android cross-build are not on-device acceptance receipts.
