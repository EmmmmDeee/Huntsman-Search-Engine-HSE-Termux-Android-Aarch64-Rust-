# Queensland traffic camera catalogue (public GeoJSON)

Read-only, rootless Termux integration, based on the QLDTraffic API specification v1.10
(19 February 2025), section 2.1.1.1 and sections 4.4–4.5 and 5.3.

## Key

The webcam feed answers only a request that carries a QLDTraffic key in its `apikey` query
parameter. Put one in the `HUNTSMAN_QLDTRAFFIC_KEY` slot of `~/.huntsman.env` (mode 600) or the
environment. The API specification (§2.1.1.1) prints a shared public developer key, limited to
100 requests a minute across everyone who uses it; TMR also issues keys to developers who ask
(§2.1.1.2, via the [Developers and data](https://qldtraffic.qld.gov.au/more/Developers-and-Data/index.html)
page). No key is built into the binary: the request goes through the API leg kernel
(`api_leg`), which adds the key only as the request is sent, binds it to
`https://api.qldtraffic.qld.gov.au`, follows no redirect and scrubs it from every diagnostic.
Without a key the command sends nothing, reports the slot as `not_configured` and exits 66.
`credential-status` lists the slot with the other providers. The state-road GIS layer needs no key.

## Run

```sh
cargo run --locked -- traffic-cameras --limit 5
cargo run --locked -- traffic-cameras --district Metropolitan --limit 50
cargo run --locked -- traffic-cameras --district 'North Coast' --locality Nambour
```

The command requests the official GeoJSON collection **once** and prints a JSON report with
provider total, filter matches, returned rows, rejected features, collection timestamp and a
typed source outcome. The command does **not** download or refresh camera images. It makes no
HTTP requests until an operator explicitly executes it. It exits 0 when every source it asked
answered, 66 when the key is not configured, 77 when a request was refused before sending, and
69 when a source gave no usable answer; each unanswered source's reason is printed on stderr.

## Upstream sources and roles

| Source | Endpoint | Role |
| --- | --- | --- |
| TMR / QLDTraffic | https://api.qldtraffic.qld.gov.au/v1/webcams | Primary dynamic webcam metadata |
| TMR state-road GIS | https://spatial-gis.information.qld.gov.au/arcgis/rest/services/Transportation/StateRoadInformation/MapServer/4 | Separate GIS asset catalogue; *not* an image availability proof |
| Queensland OpenDataSoft | https://queensland.opendatasoft.com/explore/assets/live-traffic-cameras-gold-coast/ | Republished webcam data; different schema |
| Brisbane City Council | https://data.brisbane.qld.gov.au/explore/dataset/traffic-cctv-cameras/ | Municipality CCTV locations; **not** a public video feed |

The shared public key's limit is global, not a per-device allowance: the command makes one
request per run, and repeated requests must be operator-controlled.

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
  **never** a verified zero-camera result. A GIS reply that says the layer holds more
  records than it carries (`exceededTransferLimit`, at the top of the reply or under its
  `properties`) keeps its rows, is flagged `exceeded_transfer_limit`, and is never used
  for a reconciliation.
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

This opt-in second request goes through the same API leg kernel, keyless, with the same
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
If either source is unavailable, partly rejected or capped by the GIS layer's
transfer limit, `reconciliation` is null rather than a false zero.

```sh
cargo run --locked -- traffic-cameras --reconcile --limit 10
cargo run --locked -- traffic-cameras --reconcile --district 'North Coast' --limit 25
cargo test --locked qld_traffic_cameras
```

## Test and release gates

Offline module tests cover valid and empty FeatureCollections, coordinate
order, duplications, untrusted image URLs, malformed input, HTTP status
classification, the key's placement and absence, a capped GIS reply and one-shot requests.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked qld_traffic_cameras
cargo run --locked -- traffic-cameras --limit 2
```

The final command is a **live network test** and must run on the actual
rootless Android Termux AArch64 target before claiming device support. No
claim that CI or a desktop build is a substitute for a phone validation.

## Scope

**Delivered:** a one-shot, read-only Rust library and the `traffic-cameras` CLI, with exact
ID, location and direction differences in structured JSON. There is no web route or web UI
panel: the phone page has no room under its 144 KiB budget, and a request that fetches two
catalogues should not hang off a GET route. **Not delivered:** persisted longitudinal change
history, JPEG freshness validation, independent third-party corroboration or municipal CCTV
imagery.

**Release acceptance:** `cargo gate full` on the tested commit and CI's Android cross-build;
then, with the key configured, a live `traffic-cameras --reconcile --limit 2` on the actual
rootless Termux phone. Cloud CI and an Android cross-build are not on-device acceptance
receipts.
