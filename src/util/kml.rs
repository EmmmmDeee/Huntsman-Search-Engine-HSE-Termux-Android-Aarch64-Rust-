//! `util::kml` — WiGLE KML wardriving-export ingestion engine.
//!
//! Converts a WiGLE `*.kml` export (the file you get from
//! <https://wigle.net> after an upload, or straight off the Android app)
//! into the HSE entity model so wardrive captures flow through the exact
//! same correlation / timeline / graph / web-UI machinery as any other
//! scan.
//!
//! # Why it lives in `util/`
//! It needs three things at once: `core::entity` (to mint `Entity`s — the
//! established pattern, see `util::diagnostics`), `util::oui` (BSSID →
//! vendor/device class), and `util::geohash` (geohash, country, timezone,
//! haversine). `core/` may not depend on `util/`, and `modules/` may not
//! depend on `engine`/`storage`; `util/` is the one layer that can hold all
//! three dependencies *and* be imported by both `cli/` and `api/`. The
//! persistence + correlation steps stay in those caller layers via
//! `StoragePort`, so this file never touches storage or the engine.
//!
//! # Architecture invariants honoured
//! - `#![forbid(unsafe_code)]` (crate-wide) — pure-safe parsing.
//! - Zero new dependencies / zero C/native deps: a hand-rolled streaming
//!   scanner, no XML crate. This keeps the Termux aarch64 (no-root) build a
//!   single static binary and keeps memory flat on multi-MB captures.
//! - Deterministic SHA-256 entity UIDs, GREATEST-semantics merge: repeated
//!   observations of one BSSID converge to one entity whose `corroboration`
//!   counts the sightings.
//!
//! # WiGLE KML record shape (verified against real exports)
//! ```xml
//! <Placemark>
//!   <name>HomeWiFi</name>                         <!-- SSID / carrier name -->
//!   <description>Network ID: 00:11:22:33:44:55    <!-- BSSID or PLMN_TAC_CID -->
//! Encryption: WPA2
//! Time: 2025-01-27T08:21:17.000-08:00
//! Signal: -89.0
//! Accuracy: 5.04
//! Type: WIFI</description>
//!   <styleUrl>#highConfidence</styleUrl>           <!-- confidence / radio class -->
//!   <Point><coordinates>152.95878601,-26.94807434</coordinates></Point>
//! </Placemark>                                     <!-- NOTE: lon,lat order -->
//! ```
//! `Type` ∈ {WIFI, BLE, BT, LTE, GSM, NR, CDMA, WCDMA}. WiFi/BT/BLE carry a
//! MAC `Network ID`; cellular carries `PLMN_TAC_CID` (e.g. `50501_28674_…`,
//! PLMN 505/01 = Telstra AU). SSIDs are XML-escaped (`Trey&amp;Fefe`).

use std::collections::BTreeMap;
use std::collections::HashMap;

use serde::Serialize;

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::geohash;
use crate::util::oui;

/// Source label stamped on every piece of evidence this engine emits.
pub const SOURCE: &str = "import:wigle-kml";

/// Geohash precision for the per-record `geohash` field (block-level, ±19 m).
const RECORD_GEOHASH_PRECISION: u8 = 8;

/// Geohash precision used to cluster coordinate observations into
/// `Coordinates` entities. 7 ≈ ±76 m (suburb block). Coarsened
/// automatically if a capture is so dense it would blow the cluster cap.
const CLUSTER_GEOHASH_PRECISION: u8 = 7;

/// Hard ceiling on emitted `Coordinates` cluster entities, so a 40k-point
/// capture can't mint 40k graph nodes. Every raw point still appears in
/// `records` — clustering only bounds the *derived* graph view.
const MAX_COORD_CLUSTERS: usize = 2000;

/// Cap on evidence rows attached to a single deduplicated BSSID entity.
/// A BSSID seen 900 times needs its `corroboration` count, not 900 rows.
const MAX_EVIDENCE_PER_ENTITY: usize = 4;

// ─── Radio kind ────────────────────────────────────────────────────────────

/// The radio technology a placemark describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioKind {
    Wifi,
    Ble,
    BtClassic,
    Cellular,
    Unknown,
}

impl RadioKind {
    /// Map a WiGLE `Type:` token to a radio kind.
    fn from_type(t: &str) -> Self {
        match t.trim().to_ascii_uppercase().as_str() {
            "WIFI" => Self::Wifi,
            "BLE" => Self::Ble,
            "BT" => Self::BtClassic,
            "LTE" | "GSM" | "NR" | "CDMA" | "WCDMA" | "UMTS" => Self::Cellular,
            _ => Self::Unknown,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Ble => "ble",
            Self::BtClassic => "bt",
            Self::Cellular => "cellular",
            Self::Unknown => "unknown",
        }
    }
}

// ─── Public data model (all JSON-serialisable) ──────────────────────────────

/// One fully-parsed WiGLE observation. Every field that was present in the
/// source KML is preserved verbatim — this is the "raw and transparent"
/// record the operator sees in the JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct KmlRecord {
    /// SSID (WiFi), device name (BT/BLE), or carrier name (cellular).
    pub name: Option<String>,
    /// `Network ID` — BSSID (MAC) for WiFi/BT/BLE, `PLMN_TAC_CID` for cell.
    pub network_id: String,
    /// Normalised radio kind.
    pub radio: &'static str,
    /// Raw `Type:` token from the export (WIFI/BLE/BT/LTE/GSM/NR/…).
    pub raw_type: String,
    /// Encryption (WiFi only): WPA2/WPA3/WEP/Unknown/None.
    pub encryption: Option<String>,
    /// Signal strength in dBm, if present.
    pub signal_dbm: Option<f64>,
    /// GPS accuracy metric reported by the capturing device.
    pub accuracy: Option<f64>,
    /// Observation timestamp, ISO-8601, exactly as exported.
    pub observed_at: Option<String>,
    /// WiGLE confidence / radio class from `<styleUrl>`
    /// (high/medium/low/zero/ble/bt/cell).
    pub confidence: String,
    /// Latitude (WGS-84). KML stores lon,lat — this is the *second* value.
    pub lat: f64,
    /// Longitude (WGS-84).
    pub lon: f64,
    /// Block-level geohash (precision 8) of (lat, lon).
    pub geohash: String,
    /// Whether `network_id` parsed as a 48-bit MAC.
    pub is_mac: bool,
    /// IEEE OUI vendor for the BSSID, when known.
    pub vendor: Option<String>,
    /// Device class inferred from the OUI (phone/router/wearable/…).
    pub device_class: Option<String>,
    /// Mobile Country Code (cellular only).
    pub mcc: Option<String>,
    /// Mobile Network Code (cellular only).
    pub mnc: Option<String>,
}

/// Geographic extent of the capture.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BoundingBox {
    pub min_lat: f64,
    pub min_lon: f64,
    pub max_lat: f64,
    pub max_lon: f64,
}

/// Capture centroid + its geohash. Used as the imported scan's target.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Centroid {
    pub lat: f64,
    pub lon: f64,
}

/// `{ key, count }` pair — used for the ordered breakdown arrays so the JSON
/// stays sorted-by-frequency and intuitive to skim.
#[derive(Debug, Clone, Serialize)]
pub struct Tally {
    pub key: String,
    pub count: usize,
}

/// Earliest/latest observation timestamps (lexicographic on ISO-8601).
#[derive(Debug, Clone, Serialize)]
pub struct TimeRange {
    pub earliest: String,
    pub latest: String,
}

/// Aggregate statistics over the whole capture — the at-a-glance summary.
#[derive(Debug, Clone, Serialize, Default)]
pub struct KmlStats {
    pub total_records: usize,
    pub wifi: usize,
    pub ble: usize,
    pub bt: usize,
    pub cellular: usize,
    pub unknown: usize,
    pub unique_macs: usize,
    pub unique_cell_towers: usize,
    pub unique_carriers: usize,
    pub named_networks: usize,
    pub hidden_networks: usize,
    pub coordinate_clusters: usize,
    /// Records skipped (no coordinates / unparseable). Surfaced, never hidden.
    pub skipped_records: usize,
    pub by_type: BTreeMap<String, usize>,
    pub by_encryption: BTreeMap<String, usize>,
    pub by_confidence: BTreeMap<String, usize>,
    pub top_vendors: Vec<Tally>,
    pub top_ssids: Vec<Tally>,
    pub bounding_box: Option<BoundingBox>,
    pub time_range: Option<TimeRange>,
    pub country_iso: Option<String>,
    pub country_name: Option<String>,
    pub timezone: Option<String>,
}

/// Pure parse output: the `<Document>` name, every record, and any warnings.
/// No entities, no stats — `ingest` builds those on top.
#[derive(Debug, Clone, Serialize)]
pub struct KmlDocument {
    pub document_name: Option<String>,
    pub records: Vec<KmlRecord>,
    pub warnings: Vec<String>,
}

/// The complete, self-contained result of ingesting one KML file: the raw
/// records, the aggregate stats, the derived HSE entities, and the centroid
/// that callers use as the imported scan's target. Serialised in full as the
/// transparent JSON payload.
#[derive(Debug, Clone, Serialize)]
pub struct KmlIngest {
    pub source_label: String,
    pub document_name: Option<String>,
    pub record_count: usize,
    pub entity_count: usize,
    pub centroid: Option<Centroid>,
    pub suggested_target: Option<String>,
    pub stats: KmlStats,
    pub entities: Vec<Entity>,
    pub records: Vec<KmlRecord>,
    pub warnings: Vec<String>,
    pub generated_at: u64,
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Stream-parse a WiGLE KML document into records.
///
/// Single forward pass over the input with a moving cursor: each
/// `<Placemark>…</Placemark>` block is sliced out and field-extracted, so peak
/// memory is the input string plus the output vector — no DOM, no second copy.
pub fn parse(input: &str) -> KmlDocument {
    let document_name = inner_tag(input, "name").map(|s| xml_unescape(&s));
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    let mut cursor = 0usize;
    let mut placemark_idx = 0usize;

    // `find_from` returns char-boundary-safe absolute byte offsets (it searches
    // the `&str`, never raw bytes), so the slices below can never panic on a
    // multibyte SSID.
    while let Some(start) = find_from(input, cursor, "<Placemark>") {
        let Some(end) = find_from(input, start, "</Placemark>") else {
            warnings.push("unterminated <Placemark> — truncated file?".to_string());
            break;
        };
        let block = &input[start..end];
        cursor = end + "</Placemark>".len();
        placemark_idx += 1;

        match parse_placemark(block) {
            Ok(rec) => records.push(rec),
            Err(reason) => {
                // Only the first few parse misses are spelled out; the rest are
                // counted so a malformed export can't spam the warning list.
                if warnings.len() < 16 {
                    warnings.push(format!("placemark #{placemark_idx}: {reason}"));
                }
            }
        }
    }

    KmlDocument {
        document_name,
        records,
        warnings,
    }
}

/// Parse a single `<Placemark>…` slice into a record, or explain why not.
fn parse_placemark(block: &str) -> Result<KmlRecord, String> {
    let coords = inner_tag(block, "coordinates").ok_or("no <coordinates>")?;
    let (lon, lat) = parse_coordinates(&coords).ok_or("unparseable <coordinates>")?;

    let name = inner_tag(block, "name")
        .map(|s| xml_unescape(s.trim()))
        .filter(|s| !s.is_empty() && s != "(no SSID)" && s != "(no name)");

    let style = inner_tag(block, "styleUrl").unwrap_or_default();
    let confidence = style_to_confidence(&style).to_string();

    let desc = inner_tag(block, "description")
        .map(|s| xml_unescape(&s))
        .unwrap_or_default();
    let fields = parse_description(&desc);

    let network_id = fields
        .get("network id")
        .map(|s| s.trim().to_string())
        .ok_or("no Network ID in <description>")?;
    let raw_type = fields
        .get("type")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let radio = RadioKind::from_type(&raw_type);

    let encryption = fields
        .get("encryption")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let signal_dbm = fields.get("signal").and_then(|s| s.trim().parse().ok());
    let accuracy = fields.get("accuracy").and_then(|s| s.trim().parse().ok());
    let observed_at = fields
        .get("time")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let is_mac = is_mac48(&network_id);
    // `classify_mac` returns `Some(vendor:"Unknown", class:Unregistered)` for
    // OUIs outside the curated table. Treat that as "no vendor" (None) rather
    // than tagging thousands of entities `vendor:Unknown` / mass-tallying a
    // meaningless "Unknown" bucket — honest and de-noised.
    let (vendor, device_class) = if is_mac {
        match oui::classify_mac(&network_id) {
            Some(info) if info.vendor != "Unknown" => (
                Some(info.vendor.to_string()),
                Some(info.class.as_str().to_string()),
            ),
            _ => (None, None),
        }
    } else {
        (None, None)
    };
    let (mcc, mnc) = if matches!(radio, RadioKind::Cellular) {
        parse_plmn(&network_id)
    } else {
        (None, None)
    };

    Ok(KmlRecord {
        name,
        network_id,
        radio: radio.as_str(),
        raw_type,
        encryption,
        signal_dbm,
        accuracy,
        observed_at,
        confidence,
        lat,
        lon,
        geohash: geohash::geohash(lat, lon, RECORD_GEOHASH_PRECISION),
        is_mac,
        vendor,
        device_class,
        mcc,
        mnc,
    })
}

/// Absolute byte offset of the first `needle` at or after `from`, or `None`.
/// Operates on the `&str` so the returned offset always lands on a char
/// boundary — safe to slice with.
fn find_from(hay: &str, from: usize, needle: &str) -> Option<usize> {
    hay.get(from..)
        .and_then(|tail| tail.find(needle))
        .map(|rel| from + rel)
}

/// Inner text of the first `<tag>…</tag>` in `block`, CDATA-unwrapped but not
/// yet entity-unescaped (callers unescape what they keep). Returns `None` if
/// the tag is absent or self-closing.
fn inner_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let rel_end = block.get(start..)?.find(&close)?;
    let mut inner = &block[start..start + rel_end];
    // Unwrap a single CDATA section if present (some KML writers wrap
    // descriptions). WiGLE doesn't, but it's cheap insurance.
    if let Some(s) = inner.strip_prefix("<![CDATA[")
        && let Some(s) = s.strip_suffix("]]>")
    {
        inner = s;
    }
    Some(inner.to_string())
}

/// Parse `lon,lat[,alt]` (KML coordinate order) into `(lon, lat)`, validated
/// to the WGS-84 ranges. Returns `None` on malformed or out-of-range input.
fn parse_coordinates(s: &str) -> Option<(f64, f64)> {
    let mut it = s.trim().split(',');
    let lon: f64 = it.next()?.trim().parse().ok()?;
    let lat: f64 = it.next()?.trim().parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    // Reject the WiGLE "no fix" sentinel (0,0) — it's never a real Brisbane AP.
    if lat == 0.0 && lon == 0.0 {
        return None;
    }
    Some((lon, lat))
}

/// Split a WiGLE `<description>` body into a lowercase-keyed field map.
/// Lines are `Key: Value`; keys are lowercased so lookups are case-stable.
fn parse_description(desc: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in desc.lines() {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

/// Map a `<styleUrl>` reference to a human confidence/class label.
fn style_to_confidence(style: &str) -> &'static str {
    match style.trim_start_matches('#') {
        "highConfidence" => "high",
        "mediumConfidence" => "medium",
        "lowConfidence" => "low",
        "zeroConfidence" => "zero",
        "bluetoothLe" => "ble",
        "bluetoothClassic" => "bt",
        "cell" => "cell",
        "" => "unknown",
        _ => "other",
    }
}

/// True if `s` is a 48-bit MAC in any common separator style.
fn is_mac48(s: &str) -> bool {
    let hex = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
    let sep = s
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '-' || c == '.');
    hex == 12 && sep && s.contains([':', '-'])
}

/// Split a cellular `PLMN_TAC_CID` network id into (MCC, MNC). PLMN is the
/// leading token: 5 digits → MCC(3)+MNC(2); 6 digits → MCC(3)+MNC(3).
fn parse_plmn(network_id: &str) -> (Option<String>, Option<String>) {
    let plmn = network_id.split('_').next().unwrap_or("");
    if !plmn.chars().all(|c| c.is_ascii_digit()) {
        return (None, None);
    }
    match plmn.len() {
        5 => (Some(plmn[..3].to_string()), Some(plmn[3..].to_string())),
        6 => (Some(plmn[..3].to_string()), Some(plmn[3..].to_string())),
        _ => (None, None),
    }
}

/// Decode the five predefined XML entities plus numeric (`&#NN;` / `&#xHH;`)
/// references. SSIDs legitimately contain `&` (`Trey&amp;Fefe`), so this is
/// load-bearing, not cosmetic.
fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        if let Some(semi) = tail.find(';').filter(|&i| i <= 10) {
            let ent = &tail[1..semi];
            let decoded = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => None,
            };
            match decoded {
                Some(c) => out.push(c),
                None => out.push_str(&tail[..=semi]), // unknown entity: keep verbatim
            }
            rest = &tail[semi + 1..];
        } else {
            out.push('&');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

// ─── Ingestion (records → stats + entities) ──────────────────────────────────

/// Parse `input` and build the full ingest result: stats, derived entities,
/// and centroid. `scan_id` is stamped on every entity; `source_label`
/// identifies the origin (file path or `web-upload`) in the JSON envelope.
pub fn ingest(input: &str, source_label: &str, scan_id: &str) -> KmlIngest {
    let doc = parse(input);
    let mut stats = KmlStats::default();
    let mut warnings = doc.warnings;

    // Accumulators ------------------------------------------------------------
    // Each `*_index` maps a dedup key → (entity slot, observation count). The
    // count is annotated onto the entity as `observations:N` after the pass;
    // it is deliberately NOT folded into `corroboration`, which means
    // "independent corroborating *sources*". One KML file is one source, so
    // every imported entity keeps `corroboration = 1` — repeated sightings
    // raise the observation tag, never the cross-source corroboration metric
    // (which would otherwise misfire the AU-003 high-corroboration rule).
    let mut entities: Vec<Entity> = Vec::new();
    let mut mac_index: HashMap<String, Slot> = HashMap::new();
    let mut carrier_index: HashMap<String, Slot> = HashMap::new();
    let mut cell_index: HashMap<String, Slot> = HashMap::new();
    let mut vendor_tally: HashMap<String, usize> = HashMap::new();
    let mut ssid_tally: HashMap<String, usize> = HashMap::new();
    let mut clusters: HashMap<String, ClusterAccum> = HashMap::new();
    let mut bbox: Option<BoundingBox> = None;
    let mut sum_lat = 0.0f64;
    let mut sum_lon = 0.0f64;
    let mut time_lo: Option<String> = None;
    let mut time_hi: Option<String> = None;

    for rec in &doc.records {
        let radio = RadioKind::from_type(&rec.raw_type);
        stats.total_records += 1;
        *stats
            .by_type
            .entry(rec.raw_type.clone().to_ascii_uppercase())
            .or_default() += 1;
        if let Some(enc) = &rec.encryption {
            *stats.by_encryption.entry(enc.clone()).or_default() += 1;
        }
        *stats
            .by_confidence
            .entry(rec.confidence.clone())
            .or_default() += 1;

        match radio {
            RadioKind::Wifi => stats.wifi += 1,
            RadioKind::Ble => stats.ble += 1,
            RadioKind::BtClassic => stats.bt += 1,
            RadioKind::Cellular => stats.cellular += 1,
            RadioKind::Unknown => stats.unknown += 1,
        }
        if rec.name.is_some() {
            stats.named_networks += 1;
        } else {
            stats.hidden_networks += 1;
        }
        if let Some(v) = &rec.vendor {
            *vendor_tally.entry(v.clone()).or_default() += 1;
        }
        if let Some(name) = &rec.name {
            *ssid_tally.entry(name.clone()).or_default() += 1;
        }

        // Geo aggregates
        sum_lat += rec.lat;
        sum_lon += rec.lon;
        bbox = Some(match bbox {
            None => BoundingBox {
                min_lat: rec.lat,
                min_lon: rec.lon,
                max_lat: rec.lat,
                max_lon: rec.lon,
            },
            Some(b) => BoundingBox {
                min_lat: b.min_lat.min(rec.lat),
                min_lon: b.min_lon.min(rec.lon),
                max_lat: b.max_lat.max(rec.lat),
                max_lon: b.max_lon.max(rec.lon),
            },
        });
        if let Some(t) = &rec.observed_at {
            if time_lo.as_ref().is_none_or(|lo| t < lo) {
                time_lo = Some(t.clone());
            }
            if time_hi.as_ref().is_none_or(|hi| t > hi) {
                time_hi = Some(t.clone());
            }
        }

        // Coordinate clustering. Geohash is a prefix code, so the precision-7
        // cluster key is simply the first 7 chars of the precision-8 geohash we
        // already computed for the record — no second geohash pass.
        let gh = rec
            .geohash
            .get(..CLUSTER_GEOHASH_PRECISION as usize)
            .unwrap_or(rec.geohash.as_str());
        let c = clusters.entry(gh.to_string()).or_default();
        c.add(rec);

        // Identity / device entities
        if rec.is_mac {
            upsert_mac_entity(&mut entities, &mut mac_index, rec, radio, scan_id);
        } else if matches!(radio, RadioKind::Cellular) {
            upsert_cell_entities(
                &mut entities,
                &mut carrier_index,
                &mut cell_index,
                rec,
                scan_id,
            );
        }
    }

    // Annotate observation counts as tags (e.g. a cell tower seen 40 times →
    // `observations:40`). Done before clusters are appended so the recorded
    // entity indices stay valid.
    annotate_observations(&mut entities, &mac_index);
    annotate_observations(&mut entities, &cell_index);
    annotate_observations(&mut entities, &carrier_index);

    // Centroid -----------------------------------------------------------------
    let centroid = if stats.total_records > 0 {
        Some(Centroid {
            lat: sum_lat / stats.total_records as f64,
            lon: sum_lon / stats.total_records as f64,
        })
    } else {
        None
    };

    // Coordinate-cluster entities (bounded) -----------------------------------
    let mut cluster_vec: Vec<(String, ClusterAccum)> = clusters.into_iter().collect();
    cluster_vec.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(&b.0)));
    if cluster_vec.len() > MAX_COORD_CLUSTERS {
        warnings.push(format!(
            "coordinate clusters capped at {MAX_COORD_CLUSTERS} (of {}); densest kept — every raw point remains in `records`",
            cluster_vec.len()
        ));
    }
    stats.coordinate_clusters = cluster_vec.len().min(MAX_COORD_CLUSTERS);
    for (gh, acc) in cluster_vec.into_iter().take(MAX_COORD_CLUSTERS) {
        entities.push(acc.into_entity(&gh, scan_id));
    }

    // Final stats --------------------------------------------------------------
    stats.unique_macs = mac_index.len();
    stats.unique_cell_towers = cell_index.len();
    stats.unique_carriers = carrier_index.len();
    // Surface (never hide) placemarks that didn't yield a record — no fix,
    // null-island, or malformed. Denominator = raw `<Placemark>` opens.
    stats.skipped_records = doc_records_len(input).saturating_sub(stats.total_records);
    stats.top_vendors = top_n(vendor_tally, 25);
    stats.top_ssids = top_n(ssid_tally, 25);
    stats.bounding_box = bbox;
    stats.time_range = match (time_lo, time_hi) {
        (Some(earliest), Some(latest)) => Some(TimeRange { earliest, latest }),
        _ => None,
    };
    if let Some(c) = centroid {
        if let Some(iso) = geohash::reverse_country_iso(c.lat, c.lon) {
            stats.country_iso = Some(iso.to_string());
            stats.country_name = geohash::country_name_for_iso(iso).map(str::to_string);
        }
        stats.timezone = Some(geohash::timezone_for(c.lat, c.lon).to_string());
    }

    let entity_count = entities.len();
    let suggested_target = centroid.map(|c| format!("{:.6},{:.6}", c.lat, c.lon));

    KmlIngest {
        source_label: source_label.to_string(),
        document_name: doc.document_name,
        record_count: stats.total_records,
        entity_count,
        centroid,
        suggested_target,
        stats,
        entities,
        records: doc.records,
        warnings,
        generated_at: crate::core::entity::unix_now(),
    }
}

/// Count `<Placemark>` opens in the raw input (denominator for skip stats).
fn doc_records_len(input: &str) -> usize {
    input.matches("<Placemark>").count()
}

// ─── Entity builders ─────────────────────────────────────────────────────────

/// Dedup slot: where the entity lives in the output vector + how many times it
/// was observed in this capture.
struct Slot {
    idx: usize,
    observations: u32,
}

/// Insert-or-merge a BSSID (`MacAddress`) entity. Repeated sightings of the
/// same MAC converge to one entity; the sighting count is tracked in the slot
/// (annotated later) and confidence rises to the strongest sighting.
/// `corroboration` is left at 1 — one file is one source.
fn upsert_mac_entity(
    entities: &mut Vec<Entity>,
    index: &mut HashMap<String, Slot>,
    rec: &KmlRecord,
    radio: RadioKind,
    scan_id: &str,
) {
    let conf = mac_confidence(radio, &rec.confidence);
    let normalised = normalise_mac(&rec.network_id);

    if let Some(slot) = index.get_mut(&normalised) {
        slot.observations = slot.observations.saturating_add(1);
        let e = &mut entities[slot.idx];
        if conf > e.confidence {
            e.confidence = conf;
        }
        if e.evidence.len() < MAX_EVIDENCE_PER_ENTITY {
            e.add_evidence(observation_evidence(rec));
        }
        return;
    }

    let mut e = Entity::new(EntityKind::MacAddress, &rec.network_id, conf, scan_id);
    e.tag("wigle-import");
    e.tag("kml-import");
    e.tag(radio.as_str());
    if let Some(enc) = &rec.encryption {
        e.tag(format!("enc:{enc}"));
    }
    if let Some(v) = &rec.vendor {
        e.tag(format!("vendor:{v}"));
    }
    if let Some(d) = &rec.device_class {
        e.tag(format!("device:{d}"));
    }
    if let Some(name) = &rec.name {
        e.tag(format!("ssid:{name}"));
    }
    e.tag(format!("confidence:{}", rec.confidence));
    e.add_evidence(observation_evidence(rec));
    index.insert(
        normalised,
        Slot {
            idx: entities.len(),
            observations: 1,
        },
    );
    entities.push(e);
}

/// Insert-or-merge the carrier `Organisation` and the cell-tower `DeviceId`
/// entities for one cellular observation. `corroboration` stays 1; sighting
/// counts ride in the slots.
fn upsert_cell_entities(
    entities: &mut Vec<Entity>,
    carrier_index: &mut HashMap<String, Slot>,
    cell_index: &mut HashMap<String, Slot>,
    rec: &KmlRecord,
    scan_id: &str,
) {
    // Carrier organisation
    if let Some(name) = &rec.name {
        let key = name.to_ascii_lowercase();
        if let Some(slot) = carrier_index.get_mut(&key) {
            slot.observations = slot.observations.saturating_add(1);
        } else {
            let mut org = Entity::new(EntityKind::Organisation, name, 0.60, scan_id);
            org.tag("wigle-import");
            org.tag("cell-carrier");
            if let Some(mcc) = &rec.mcc {
                org.tag(format!("mcc:{mcc}"));
            }
            if let Some(mnc) = &rec.mnc {
                org.tag(format!("mnc:{mnc}"));
            }
            org.add_evidence(
                Evidence::new(
                    SOURCE,
                    format!("Mobile carrier observed via {} cell", rec.raw_type),
                )
                .with_attr("plmn", rec.network_id.split('_').next().unwrap_or("")),
            );
            carrier_index.insert(
                key,
                Slot {
                    idx: entities.len(),
                    observations: 1,
                },
            );
            entities.push(org);
        }
    }

    // Cell tower device id
    if let Some(slot) = cell_index.get_mut(&rec.network_id) {
        slot.observations = slot.observations.saturating_add(1);
        let e = &mut entities[slot.idx];
        if e.evidence.len() < MAX_EVIDENCE_PER_ENTITY {
            e.add_evidence(observation_evidence(rec));
        }
    } else {
        let mut e = Entity::new(EntityKind::DeviceId, &rec.network_id, 0.55, scan_id);
        e.tag("wigle-import");
        e.tag("cell-tower");
        e.tag(format!("rat:{}", rec.raw_type));
        if let Some(mcc) = &rec.mcc {
            e.tag(format!("mcc:{mcc}"));
        }
        if let Some(mnc) = &rec.mnc {
            e.tag(format!("mnc:{mnc}"));
        }
        e.add_evidence(observation_evidence(rec));
        cell_index.insert(
            rec.network_id.clone(),
            Slot {
                idx: entities.len(),
                observations: 1,
            },
        );
        entities.push(e);
    }
}

/// Stamp an `observations:N` tag on every multiply-seen entity so the sighting
/// frequency is visible in the graph without inflating `corroboration`.
fn annotate_observations(entities: &mut [Entity], index: &HashMap<String, Slot>) {
    for slot in index.values() {
        if slot.observations > 1
            && let Some(e) = entities.get_mut(slot.idx)
        {
            e.tag(format!("observations:{}", slot.observations));
        }
    }
}

/// Build the evidence row for a single observation — coordinates, signal,
/// time, geohash, accuracy. Never contains secrets.
fn observation_evidence(rec: &KmlRecord) -> Evidence {
    let label = match &rec.name {
        Some(n) => format!("{} '{}' @ {:.5},{:.5}", rec.raw_type, n, rec.lat, rec.lon),
        None => format!("{} @ {:.5},{:.5}", rec.raw_type, rec.lat, rec.lon),
    };
    let mut ev = Evidence::new(SOURCE, label)
        .with_attr("network_id", &rec.network_id)
        .with_attr("lat", format!("{:.7}", rec.lat))
        .with_attr("lon", format!("{:.7}", rec.lon))
        .with_attr("geohash", &rec.geohash)
        .with_attr("confidence", &rec.confidence)
        .with_attr("radio", rec.radio);
    if let Some(s) = rec.signal_dbm {
        ev = ev.with_attr("signal_dbm", format!("{s}"));
    }
    if let Some(a) = rec.accuracy {
        ev = ev.with_attr("accuracy", format!("{a}"));
    }
    if let Some(t) = &rec.observed_at {
        ev = ev.with_attr("observed_at", t);
    }
    if let Some(enc) = &rec.encryption {
        ev = ev.with_attr("encryption", enc);
    }
    ev
}

/// Base confidence for a BSSID entity by radio + WiGLE style confidence.
fn mac_confidence(radio: RadioKind, style_conf: &str) -> f64 {
    match radio {
        RadioKind::Wifi => match style_conf {
            "high" => 0.80,
            "medium" => 0.62,
            "low" => 0.48,
            "zero" => 0.35,
            _ => 0.55,
        },
        RadioKind::Ble | RadioKind::BtClassic => 0.55,
        _ => 0.50,
    }
}

/// Normalise a MAC to lowercase colon form for dedup keying — mirrors
/// `core::entity::normalise(MacAddress, …)` so the dedup key matches the
/// entity UID's normalised value exactly.
fn normalise_mac(mac: &str) -> String {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if hex.len() == 12 {
        format!(
            "{}:{}:{}:{}:{}:{}",
            &hex[0..2],
            &hex[2..4],
            &hex[4..6],
            &hex[6..8],
            &hex[8..10],
            &hex[10..12]
        )
    } else {
        mac.trim().to_lowercase()
    }
}

/// Top-`n` `(key, count)` tallies, sorted by count desc then key asc.
fn top_n(map: HashMap<String, usize>, n: usize) -> Vec<Tally> {
    let mut v: Vec<Tally> = map
        .into_iter()
        .map(|(key, count)| Tally { key, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    v.truncate(n);
    v
}

// ─── Coordinate cluster accumulator ──────────────────────────────────────────

/// Running aggregate for one geohash cell while scanning records.
#[derive(Default)]
struct ClusterAccum {
    count: usize,
    sum_lat: f64,
    sum_lon: f64,
    types: BTreeMap<String, usize>,
    sample_ssids: Vec<String>,
    earliest: Option<String>,
    latest: Option<String>,
}

impl ClusterAccum {
    fn add(&mut self, rec: &KmlRecord) {
        self.count += 1;
        self.sum_lat += rec.lat;
        self.sum_lon += rec.lon;
        *self
            .types
            .entry(rec.raw_type.to_ascii_uppercase())
            .or_default() += 1;
        if let Some(name) = &rec.name
            && self.sample_ssids.len() < 8
            && !self.sample_ssids.contains(name)
        {
            self.sample_ssids.push(name.clone());
        }
        if let Some(t) = &rec.observed_at {
            if self.earliest.as_ref().is_none_or(|e| t < e) {
                self.earliest = Some(t.clone());
            }
            if self.latest.as_ref().is_none_or(|l| t > l) {
                self.latest = Some(t.clone());
            }
        }
    }

    fn into_entity(self, gh: &str, scan_id: &str) -> Entity {
        let lat = self.sum_lat / self.count as f64;
        let lon = self.sum_lon / self.count as f64;
        let value = format!("{lat:.6},{lon:.6}");
        // Density lifts confidence: a single stray point is weaker than a cell
        // hit hundreds of times. Capped at 0.90 — wardrive GPS isn't survey-grade.
        // `corroboration` stays 1 (one source: this capture); the observation
        // count rides in the `observations:N` tag + evidence, so the density is
        // visible without misfiring the high-corroboration correlation rule.
        let conf = (0.70 + (self.count as f64).ln() * 0.04).min(0.90);
        let mut e = Entity::new(EntityKind::Coordinates, &value, conf, scan_id);
        e.tag("wigle-import");
        e.tag("geoint");
        e.tag("wifi-observed");
        e.tag(format!("geohash:{gh}"));
        e.tag(format!("observations:{}", self.count));
        let types: Vec<String> = self.types.iter().map(|(k, v)| format!("{k}×{v}")).collect();
        let mut ev = Evidence::new(
            SOURCE,
            format!(
                "{} observations clustered in geohash {gh} ({})",
                self.count,
                types.join(", ")
            ),
        )
        .with_attr("geohash", gh)
        .with_attr("observations", self.count.to_string())
        .with_attr("lat", format!("{lat:.7}"))
        .with_attr("lon", format!("{lon:.7}"))
        .with_attr("timezone", geohash::timezone_for(lat, lon));
        if !self.sample_ssids.is_empty() {
            ev = ev.with_attr("sample_ssids", self.sample_ssids.join(", "));
        }
        if let (Some(e0), Some(e1)) = (&self.earliest, &self.latest) {
            ev = ev.with_attr("first_seen", e0).with_attr("last_seen", e1);
        }
        e.add_evidence(ev);
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A verbatim slice of a real WiGLE export (file 3bbc0d80-2025012700607.kml,
    // first two placemarks) plus one real cellular + one real BLE placemark.
    // Real records — no synthetic data.
    const REAL_KML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
    <Document>
        <name>WiGLE_Upload-20250127-00607</name>
        <Placemark>
            <name>544xanTRU19</name>
            <description>Network ID: 00:03:16:00:8A:AC
Encryption: WPA2
Time: 2025-01-27T08:21:17.000-08:00
Signal: -89.0
Accuracy: 5.04279
Type: WIFI</description>
            <styleUrl>#highConfidence</styleUrl>
            <Point><coordinates>152.95878601,-26.94807434</coordinates></Point>
        </Placemark>
        <Placemark>
            <name>Trey&amp;Fefe</name>
            <description>Network ID: 00:04:56:AF:FE:A0
Encryption: WPA3
Time: 2025-01-27T07:36:39.000-08:00
Signal: -90.0
Accuracy: 4.81637
Type: WIFI</description>
            <styleUrl>#highConfidence</styleUrl>
            <Point><coordinates>153.03323364,-27.41077232</coordinates></Point>
        </Placemark>
        <Placemark>
            <name>(no SSID)</name>
            <description>Network ID: 00:01:74:60:6D:47
Time: 2024-10-13T06:59:10.000-07:00
Signal: -95.0
Accuracy: 21.5187
Type: BLE
Attributes: Misc</description>
            <styleUrl>#bluetoothLe</styleUrl>
            <Point><coordinates>152.90296936,-27.67771721</coordinates></Point>
        </Placemark>
        <Placemark>
            <name>Telstra Corporation Limited</name>
            <description>Network ID: 50501_28674_147165965
Time: 2025-01-17T02:45:36.000-08:00
Signal: -113.0
Accuracy: 0.844652
Type: LTE</description>
            <styleUrl>#cell</styleUrl>
            <Point><coordinates>152.99046326,-27.42411613</coordinates></Point>
        </Placemark>
    </Document>
</kml>"#;

    #[test]
    fn parses_document_name_and_all_records() {
        let doc = parse(REAL_KML);
        assert_eq!(
            doc.document_name.as_deref(),
            Some("WiGLE_Upload-20250127-00607")
        );
        assert_eq!(doc.records.len(), 4, "all four placemarks parse");
        assert!(
            doc.warnings.is_empty(),
            "clean file → no warnings: {:?}",
            doc.warnings
        );
    }

    #[test]
    fn coordinate_order_is_lon_lat() {
        let doc = parse(REAL_KML);
        let r = &doc.records[0];
        // lon first in KML, lat second — must not be swapped.
        assert!((r.lon - 152.95878601).abs() < 1e-6, "lon");
        assert!((r.lat - -26.94807434).abs() < 1e-6, "lat");
        assert!(r.lat < 0.0 && r.lon > 150.0, "Queensland AU quadrant");
    }

    #[test]
    fn xml_entities_in_ssid_are_decoded() {
        let doc = parse(REAL_KML);
        assert_eq!(doc.records[1].name.as_deref(), Some("Trey&Fefe"));
    }

    #[test]
    fn hidden_ssid_sentinel_becomes_none() {
        let doc = parse(REAL_KML);
        assert_eq!(doc.records[2].name, None, "(no SSID) → None");
        assert_eq!(doc.records[2].radio, "ble");
    }

    #[test]
    fn wifi_fields_fully_parsed() {
        let doc = parse(REAL_KML);
        let r = &doc.records[0];
        assert_eq!(r.network_id, "00:03:16:00:8A:AC");
        assert_eq!(r.radio, "wifi");
        assert_eq!(r.encryption.as_deref(), Some("WPA2"));
        assert_eq!(r.signal_dbm, Some(-89.0));
        assert_eq!(r.accuracy, Some(5.04279));
        assert_eq!(r.confidence, "high");
        assert!(r.is_mac, "colon-separated 48-bit address is a MAC");
        // OUI 00:03:16 is outside the curated vendor table, so de-noising
        // leaves vendor/device_class None (we don't fabricate "Unknown").
        assert_eq!(r.vendor, None);
        assert_eq!(r.device_class, None);
        assert_eq!(r.geohash.len(), RECORD_GEOHASH_PRECISION as usize);
    }

    #[test]
    fn cellular_plmn_split_into_mcc_mnc() {
        let doc = parse(REAL_KML);
        let cell = &doc.records[3];
        assert_eq!(cell.radio, "cellular");
        assert!(!cell.is_mac);
        assert_eq!(cell.mcc.as_deref(), Some("505"), "MCC 505 = Australia");
        assert_eq!(cell.mnc.as_deref(), Some("01"), "MNC 01 = Telstra");
    }

    #[test]
    fn ingest_builds_entities_stats_and_centroid() {
        let ing = ingest(REAL_KML, "unit-test", "scan-kml-test");
        assert_eq!(ing.record_count, 4);
        assert_eq!(ing.stats.wifi, 2);
        assert_eq!(ing.stats.ble, 1);
        assert_eq!(ing.stats.cellular, 1);
        assert_eq!(ing.stats.unique_macs, 3, "2 wifi + 1 ble BSSIDs");
        assert_eq!(ing.stats.unique_carriers, 1, "Telstra");
        assert_eq!(ing.stats.unique_cell_towers, 1);
        assert_eq!(ing.stats.by_encryption.get("WPA2"), Some(&1));
        assert_eq!(ing.stats.by_encryption.get("WPA3"), Some(&1));
        assert!(ing.centroid.is_some());
        assert_eq!(ing.stats.country_iso.as_deref(), Some("AU"));
        // entities: 3 MAC + 1 carrier org + 1 cell device + ≥1 coord cluster
        assert!(ing.entity_count >= 6, "got {}", ing.entity_count);
        assert!(
            ing.entities
                .iter()
                .any(|e| e.kind == EntityKind::Coordinates),
            "must emit clustered Coordinates"
        );
        assert!(
            ing.entities
                .iter()
                .any(|e| e.kind == EntityKind::Organisation && e.value.contains("Telstra")),
            "carrier org present"
        );
    }

    #[test]
    fn repeated_bssid_merges_and_counts_corroboration() {
        // Two observations of the same BSSID at different spots → one entity,
        // corroboration 2.
        let kml = REAL_KML
            .replace("153.03323364,-27.41077232", "152.95878601,-26.94807434")
            .replace("00:04:56:AF:FE:A0", "00:03:16:00:8A:AC");
        let ing = ingest(&kml, "unit-test", "s");
        let mac = ing
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::MacAddress && e.value == "00:03:16:00:8a:ac")
            .expect("merged BSSID entity");
        // One source (this file) → corroboration stays 1; the sighting count
        // rides in the observations tag so AU-003 can't misfire.
        assert_eq!(mac.corroboration, 1, "single source → corroboration 1");
        assert!(
            mac.tags.iter().any(|t| t == "observations:2"),
            "two sightings → observations:2 tag, got {:?}",
            mac.tags
        );
    }

    #[test]
    fn malformed_placemark_is_warned_not_panicked() {
        let bad = "<Placemark><name>x</name><Point></Point></Placemark>";
        let doc = parse(bad);
        assert_eq!(doc.records.len(), 0);
        assert_eq!(doc.warnings.len(), 1);
    }

    #[test]
    fn empty_input_is_clean() {
        let doc = parse("");
        assert!(doc.records.is_empty());
        assert!(doc.document_name.is_none());
    }

    #[test]
    fn null_island_coordinates_rejected() {
        assert_eq!(parse_coordinates("0,0"), None);
        assert_eq!(parse_coordinates("0.0,0.0"), None);
        assert_eq!(parse_coordinates("152.9,-26.9"), Some((152.9, -26.9)));
    }
}
