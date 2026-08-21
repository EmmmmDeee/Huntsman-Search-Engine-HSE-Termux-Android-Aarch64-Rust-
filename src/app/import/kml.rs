//! Parser for WiGLE-style KML wardriving exports — the native output of the
//! WiGLE Android app's "export to KML", and therefore the one artifact an
//! on-device wardriving session actually produces.
//!
//! The engine could already *query* the WiGLE API but could not ingest the file
//! its own capture device writes, so a survey run offline (or over a quota the
//! `wigle` module refuses to spend) had nowhere to go.
//!
//! ## Format, as actually emitted
//!
//! Every observation is one `<Placemark>`:
//!
//! ```text
//! <Placemark>
//!   <name>(no SSID)</name>
//!   <description>Network ID: 2C:8D:48:46:33:07Encryption: WPA2Time: …Signal: -82.0Accuracy: 3.4Type: WIFI</description>
//!   <Point><coordinates>153.08647156,-26.81446838</coordinates></Point>
//! </Placemark>
//! ```
//!
//! Two properties of real exports drive the whole parser and are not guesses —
//! they were read out of the byte stream of four files off the capture device:
//!
//! 1. **The document can contain no newlines at all.** A line-oriented parser
//!    extracts precisely nothing. Everything here is offset-based.
//! 2. **The `<description>` fields are run together with no separator.** The
//!    value of one field abuts the label of the next (`…33:07Encryption: WPA2`),
//!    so fields are located by scanning for the known labels and slicing between
//!    them. Splitting on `:` is doubly wrong: the `Network ID` value is a MAC
//!    address and contains five colons of its own.
//!
//! ## Ordering
//!
//! Placemarks are emitted in document order and each placemark's entities in a
//! fixed order (BSSID, SSID, coordinates), so the same file always yields the
//! same graph — the determinism invariant, which a `HashMap` pass over the
//! fields would have broken.

use super::ImportStats;
use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind, Evidence};

const SRC: &str = "import:kml";

/// WiGLE's placeholder `<name>` for a network that broadcast no SSID. It is not
/// a network name and must never become an [`EntityKind::Ssid`].
const NO_SSID_PLACEHOLDER: &str = "(no SSID)";

/// Field labels inside a WiGLE `<description>`. Order here is irrelevant — the
/// parser sorts by the offset each label is found at — but the set must stay
/// aligned with what the app emits, since an unknown label is not a delimiter
/// and its text is swallowed into the preceding field's value.
const DESC_FIELDS: &[&str] = &[
    "Network ID",
    "Encryption",
    "Time",
    "Signal",
    "Accuracy",
    "Type",
];

/// The radio a placemark's `Type:` names, which decides how its `Network ID` and
/// `<name>` are read.
///
/// The distinction is not cosmetic. A Wi-Fi `<name>` is a network SSID and is
/// searchable in WiGLE; a Bluetooth `<name>` is a device name and is not, so
/// minting one as an [`EntityKind::Ssid`] would dispatch a meaningless lookup.
/// A cellular `Network ID` is an `MCC_MNC_LAC_CID` tuple, not a MAC, and must
/// never be attributed to a hardware vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RadioKind {
    Wifi,
    Bluetooth,
    Cellular,
    Unknown,
}

/// Classify a WiGLE `Type:` value.
///
/// Matched by prefix because the app writes `BLEAttributes` / `BTAttributes`,
/// not bare `BLE` / `BT` — an equality test against the short forms silently
/// classified every Bluetooth observation as `Unknown`.
fn radio_kind(raw: &str) -> RadioKind {
    let t = raw.trim().to_ascii_uppercase();
    if t.starts_with("WIFI") || t == "W" {
        RadioKind::Wifi
    } else if t.starts_with("BLE") || t.starts_with("BT") {
        RadioKind::Bluetooth
    } else if ["GSM", "LTE", "NR", "CDMA", "WCDMA", "UMTS"]
        .iter()
        .any(|c| t.starts_with(c))
    {
        RadioKind::Cellular
    } else {
        RadioKind::Unknown
    }
}

/// Extract the text of the first `<tag>…</tag>` in `hay`, XML-entity-decoded.
///
/// Deliberately not a general XML parser: a KML placemark is a flat, generated
/// fragment with no attributes on the tags we read and no CDATA, and pulling in
/// a full parser to read three known tags would be a far larger trusted surface
/// than the format warrants. Returns `None` rather than a partial value when the
/// closing tag is absent, so a truncated document fails closed.
fn tag_text(hay: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = hay.find(&open)? + open.len();
    let end = hay[start..].find(&close)? + start;
    // XML's five predefined entities are a subset of HTML's, and numeric
    // character references are identical, so the existing decoder is correct
    // here; a second near-identical unescaper is exactly the divergent
    // duplication that leaves one copy hardened and its twin stale.
    Some(crate::util::html::decode_entities(&hay[start..end]))
}

/// Split a run-together WiGLE `<description>` into `(label, value)` pairs.
///
/// Locates every known label, sorts the hits by offset, and slices each value
/// from the end of its own label to the start of the next. This is what makes a
/// separator-free description parseable at all, and it is why a MAC address in
/// the `Network ID` value survives intact.
///
/// A label is recognised only when followed by `": "`, so the bare word
/// "Signal" inside an SSID cannot fabricate a field boundary. All offsets land
/// on label boundaries, which are ASCII, so the slicing is UTF-8 safe even when
/// an SSID contains multi-byte characters.
fn description_fields(desc: &str) -> Vec<(&'static str, String)> {
    let mut marks: Vec<(usize, &'static str)> = DESC_FIELDS
        .iter()
        .filter_map(|&f| desc.find(&format!("{f}: ")).map(|pos| (pos, f)))
        .collect();
    // Sort by offset, then by label, so two labels found at the same offset
    // (impossible in a well-formed document, but not worth an unstable order)
    // still resolve identically on every run.
    marks.sort_unstable();

    let mut out = Vec::with_capacity(marks.len());
    for (i, &(pos, label)) in marks.iter().enumerate() {
        let start = pos + label.len() + ": ".len();
        let end = marks.get(i + 1).map_or(desc.len(), |&(p, _)| p);
        if start <= end {
            out.push((label, desc[start..end].trim().to_string()));
        }
    }
    out
}

/// Parse a KML `<coordinates>` body into `(lat, lon)`.
///
/// KML orders a coordinate tuple **`lon,lat[,alt]`** — the opposite of the
/// `lat,lon` this engine stores in an [`EntityKind::Coordinates`] value. Swapping
/// here, once, is the whole reason this is a named function: a transposed pair
/// is still a valid coordinate, so the mistake produces a plausible location in
/// the wrong hemisphere rather than an error anyone would notice.
///
/// Rejects out-of-range values and the null island (0,0), which is what a
/// device with no GPS fix reports.
fn parse_coordinates(raw: &str) -> Option<(f64, f64)> {
    let mut parts = raw.trim().split(',');
    let lon: f64 = parts.next()?.trim().parse().ok()?;
    let lat: f64 = parts.next()?.trim().parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    // A GPS-less capture reports exactly 0,0; treating it as a location would
    // pin every such observation off the coast of Africa.
    if lat == 0.0 && lon == 0.0 {
        return None;
    }
    Some((lat, lon))
}

/// Parse a WiGLE KML export into entities.
///
/// Emits, per placemark: the hardware address as an [`EntityKind::MacAddress`]
/// carrying the same OUI vendor/device-class/trackability tags the live radar
/// attaches (`crate::modules::signal_radar::wifi` for an access point,
/// `::bluetooth` for a BT/BLE device), so an imported observation and a sensed
/// one are indistinguishable downstream; a Wi-Fi network name as an
/// [`EntityKind::Ssid`]; and the fix as [`EntityKind::Coordinates`].
pub(super) fn parse_kml(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();

    for placemark in body.split("<Placemark>").skip(1) {
        // Bound each placemark at its own closing tag so a malformed document
        // cannot let one record's fields bleed into the next.
        let pm = placemark
            .find("</Placemark>")
            .map_or(placemark, |end| &placemark[..end]);

        let fields = tag_text(pm, "description")
            .map(|d| description_fields(&d))
            .unwrap_or_default();
        let field = |k: &str| {
            fields
                .iter()
                .find(|(label, _)| *label == k)
                .map(|(_, v)| v.as_str())
        };

        let kind = field("Type").unwrap_or_default().to_ascii_uppercase();
        let radio = radio_kind(&kind);
        let name = tag_text(pm, "name").unwrap_or_default();
        let ssid = name.trim();
        let coords = tag_text(pm, "coordinates").and_then(|c| parse_coordinates(&c));

        // Shared evidence: the full observation at the precision the capture
        // device recorded it, including the signal and accuracy readings that
        // the entity values themselves have no room for.
        let mut ev = Evidence::new(
            SRC,
            format!(
                "Wardriving observation ({}) — {}",
                if kind.is_empty() { "unknown" } else { &kind },
                if ssid.is_empty() || ssid == NO_SSID_PLACEHOLDER {
                    "hidden network"
                } else {
                    ssid
                }
            ),
        );
        for (label, value) in &fields {
            ev = ev.with_attr(label.to_ascii_lowercase().replace(' ', "_"), value);
        }
        // The `<name>` is the only field that is NOT in the description, and for
        // a Bluetooth record it is the device name — the single most
        // identifying thing in the observation ("Jane's AirPods"). It gets no
        // entity of its own below, so without this it would be lost entirely.
        if !ssid.is_empty() && ssid != NO_SSID_PLACEHOLDER {
            ev = ev.with_attr("name", ssid);
        }
        if let Some((lat, lon)) = coords {
            ev = ev
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string());
        }

        // ── Hardware address ─────────────────────────────────────────────────
        // Gated on `normalize_bssid` succeeding, NOT on the radio type: a
        // Bluetooth/BLE `Network ID` is every bit as much a real MAC as a Wi-Fi
        // BSSID, carries an OUI, and is exactly what the BLE radar analyses —
        // filtering to Wi-Fi discarded ~31% of a real capture. A cellular
        // `Network ID` is an `MCC_MNC_LAC_CID` tuple, which the MAC validation
        // rejects on its own, so no type test is needed to keep towers out.
        if let Some(id) = field("Network ID")
            && let Some(mac) = normalize_bssid(id)
            && seen.insert(format!("mac:{mac}"))
        {
            let mut e = Entity::new(EntityKind::MacAddress, &mac, confidence::MEDIUM_HIGH, sid);
            e.tag("import");
            e.tag("kml");
            e.tag("geolocatable");
            match radio {
                RadioKind::Wifi => {
                    e.tag("bssid");
                    e.tag(crate::core::tags::WIFI_AP);
                }
                // Mirrors `signal_radar::bluetooth`, so a device imported from a
                // wardrive and one sensed live carry the same tags.
                RadioKind::Bluetooth => {
                    e.tag("bluetooth");
                    e.tag(format!("bt-{}", kind.to_lowercase()));
                }
                RadioKind::Cellular | RadioKind::Unknown => {}
            }

            let mut mev = ev.clone();
            // OUI classification, mirroring the live Wi-Fi radar path exactly
            // (`signal_radar::wifi`): attribute a real hardware BSSID to its
            // vendor, or mark a locally-administered one `randomized`. A
            // randomized BSSID is a rotating privacy address, not a fixed access
            // point, and must never be treated as a trackable pin.
            if let Some(oui) = crate::util::oui::classify_mac(&mac) {
                e.tag(format!("vendor:{}", oui.vendor));
                e.tag(format!("device:{}", oui.class.as_str()));
                let trackable = crate::util::oui::is_locally_administered(&mac) == Some(false);
                e.tag(if trackable { "trackable" } else { "randomized" });
                mev = mev
                    .with_attr("vendor", oui.vendor)
                    .with_attr("device_class", oui.class.as_str())
                    .with_attr("trackable", trackable.to_string());
            }
            e.add_evidence(mev);
            entities.push(e);
            stats.bssids += 1;
        }

        // ── SSID ─────────────────────────────────────────────────────────────
        // Wi-Fi only. A Bluetooth `<name>` is a device name, not a network name:
        // it is not searchable in WiGLE, so minting it as an Ssid would queue a
        // lookup that cannot succeed and spend the geo budget doing it. It is
        // preserved as the `name` evidence attribute above instead.
        //
        // Generic/default names are kept as entities but filtered at dispatch
        // time by `wigle`'s own `is_generic_ssid` gate, exactly as the live
        // radar leaves that decision to the dispatcher.
        if radio == RadioKind::Wifi
            && !ssid.is_empty()
            && ssid != NO_SSID_PLACEHOLDER
            && seen.insert(format!("ssid:{}", ssid.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Ssid, ssid, confidence::MEDIUM_PLUS, sid);
            e.tag("import");
            e.tag("kml");
            e.tag("wifi-network");
            e.tag(crate::core::tags::WIFI_AP);
            e.add_evidence(ev.clone());
            entities.push(e);
            stats.ssids += 1;
        }

        // ── Coordinates ──────────────────────────────────────────────────────
        if let Some((lat, lon)) = coords {
            // Six decimals, matching what `normalize_value` canonicalises a
            // Coordinates entity to, so the dedup key here and the stored value
            // agree. Deliberately NOT the 4dp the IP-geolocation import path
            // uses: that is generous for a city-level GEOIP guess but would
            // throw away ~11m of real precision from a GPS fix and merge
            // genuinely distinct access points into one node.
            let value = format!("{lat:.6},{lon:.6}");
            if seen.insert(format!("geo:{value}")) {
                let mut e =
                    Entity::new(EntityKind::Coordinates, &value, confidence::HIGH_PLUS, sid);
                e.tag("import");
                e.tag("kml");
                e.tag("geoint");
                e.add_evidence(ev.clone());
                entities.push(e);
                stats.coordinates += 1;
            }
        }
    }

    (entities, stats)
}

/// Canonicalise a WiGLE `Network ID` to a lowercase colon-separated MAC, or
/// `None` if it is not one.
///
/// WiGLE writes BSSIDs uppercase; the engine's other MAC producers write them
/// lowercase, and an entity's identity is its value — so without folding here,
/// the same access point imported from KML and seen by the radar would be two
/// unrelated nodes in the graph.
fn normalize_bssid(raw: &str) -> Option<String> {
    let mac = raw.trim().to_ascii_lowercase();
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() != 6
        || !octets
            .iter()
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(mac)
}

/// Heuristic: is this body a KML document?
///
/// Keyed on the OGC namespace or the root element, never on the `.kml`
/// extension — the same content-not-filename rule every other detector here
/// follows, so a wardriving export imports correctly whatever it is named.
pub(super) fn looks_like_kml(head: &str) -> bool {
    head.contains("<kml") || head.contains("opengis.net/kml")
}

/// CLI entry: parse a WiGLE KML export and persist it as a completed scan.
pub(super) async fn cmd_import_kml(body: &str, output: &str) -> crate::core::error::Result<()> {
    use super::{
        deduplicate_by_uid, note, persist_and_report, print_import_stats, render_import_entities,
    };
    note(output, "Importing WiGLE KML wardriving export...");
    let sid = format!("import-kml-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_kml(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);

    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("kml_tests.rs");
}
