//! End-to-end front-end for `huntsman-recon network` and the network arm of `scan`.
//!
//! A network selector is a BSSID (`aa:bb:cc:dd:ee:ff`), a coordinate pair (`LAT,LON`) or an
//! SSID (`ssid:NAME`, or any other text when the kind is named), or a cell site
//! (`cell:MCC:MNC:AREA:CELL`), which the `OpenCelliD` indicator leg looks up; a coordinate pair is
//! also searched for the cell sites `OpenCelliD` lists around it. A BSSID is first classified
//! offline: its OUI vendor and whether it is a randomised (locally administered) address. Then
//! the keyed `WiGLE` legs ([`crate::wigle`]) search for what the selector names: `WiFi` always,
//! and Bluetooth too for a MAC address or a place. Without
//! both `WiGLE` slots it makes no request and records `NotConfigured`, never a zero.
//!
//! Each network `WiGLE` returns becomes a BSSID entity carrying what `WiGLE` records about it,
//! and its SSID and trilaterated position become pivots. Everything flows through
//! `merge_by_uid`, `lookup_report` (lineage) and `lookup_save`.
//!
//! A lookup nothing answered is not printed when a search was refused or got no response: a
//! search refused before sending (by the egress policy, or a credential that cannot be sent)
//! is [`NetworkRun::Network`] (exit 77), and one that got no response is
//! [`NetworkRun::Failed`] (exit 69), as the CLI's exit codes say. A search `WiGLE` answered
//! with an error (a rate limit, a rejected key) or that had no credentials to send is a row of
//! the printed report.

use std::path::PathBuf;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::indicator_legs;
use crate::indicator_sources::Indicator;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::opencellid;
use crate::oui;
use crate::scan_route::{CELL_PREFIX, NetworkSelector, network_selector};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceRun};
use crate::tags;
use crate::textnorm::escape_controls;
use crate::wigle::{self, Database, WigleError};

pub const NETWORK_USAGE: &str =
    "usage: huntsman-recon network BSSID|LAT,LON|ssid:NAME|cell:MCC:MNC:AREA:CELL [--save FILE]";
pub const NETWORK_HELP: &str = "\
network BSSID|LAT,LON|ssid:NAME|cell:MCC:MNC:AREA:CELL [--save FILE]
Look up a WiFi network, or a cell site. A cell site (cell:505:01:17:91, the country, network, area and cell numbers radar cells reports) is looked up in OpenCelliD, which gives the tower's position, range and sample count; it needs HUNTSMAN_OPENCELLID_KEY, and without it makes no request and reports not_configured. WiGLE is not searched for a cell site. With the same key, LAT,LON also lists the cell sites OpenCelliD places in the 1.8 km square around the point (at most 50, one request), each a cell: selector network takes back; they are sites near the point, not ones any device there used. A BSSID (aa:bb:cc:dd:ee:ff) is classified offline first: its OUI vendor and whether it is a randomised address. Then WiGLE search runs: a BSSID searches WiGLE's WiFi and Bluetooth databases for that address, ssid:NAME searches WiFi networks with exactly that name, and LAT,LON searches both databases in a box of about 220 m around the point, nearest first. WiGLE needs HUNTSMAN_WIGLE_USER (the API Name) and HUNTSMAN_WIGLE_TOKEN (the API Token) from https://wigle.net/account in the environment; without them it makes no request and reports not_configured. Each search spends one of the account's daily WiGLE queries, so a BSSID or LAT,LON spends two. credential-status --probe checks the credentials without spending one. Results are lineage-rendered entities, then wigle_networks=N (none when WiGLE gave no answer) and one wigle_network row per network: SSID, encryption, channel, position, first and last seen, and the street address WiGLE gives the position; for a BSSID or LAT,LON, then wigle_bluetooth_devices=N and one wigle_bluetooth row per device: name, radio (bt or ble), device class, position, first and last seen, address. --save FILE writes an unverified ledger that verify can reload.";

/// Source label for the offline OUI classification of a BSSID selector.
pub const OUI_SOURCE: &str = "oui";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    /// The `WiFi` networks `WiGLE` returned. `None` when that search gave no answer (no
    /// credentials, or a failed request), which is not a zero.
    pub wigle: Option<Vec<wigle::Network>>,
    /// The Bluetooth devices `WiGLE` returned, on the same terms.
    pub wigle_bluetooth: Option<Vec<wigle::Network>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkArgs {
    pub selector: String,
    pub save: Option<PathBuf>,
}

impl NetworkArgs {
    /// # Errors
    /// Invalid or missing selector, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(
            args,
            "network needs exactly one BSSID, LAT,LON, ssid:NAME or cell:MCC:MNC:AREA:CELL",
        )?;
        let selector = network_selector(&raw)
            .ok_or_else(|| Error::invalid_value("invalid network selector"))?;
        Ok(Self { selector, save })
    }
}

/// The first `WiGLE` search refused before sending, and the first that got no response.
#[derive(Debug, Default)]
struct Unanswered {
    refused: Option<String>,
    no_response: Option<String>,
}

pub type NetworkRun = SourceRun<Report>;

/// Classify the selector and run each `WiGLE` search it calls for when `wigle` carries a
/// transport and keys. A transport whose lookup does not ask `wigle`
/// ([`Transport::runs_module`]) sends no search and leaves no `WiGLE` row.
#[must_use]
pub fn run(wigle: Option<(&dyn Transport, &Keys)>, selector: &str, now_unix: u64) -> NetworkRun {
    let Some(selector) = NetworkSelector::parse(selector) else {
        return NetworkRun::Failed("invalid network selector".into());
    };
    let canonical = selector.canonical();
    let scan_id = crate::entity::scan_id("network", &canonical);
    let mut report = Report {
        entities: vec![seed_entity(&selector, &scan_id)],
        ..Report::default()
    };
    if let NetworkSelector::Bssid(bssid) = &selector {
        report
            .outcomes
            .push(oui_leg(bssid, &scan_id, now_unix, &mut report.entities));
    }
    let mut unanswered = Unanswered::default();
    for &database in Database::for_selector(&selector) {
        let outcome = match wigle {
            Some((transport, _)) if !transport.runs_module(wigle::SOURCE) => continue,
            Some((transport, keys)) if wigle::configured(keys) => wigle_leg(
                transport,
                keys,
                database,
                &selector,
                &scan_id,
                now_unix,
                &mut report,
                &mut unanswered,
            ),
            _ => SourceExecutionOutcome::failed(
                database.source(),
                now_unix,
                SourceOutcomeKind::NotConfigured,
                None,
                format!(
                    "no WiGLE credentials configured ({} and {}); no request made",
                    wigle::USER_SLOT,
                    wigle::TOKEN_SLOT
                ),
            ),
        };
        report.outcomes.push(outcome);
    }
    // A cell site is looked up by the indicator legs that take one (OpenCelliD, when its key is
    // set), as the ip, domain, email and phone lookups run theirs. Without the key it makes no
    // request and records `NotConfigured`, never a zero.
    if matches!(selector, NetworkSelector::Cell { .. }) {
        let indicator = canonical.strip_prefix(CELL_PREFIX).unwrap_or(&canonical);
        match wigle {
            Some((transport, _)) if !transport.runs_module(opencellid::SOURCE) => {}
            Some((transport, keys)) if keys.get(opencellid::KEY_SLOT).is_some() => {
                let legs = indicator_legs::run(
                    transport,
                    keys,
                    Indicator::Cell(indicator),
                    &scan_id,
                    now_unix,
                );
                report.entities.extend(legs.entities);
                report.outcomes.extend(legs.outcomes);
            }
            _ => report.outcomes.push(opencellid_not_configured(now_unix)),
        }
    }
    // A point is searched for the cell sites OpenCelliD lists around it, under the same key.
    if let NetworkSelector::Area { lat, lon } = selector {
        match wigle {
            Some((transport, _)) if !transport.runs_module(opencellid::SOURCE) => {}
            Some((transport, keys)) if keys.get(opencellid::KEY_SLOT).is_some() => {
                let outcome =
                    area_cells_leg(transport, keys, (lat, lon), &scan_id, now_unix, &mut report);
                report.outcomes.push(outcome);
            }
            _ => report.outcomes.push(opencellid_not_configured(now_unix)),
        }
    }
    merge_by_uid(&mut report.entities);

    if !report.outcomes.iter().any(|o| o.kind.is_accepted()) {
        if let Some(message) = unanswered.refused {
            return NetworkRun::Network(message);
        }
        if let Some(why) = unanswered.no_response {
            return NetworkRun::Failed(format!("no source answered the network lookup: {why}"));
        }
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(mut text) => {
            if Database::for_selector(&selector).contains(&Database::Wifi) {
                text.push_str(&render_wigle(Database::Wifi, report.wigle.as_deref()));
            }
            if Database::for_selector(&selector).contains(&Database::Bluetooth) {
                text.push_str(&render_wigle(
                    Database::Bluetooth,
                    report.wigle_bluetooth.as_deref(),
                ));
            }
            NetworkRun::Printed { text, report }
        }
        Err(msg) => NetworkRun::Failed(msg),
    }
}

/// The row an `OpenCelliD` search leaves when its key is not set: no request, never a zero.
fn opencellid_not_configured(now_unix: u64) -> SourceExecutionOutcome {
    SourceExecutionOutcome::failed(
        opencellid::SOURCE,
        now_unix,
        SourceOutcomeKind::NotConfigured,
        None,
        format!(
            "no OpenCelliD key configured ({}); no request made",
            opencellid::KEY_SLOT
        ),
    )
}

/// The cell sites `OpenCelliD` lists in the square around a point: each a `cell:` entity a
/// `network` lookup takes back, with its position, radio, range and sample count as evidence.
/// They are sites near the point, not ones any device there used.
fn area_cells_leg(
    transport: &dyn Transport,
    keys: &Keys,
    (lat, lon): (f64, f64),
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    let area = match opencellid::area(transport, keys, lat, lon, now_unix) {
        Ok(area) => area,
        Err(err) => return err.outcome(&opencellid::API, now_unix),
    };
    if area.cells.is_empty() {
        return SourceExecutionOutcome::valid_zero(opencellid::SOURCE, now_unix);
    }
    let listed = area.cells.len();
    if let Some(count) = area.count.filter(|count| *count > listed as u64) {
        let note = Evidence::new(
            EvidenceProvenance::for_scan(opencellid::SOURCE, scan_id),
            format!(
                "OpenCelliD lists {count} cell sites in the {:.0} m square around the point; the first {listed} are kept",
                2.0 * opencellid::AREA_HALF_SIDE_M
            ),
        )
        .with_attr("cells_in_area", count.to_string());
        if let Some(point) = report
            .entities
            .iter_mut()
            .find(|entity| entity.kind == EntityKind::Coordinates)
        {
            point.add_evidence(note);
        }
    }
    for site in &area.cells {
        let cell = &site.cell;
        let value = format!(
            "{CELL_PREFIX}{}:{:02}:{}:{}",
            cell.mcc, cell.mnc, cell.lac, cell.cellid
        );
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(opencellid::SOURCE, scan_id),
            "Cell site OpenCelliD places near the point",
        )
        .with_attr("position", format!("{:.6},{:.6}", site.lat, site.lon))
        .with_optional_attrs([("radio", site.radio.as_deref())])
        .with_optional_attrs([
            (
                "range_m",
                site.range.map(|range| range.to_string()).as_deref(),
            ),
            ("samples", site.samples.map(|n| n.to_string()).as_deref()),
        ]);
        let mut entity = Entity::new(EntityKind::Other, value, 0.70, scan_id);
        entity.tag(tags::GEOINT);
        entity.add_evidence(evidence);
        report.entities.push(entity);
    }
    SourceExecutionOutcome::success(opencellid::SOURCE, now_unix, listed)
}

fn seed_entity(selector: &NetworkSelector, scan_id: &str) -> Entity {
    let (kind, note) = match selector {
        NetworkSelector::Bssid(_) => (EntityKind::MacAddress, "operator-supplied BSSID selector"),
        NetworkSelector::Ssid(_) => (EntityKind::Ssid, "operator-supplied SSID selector"),
        NetworkSelector::Area { .. } => (
            EntityKind::Coordinates,
            "operator-supplied coordinate selector",
        ),
        NetworkSelector::Cell { .. } => (EntityKind::Other, "operator-supplied cell site selector"),
    };
    let value = match selector {
        NetworkSelector::Ssid(name) => name.clone(),
        other => other.canonical(),
    };
    let mut entity = Entity::new(kind, value, 0.99, scan_id);
    entity.tag("seed");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        note,
    ));
    entity
}

/// The offline OUI classification of a BSSID, as evidence on its entity.
fn oui_leg(
    bssid: &str,
    scan_id: &str,
    now_unix: u64,
    entities: &mut Vec<Entity>,
) -> SourceExecutionOutcome {
    let Some(info) = oui::classify_mac(bssid) else {
        return SourceExecutionOutcome::valid_zero(OUI_SOURCE, now_unix);
    };
    let randomised = info.class == oui::DeviceClass::Randomized;
    let vendor = if randomised {
        info.vendor
    } else if let Some(manufacturer) = info.manufacturer() {
        manufacturer
    } else {
        // No MA-L assignment names the prefix (unregistered, or a block the IEEE Registration
        // Authority sub-assigns): the registry has no manufacturer to report.
        return SourceExecutionOutcome::valid_zero(OUI_SOURCE, now_unix);
    };
    let mut entity = Entity::new(EntityKind::MacAddress, bssid, 0.95, scan_id);
    entity.add_evidence(
        Evidence::new(
            EvidenceProvenance::for_scan(OUI_SOURCE, scan_id),
            if randomised {
                "Locally administered (randomised) address: it names no manufacturer and may \
                 rotate"
            } else {
                "Manufacturer from the IEEE OUI registry"
            },
        )
        .with_attr("vendor", vendor)
        .with_attr("randomised", randomised.to_string()),
    );
    entities.push(entity);
    SourceExecutionOutcome::success(OUI_SOURCE, now_unix, 1)
}

#[allow(clippy::too_many_arguments)]
fn wigle_leg(
    transport: &dyn Transport,
    keys: &Keys,
    database: Database,
    selector: &NetworkSelector,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
    unanswered: &mut Unanswered,
) -> SourceExecutionOutcome {
    let source = database.source();
    match wigle::search(transport, keys, database, selector, now_unix) {
        Ok(search) => {
            report
                .entities
                .extend(wigle_entities(database, scan_id, &search));
            let outcome = if search.networks.is_empty() {
                SourceExecutionOutcome::valid_zero(source, now_unix)
            } else {
                SourceExecutionOutcome::success(source, now_unix, search.networks.len())
            }
            .with_http_status(200);
            let mut notes: Vec<String> = search.truncation().into_iter().collect();
            if search.unusable > 0 {
                notes.push(format!(
                    "{} result(s) carry no MAC address and were not kept",
                    search.unusable
                ));
            }
            match database {
                Database::Wifi => report.wigle = Some(search.networks),
                Database::Bluetooth => report.wigle_bluetooth = Some(search.networks),
            }
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => {
            let first = match &err {
                WigleError::Refused(_) => Some(&mut unanswered.refused),
                WigleError::Transport(_) => Some(&mut unanswered.no_response),
                _ => None,
            };
            if let Some(first) = first {
                first.get_or_insert_with(|| err.to_string());
            }
            let outcome = SourceExecutionOutcome::failed(
                source,
                now_unix,
                err.outcome_kind(),
                err.http_status(),
                err.to_string(),
            );
            match err {
                WigleError::RateLimited {
                    retry_after: Some(secs),
                } => outcome.with_retry_after(secs),
                _ => outcome,
            }
        }
    }
}

/// One MAC-address entity per network or device carrying what `WiGLE` records about it, then a
/// pivot for its trilaterated position and, for a `WiFi` network, one for its SSID. A Bluetooth
/// device name stays an attribute: it often names its owner.
fn wigle_entities(database: Database, scan_id: &str, search: &wigle::Search) -> Vec<Entity> {
    let source = database.source();
    let (summary, name_key) = match database {
        Database::Wifi => ("WiFi network recorded by WiGLE", "ssid"),
        Database::Bluetooth => ("Bluetooth device recorded by WiGLE", "device_name"),
    };
    let mut entities = Vec::new();
    for net in &search.networks {
        let mut entity = Entity::new(EntityKind::MacAddress, net.bssid(), 0.85, scan_id);
        entity.tag(tags::GEOINT);
        let mut evidence = Evidence::new(EvidenceProvenance::for_scan(source, scan_id), summary)
            .with_attr("radio", net.sighting.radio.as_db_str());
        let channel = net.channel.map(|c| c.to_string());
        let frequency = net.frequency_mhz.map(|f| f.to_string());
        let position = net
            .position()
            .map(|(lat, lon)| format!("{lat:.6},{lon:.6}"));
        let address = net.address();
        for (key, value) in [
            (name_key, net.ssid()),
            ("device_class", net.sighting.device_class.as_deref()),
            ("encryption", net.sighting.encryption.as_deref()),
            ("network_type", net.sighting.raw_type.as_deref()),
            ("channel", channel.as_deref()),
            ("frequency_mhz", frequency.as_deref()),
            ("position", position.as_deref()),
            ("first_seen", net.first_seen.as_deref()),
            ("last_seen", net.sighting.observed_at.as_deref()),
            ("last_updated", net.last_updated.as_deref()),
            ("address", address.as_deref()),
        ] {
            if let Some(value) = value {
                evidence = evidence.with_attr(key, value);
            }
        }
        entity.add_evidence(evidence);
        entities.push(entity);

        let pivot = |kind, value: &str, confidence, note: &str| {
            let mut entity = Entity::new(kind, value, confidence, scan_id);
            entity.add_evidence(
                Evidence::new(EvidenceProvenance::for_scan(source, scan_id), note)
                    .with_attr("bssid", net.bssid()),
            );
            entity
        };
        if let (Database::Wifi, Some(ssid)) = (database, net.ssid()) {
            entities.push(pivot(
                EntityKind::Ssid,
                ssid,
                0.80,
                "SSID WiGLE records for the network",
            ));
        }
        if let Some(position) = &position {
            let mut place = pivot(
                EntityKind::Coordinates,
                position,
                0.60,
                "Position WiGLE trilaterates from its sightings",
            );
            place.tag(tags::GEOINT);
            entities.push(place);
        }
    }
    entities
}

/// One `WiGLE` section after the lookup report: `wigle_networks=N` (or
/// `wigle_bluetooth_devices=N`), `none` when that search gave no answer, then one tab-separated
/// row per network or device in `WiGLE`'s order. Every value is written through
/// [`escape_controls`].
fn render_wigle(database: Database, networks: Option<&[wigle::Network]>) -> String {
    let (count, row_label, name_key) = match database {
        Database::Wifi => ("wigle_networks", "wigle_network", "ssid"),
        Database::Bluetooth => ("wigle_bluetooth_devices", "wigle_bluetooth", "name"),
    };
    let Some(networks) = networks else {
        return format!("{count}=none\n");
    };
    let mut out = format!("{count}={}\n", networks.len());
    for net in networks {
        let known = |value: Option<String>| {
            value.map_or_else(|| "unknown".to_owned(), |v| escape_controls(&v))
        };
        let mut row = vec![
            row_label.to_owned(),
            escape_controls(net.bssid()),
            format!("{name_key}={}", known(net.ssid().map(str::to_owned))),
        ];
        match database {
            Database::Wifi => {
                row.push(format!(
                    "encryption={}",
                    known(net.sighting.encryption.clone())
                ));
                row.push(format!(
                    "channel={}",
                    known(net.channel.map(|c| c.to_string()))
                ));
            }
            Database::Bluetooth => {
                row.push(format!("radio={}", net.sighting.radio.as_db_str()));
                row.push(format!(
                    "class={}",
                    known(net.sighting.device_class.clone())
                ));
            }
        }
        row.extend([
            format!(
                "position={}",
                known(
                    net.position()
                        .map(|(lat, lon)| format!("{lat:.6},{lon:.6}"))
                )
            ),
            format!("first_seen={}", known(net.first_seen.clone())),
            format!("last_seen={}", known(net.sighting.observed_at.clone())),
            format!("address={}", known(net.address())),
        ]);
        out.push_str(&row.join("\t"));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests;
