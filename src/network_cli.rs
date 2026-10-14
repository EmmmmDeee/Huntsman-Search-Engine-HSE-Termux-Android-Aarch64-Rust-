//! End-to-end front-end for `huntsman-recon network` and the network arm of `scan`.
//!
//! A network selector is a BSSID (`aa:bb:cc:dd:ee:ff`), a coordinate pair (`LAT,LON`) or an
//! SSID (`ssid:NAME`, or any other text when the kind is named). A BSSID is first classified
//! offline: its OUI vendor and whether it is a randomised (locally administered) address. Then
//! the keyed `WiGLE` legs ([`crate::wigle`]) search for what the selector names: `WiFi` always,
//! and Bluetooth too for a MAC address or a place. Without
//! both `WiGLE` slots it makes no request and records `AuthRequired`, never a zero.
//!
//! Each network `WiGLE` returns becomes a BSSID entity carrying what `WiGLE` records about it,
//! and its SSID and trilaterated position become pivots. Everything flows through
//! `merge_by_uid`, `lookup_report` (lineage) and `lookup_save`.

use std::path::PathBuf;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::oui;
use crate::scan_route::{NetworkSelector, network_selector};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::tags;
use crate::textnorm::escape_controls;
use crate::wigle::{self, Database, WigleError};

pub const NETWORK_USAGE: &str =
    "usage: huntsman-recon network BSSID|LAT,LON|ssid:NAME [--save FILE]";
pub const NETWORK_HELP: &str = "\
network BSSID|LAT,LON|ssid:NAME [--save FILE]
Look up a WiFi network. A BSSID (aa:bb:cc:dd:ee:ff) is classified offline first: its OUI vendor and whether it is a randomised address. Then WiGLE search runs: a BSSID searches WiGLE's WiFi and Bluetooth databases for that address, ssid:NAME searches WiFi networks with exactly that name, and LAT,LON searches both databases in a box of about 220 m around the point, nearest first. WiGLE needs HUNTSMAN_WIGLE_USER (the API Name) and HUNTSMAN_WIGLE_TOKEN (the API Token) from https://wigle.net/account in the environment; without them it makes no request and reports auth_required. Each search spends one of the account's daily WiGLE queries, so a BSSID or LAT,LON spends two. credential-status --probe checks the credentials without spending one. Results are lineage-rendered entities, then wigle_networks=N (none when WiGLE gave no answer) and one wigle_network row per network: SSID, encryption, channel, position, first and last seen, and the street address WiGLE gives the position; for a BSSID or LAT,LON, then wigle_bluetooth_devices=N and one wigle_bluetooth row per device: name, radio (bt or ble), device class, position, first and last seen, address. --save FILE writes an unverified ledger that verify can reload.";

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
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid(
                "network needs exactly one BSSID, LAT,LON or ssid:NAME".into(),
            ));
        }
        let selector = network_selector(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid network selector"))?;
        Ok(Self { selector, save })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

/// Classify the selector and run each `WiGLE` search it calls for when `wigle` carries a
/// transport and keys.
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
    let mut network = None;
    for &database in Database::for_selector(&selector) {
        let outcome = match wigle {
            Some((transport, keys)) if wigle::configured(keys) => wigle_leg(
                transport,
                keys,
                database,
                &selector,
                &scan_id,
                now_unix,
                &mut report,
                &mut network,
            ),
            _ => SourceExecutionOutcome::failed(
                database.source(),
                now_unix,
                SourceOutcomeKind::AuthRequired,
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
    merge_by_uid(&mut report.entities);

    let collected = report.outcomes.iter().any(|o| o.kind.is_accepted());
    if let (false, Some(msg)) = (collected, network) {
        return NetworkRun::Network(msg);
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(mut text) => {
            text.push_str(&render_wigle(Database::Wifi, report.wigle.as_deref()));
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

fn seed_entity(selector: &NetworkSelector, scan_id: &str) -> Entity {
    let (kind, note) = match selector {
        NetworkSelector::Bssid(_) => (EntityKind::MacAddress, "operator-supplied BSSID selector"),
        NetworkSelector::Ssid(_) => (EntityKind::Ssid, "operator-supplied SSID selector"),
        NetworkSelector::Area { .. } => (
            EntityKind::Coordinates,
            "operator-supplied coordinate selector",
        ),
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
    let randomised = oui::is_locally_administered(bssid) == Some(true);
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
        .with_attr("vendor", info.vendor)
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
    network: &mut Option<String>,
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
            if let WigleError::Transport(_) = &err {
                network.get_or_insert_with(|| err.to_string());
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
