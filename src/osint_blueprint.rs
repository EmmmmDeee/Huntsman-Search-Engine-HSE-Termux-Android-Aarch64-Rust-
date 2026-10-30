//! The OSINT app blueprint: the Android apps an investigator reaches for, what each does, and
//! what in Huntsman reproduces it in Rust on a rootless Termux phone.
//!
//! [`ENTRIES`] is the one authority. `huntsman-recon blueprint` prints it, `--json` and
//! `GET /api/blueprint` answer it, and `blueprint --docx FILE` or
//! `GET /api/blueprint?format=docx` write it as a Word document (`docs/OSINT_APK_BLUEPRINT.docx`
//! is that document, checked against these entries by a test). A test also holds every command
//! an entry names to the dispatcher, and every module to the source tree, so the blueprint
//! cannot claim a capability Huntsman lacks. Facts about each app come from its F-Droid page or
//! source repository; a licence or package not confirmed there says "not verified".

use std::fmt::Write as _;

use serde::Serialize;

use crate::docx::{self, Block};

/// How much of an app's method Huntsman reproduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Huntsman does what the app does for an investigator.
    Implemented,
    /// Huntsman does part of it; `gap` says what is missing.
    Partial,
    /// Feasible on a rootless phone, not built yet.
    Planned,
    /// Android or Termux denies what the method needs; `gap` says what.
    NotFeasibleRootless,
}

impl Status {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Implemented => "Implemented",
            Self::Partial => "Partial",
            Self::Planned => "Planned",
            Self::NotFeasibleRootless => "Not feasible rootless",
        }
    }
}

/// One app and its Huntsman equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub app: &'static str,
    /// The Android package name, or "not verified".
    pub package: &'static str,
    pub category: &'static str,
    pub source: &'static str,
    /// The licence its source states, or "not verified".
    pub licence: &'static str,
    pub features: &'static str,
    /// The Huntsman modules (`src/NAME.rs`) that reproduce the method.
    pub modules: &'static [&'static str],
    /// The Huntsman commands that reach them, as typed after `huntsman-recon`.
    pub commands: &'static [&'static str],
    /// Where in Huntsman the capability is reachable.
    pub integration: &'static str,
    pub termux: &'static str,
    /// P1 is the most investigative value for the cost.
    pub priority: &'static str,
    pub status: Status,
    /// What is missing, or what Android denies.
    pub gap: &'static str,
    /// The checkable condition that shows the Huntsman equivalent works.
    pub acceptance: &'static str,
}

const RADAR_CLI_API_UI: &str = "CLI (radar), GET /api/radar/wifi and /api/radar/cells, POST /api/radar/track, Web UI Radar tab";
const TERMUX_API: &str = "Termux:API app plus `pkg install termux-api`; Android location and phone permissions granted to Termux:API; no root";

/// Every app the blueprint covers, by category.
pub const ENTRIES: &[Entry] = &[
    Entry {
        app: "Termux:API",
        package: "com.termux.api",
        category: "Platform",
        source: "https://github.com/termux/termux-api",
        licence: "GPL-3.0-only",
        features: "Exposes Android APIs to Termux shell commands: the cached Wi-Fi scan (termux-wifi-scaninfo), the cells the modem reports (termux-telephony-cellinfo), location, SMS, clipboard, notifications.",
        modules: &["wifi_radar", "cell_radar", "radar"],
        commands: &["radar wifi", "radar cells", "radar track"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P1",
        status: Status::Implemented,
        gap: "Android serves Termux only cached Wi-Fi results and the cell list; no active scan, no Bluetooth or GNSS satellite data.",
        acceptance: "radar wifi and radar cells parse the exact JSON Termux:API writes; an empty or redacted read is reported as inconclusive, never as an absence (wifi_radar and cell_radar tests).",
    },
    Entry {
        app: "Network Survey",
        package: "com.craxiom.networksurvey",
        category: "Cellular and radio",
        source: "https://github.com/christianrowlands/android-network-survey",
        licence: "Apache-2.0",
        features: "Logs cellular (GSM, CDMA, UMTS, LTE, NR), Wi-Fi, Bluetooth and GNSS records to CSV or GeoPackage; LTE cell ID to eNodeB and sector calculator; band and channel tools.",
        modules: &["cell_radar", "radar"],
        commands: &["radar cells", "radar track"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P1",
        status: Status::Partial,
        gap: "No Bluetooth or GNSS records (Termux:API exposes neither) and no GeoPackage export; sweeps are logged as JSON lines.",
        acceptance: "radar cells gives each LTE cell its eNodeB and sector (ci >> 8, ci & 0xFF), each WCDMA cell its RNC and cell, PCI or PSC, bands and the LTE timing advance band; radar track logs sweeps with the serving cell.",
    },
    Entry {
        app: "ICdetection",
        package: "com.alexisgordr.icdetector",
        category: "Cellular and radio",
        source: "https://f-droid.org/packages/com.alexisgordr.icdetector/",
        licence: "GPL-3.0-or-later",
        features: "Rootless, offline cellular anomaly auditor: cell identity, MCC, MNC, TAC, PCI, ARFCN, signal and timing advance from Android's public telephony API, with conservative heuristics whose alerts need temporal confirmation.",
        modules: &["cell_radar"],
        commands: &["radar cells"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P1",
        status: Status::Partial,
        gap: "Huntsman audits one read at a time; confirming an indicator across reads and places, and ARFCN (Termux:API does not report it), are missing.",
        acceptance: "radar cells flags a GSM serving cell beside the same operator's LTE/NR, eNodeB sectors in different tracking areas, and a registered cell without neighbours, as indicators with the stated limit that no app can detect an IMSI catcher.",
    },
    Entry {
        app: "AIMSICD",
        package: "not verified",
        category: "Cellular and radio",
        source: "https://github.com/CellularPrivacy/Android-IMSI-Catcher-Detector",
        licence: "not verified",
        features: "IMSI-catcher detection heuristics: tower information consistency, LAC/cell ID consistency, neighbouring cell checks, signal strength monitoring, silent SMS and femtocell detection.",
        modules: &["cell_radar"],
        commands: &["radar cells"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P2",
        status: Status::Partial,
        gap: "Silent SMS and femtocell detection need the modem or SMS internals Termux cannot read.",
        acceptance: "The neighbour and tracking-area consistency checks of radar cells hold on Termux:API JSON (cell_radar audit tests).",
    },
    Entry {
        app: "NetMonster",
        package: "not verified",
        category: "Cellular and radio",
        source: "https://github.com/mroczis/netmonster-core",
        licence: "Apache-2.0 (netmonster-core library; the app is not open source)",
        features: "Validates and corrects the cell data Android's RIL reports and derives richer cell identity and signal fields.",
        modules: &["cell_radar"],
        commands: &["radar cells"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P2",
        status: Status::Partial,
        gap: "No per-vendor RIL corrections; out-of-range or redacted values are rejected, not repaired.",
        acceptance: "Every identity, PCI, band and timing-advance value is range-checked against 3GPP limits; a redacted value (Integer.MAX_VALUE) never becomes a cell.",
    },
    Entry {
        app: "Tower Collector",
        package: "info.zamojski.soft.towercollector",
        category: "Cellular and radio",
        source: "https://github.com/zamojski/TowerCollector",
        licence: "MPL-2.0",
        features: "Collects GPS locations of cell towers, uploads them to OpenCelliD and BeaconDB, exports CSV, JSON, GPX, KML and KMZ.",
        modules: &["opencellid", "network_cli"],
        commands: &["network cell:MCC:MNC:AREA:CELL", "network LAT,LON"],
        integration: "CLI (network), scans and the Web UI New Scan (network kind)",
        termux: "HUNTSMAN_OPENCELLID_KEY for OpenCelliD; without it no request is made",
        priority: "P2",
        status: Status::Partial,
        gap: "Huntsman reads OpenCelliD (a cell's position, the sites around a point); it does not contribute measurements.",
        acceptance: "network cell:MCC:MNC:AREA:CELL returns OpenCelliD's position, range and samples when keyed and records NotConfigured without a key (opencellid tests).",
    },
    Entry {
        app: "SnoopSnitch",
        package: "de.srlabs.snoopsnitch",
        category: "Cellular and radio",
        source: "https://f-droid.org/packages/de.srlabs.snoopsnitch/",
        licence: "not verified",
        features: "Analyses mobile radio data for fake base stations, user tracking and over-the-air updates; contributes to the GSM Security Map.",
        modules: &[],
        commands: &[],
        integration: "None",
        termux: "Requires root and a Qualcomm DIAG kernel driver",
        priority: "P3",
        status: Status::NotFeasibleRootless,
        gap: "Needs root and the Qualcomm DIAG interface to read layer-3 signalling; Termux userland has neither.",
        acceptance: "Out of scope while Huntsman runs without root.",
    },
    Entry {
        app: "WiGLE WiFi Wardriving",
        package: "net.wigle.wigleandroid",
        category: "Wi-Fi",
        source: "https://github.com/wiglenet/wigle-wifi-wardriving",
        licence: "BSD-3-Clause",
        features: "Geolocated detection and logging of Wi-Fi, Bluetooth and cell signals; local database; CSV and KML export; upload to wigle.net.",
        modules: &["wigle", "wifi_radar", "mitm_guard"],
        commands: &["network BSSID", "network ssid:NAME", "mitm audit"],
        integration: "CLI (network, mitm audit), scans, Web UI New Scan and Radar BSSID pivots",
        termux: "WiGLE API key for wigle.net searches; Termux:API for the local Wi-Fi cache",
        priority: "P2",
        status: Status::Partial,
        gap: "No active wardriving or upload: Android gives Termux only the cached scan.",
        acceptance: "network BSSID and ssid:NAME search wigle.net when keyed; mitm audit --file reads Huntsman-normalised WiGLE JSONL as well as a Termux scan (wigle and mitm_guard tests).",
    },
    Entry {
        app: "WiFiAnalyzer",
        package: "com.vrem.wifianalyzer",
        category: "Wi-Fi",
        source: "https://f-droid.org/packages/com.vrem.wifianalyzer/",
        licence: "GPL-3.0-only",
        features: "Nearby access points, channel ratings, signal over time, 2.4/5/6 GHz bands, 40-320 MHz widths, security, estimated distance, vendor/OUI lookup.",
        modules: &["wifi_radar", "oui", "mitm_guard"],
        commands: &["radar wifi", "mitm audit"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P3",
        status: Status::Partial,
        gap: "No channel ratings or signal-over-time graphs.",
        acceptance: "radar wifi reports each BSSID's SSID, RSSI, band, width, security, vendor and cache age; mitm audit flags evil-twin patterns.",
    },
    Entry {
        app: "Fieldwatch",
        package: "app.fieldwatch",
        category: "Wi-Fi",
        source: "https://github.com/OffGridPete/Fieldwatch",
        licence: "MIT",
        features: "Passive Wi-Fi and Bluetooth LE listening, an extensible signature library, GPS co-travel ('moving with you') detection and reports.",
        modules: &["radar", "wifi_radar"],
        commands: &["radar track"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P2",
        status: Status::Partial,
        gap: "Wi-Fi only: Termux:API reports no Bluetooth LE advertisements.",
        acceptance: "radar track names a device seen in at least three distinct cells over ten minutes as a follower candidate, never one seen in one place (radar tests).",
    },
    Entry {
        app: "Spectre",
        package: "dev.thomasbuilds.spectre",
        category: "Wi-Fi",
        source: "https://github.com/thomasbuilds/Spectre",
        licence: "GPL-3.0-only",
        features: "Cellular serving and neighbour cells, Wi-Fi with 802.11mc ranging, Bluetooth LE, GNSS, local-network host and service discovery, GATT inspector.",
        modules: &["wifi_radar", "cell_radar"],
        commands: &["radar wifi", "radar cells"],
        integration: RADAR_CLI_API_UI,
        termux: TERMUX_API,
        priority: "P3",
        status: Status::Partial,
        gap: "Bluetooth LE, GATT, GNSS and Wi-Fi ranging are not exposed to Termux; local-network probing is outside Huntsman's public-only egress policy.",
        acceptance: "radar cells keeps PCI-only neighbour cells beside the serving cell (cell_radar tests).",
    },
    Entry {
        app: "Exodus",
        package: "org.eu.exodus_privacy.exodusprivacy",
        category: "App analysis",
        source: "https://github.com/Exodus-Privacy/exodus-android-app",
        licence: "GPL-3.0-only",
        features: "Shows the trackers and permissions in installed apps, from reports the εxodus platform publishes.",
        modules: &["apk_intel"],
        commands: &["apk FILE"],
        integration: "CLI (apk), POST /api/inspect and the Web UI",
        termux: "None beyond Termux; an APK file on the phone",
        priority: "P1",
        status: Status::Implemented,
        gap: "Huntsman reads the APK itself offline instead of downloading εxodus reports.",
        acceptance: "apk FILE names the third-party SDKs its DEX code references and its manifest permissions, offline (apk_intel tests).",
    },
    Entry {
        app: "App Manager",
        package: "io.github.muntashirakon.AppManager",
        category: "App analysis",
        source: "https://github.com/MuntashirAkon/AppManager",
        licence: "GPL-3.0-or-later",
        features: "Lists activities, receivers, services, providers, permissions and signatures; scans for trackers and libraries; views the manifest; installs, backs up and signs APKs.",
        modules: &["apk_intel"],
        commands: &["apk FILE", "apk diff OLD NEW"],
        integration: "CLI (apk), POST /api/inspect and the Web UI",
        termux: "None beyond Termux; an APK file on the phone",
        priority: "P1",
        status: Status::Implemented,
        gap: "Static reading only: Huntsman does not install, launch, back up or sign apps.",
        acceptance: "apk FILE decodes the manifest, exported components, signing certificates, SDKs, native libraries and network policy; apk diff names what changed between two builds (apk_intel tests).",
    },
    Entry {
        app: "PCAPdroid",
        package: "com.emanuelef.remote_capture",
        category: "Network",
        source: "https://f-droid.org/packages/com.emanuelef.remote_capture/",
        licence: "GPL-3.0-or-later",
        features: "No-root traffic capture through a local VPN: per-app connections, PCAP export, DNS/TLS/HTTP host extraction, TLS decryption, offline country and ASN lookup.",
        modules: &[],
        commands: &[],
        integration: "None",
        termux: "Requires Android's VpnService, which a Termux command cannot hold",
        priority: "P3",
        status: Status::NotFeasibleRootless,
        gap: "Capturing other apps' traffic needs a VpnService app; Termux userland cannot open one.",
        acceptance: "Out of scope in Termux; apk FILE lists the URLs an app's code names as the offline alternative.",
    },
    Entry {
        app: "Ghost onion search",
        package: "org.darknetcrawler.mobile",
        category: "Network",
        source: "https://codeberg.org/sookoothaii/digital-spyglass-android",
        licence: "MIT",
        features: "Queries 13 public onion search engines through Tor SOCKS5, deduplicates and ranks results in RAM; extracts onion hosts, PGP fingerprints and coin addresses.",
        modules: &[],
        commands: &[],
        integration: "None",
        termux: "pkg install tor; a SOCKS5 proxy on 127.0.0.1:9050",
        priority: "P3",
        status: Status::Planned,
        gap: "Huntsman's transport reaches the public clearnet only; a SOCKS5 path through Termux's tor would be needed.",
        acceptance: "A query sent through a local Tor SOCKS5 proxy, refused when the proxy is absent, with onion results kept apart from clearnet evidence.",
    },
    Entry {
        app: "Orbot",
        package: "org.torproject.android",
        category: "Network",
        source: "https://github.com/guardianproject/orbot-android",
        licence: "not verified",
        features: "Tor as a VPN or proxy for other apps.",
        modules: &[],
        commands: &[],
        integration: "None",
        termux: "pkg install tor offers the same SOCKS5 proxy inside Termux",
        priority: "P3",
        status: Status::Planned,
        gap: "Huntsman cannot route its requests through Tor yet.",
        acceptance: "Every lookup can be sent through a configured SOCKS5 proxy, and the egress policy still holds.",
    },
    Entry {
        app: "GPSTest",
        package: "com.android.gpstest.osmdroid",
        category: "Location",
        source: "https://github.com/barbeau/gpstest",
        licence: "Apache-2.0",
        features: "Real-time GNSS satellite status (GPS, GLONASS, Galileo, BeiDou, QZSS, NavIC, SBAS), dual-frequency, assistance data controls.",
        modules: &[],
        commands: &[],
        integration: "None",
        termux: "termux-location returns a position fix, not satellite status",
        priority: "P3",
        status: Status::NotFeasibleRootless,
        gap: "Android's GnssStatus is open to apps, but Termux:API forwards only a location fix.",
        acceptance: "Out of scope until Termux:API exposes GNSS status.",
    },
    Entry {
        app: "Scrambled Exif",
        package: "com.jarsilio.android.scrambledeggsif",
        category: "Media metadata",
        source: "https://gitlab.com/juanitobananas/scrambled-exif",
        licence: "not verified",
        features: "Removes metadata from pictures before they are shared.",
        modules: &["exif", "docmeta"],
        commands: &["exif IMAGE-FILE", "docmeta FILE"],
        integration: "CLI (exif, docmeta), POST /api/inspect and the Web UI",
        termux: "None beyond Termux",
        priority: "P3",
        status: Status::Partial,
        gap: "Huntsman reads what metadata a file still carries (the investigator's side); it does not strip it.",
        acceptance: "exif IMAGE-FILE reads EXIF tags and GPS position from JPEG, TIFF, WebP and PNG, and refuses a corrupt file without a panic (exif tests).",
    },
    Entry {
        app: "Sharchive",
        package: "com.nudev.sharchive",
        category: "Web archives",
        source: "https://apt.izzysoft.de/fdroid/index/apk/com.nudev.sharchive",
        licence: "GPL-3.0-only",
        features: "Opens a shared page's history in the Internet Archive's Wayback Machine or Archive.is from the Android share sheet, and can ask Archive.org to save the page.",
        modules: &["wayback_cdx", "common_crawl", "archived_page"],
        commands: &["domain DOMAIN"],
        integration: "CLI (domain, scan -k domain), /api/lookup and the Web UI domain scan; wayback_cdx and common_crawl in the module catalogue",
        termux: "None beyond Termux; keyless",
        priority: "P1",
        status: Status::Partial,
        gap: "Huntsman reads two archives for a whole domain (the Wayback CDX index and the newest Common Crawl index) and the contacts up to three archived pages of each published; it does not query Archive.is or submit pages to Save Page Now, which would write to a third party.",
        acceptance: "domain DOMAIN reports wayback_cdx and common_crawl outcomes; a captured contact page yields historical_content leads naming the capture and archive, and an empty index is a valid zero (wayback_cdx and common_crawl tests).",
    },
    Entry {
        app: "Mempal",
        package: "com.example.mempal",
        category: "Blockchain",
        source: "https://f-droid.org/packages/com.example.mempal/",
        licence: "MIT",
        features: "Bitcoin network monitor: block height, hashrate, mempool size and fee rates, alerts when a TXID confirms, a fee estimator, a self-hosted mempool server option and Tor.",
        modules: &["blockchain", "crypto_cli"],
        commands: &["crypto BITCOIN-ADDRESS"],
        integration: "CLI (crypto, scan -k crypto), /api/lookup and the Web UI's Bitcoin / Base / Ethereum / Solana address scan",
        termux: "None beyond Termux; keyless",
        priority: "P3",
        status: Status::Partial,
        gap: "Huntsman investigates an address (balance, a sampled transaction chronology and role-named counterparties), not the network: no mempool, fee or TXID-confirmation watch.",
        acceptance: "crypto BITCOIN-ADDRESS on a fictional fixture lists the sampled first and last transaction times and paid_by, paid_to and co_input counterparties, each stating that a shared transaction is not common ownership (blockchain tests).",
    },
    Entry {
        app: "SkyPulse",
        package: "io.github.mrjohn6774.skypulse",
        category: "Aviation",
        source: "https://f-droid.org/packages/io.github.mrjohn6774.skypulse/",
        licence: "GPL-3.0-or-later",
        features: "Decodes 1090 MHz Mode S and ADS-B on the phone from an RTL-SDR, maps the aircraft with offline FIR and TRACON boundaries, and can feed local tools over Beast TCP.",
        modules: &["opensky", "nominatim_cli"],
        commands: &["geocode QUERY"],
        integration: "CLI (geocode LAT,LON, scan -k geocode), /api/lookup and the Web UI's Place scan; opensky in the module catalogue",
        termux: "None for the OpenSky leg; own-receiver decoding would need an RTL-SDR on USB OTG through termux-usb",
        priority: "P2",
        status: Status::Partial,
        gap: "Huntsman reads what OpenSky's public receiver network last reported around a point (transponder, callsign, position time, altitude, speed, squawk); it does not decode 1090 MHz itself from an attached SDR.",
        acceptance: "geocode LAT,LON lists the aircraft OpenSky reported within half a degree, nearest first, each a transponder DeviceId stating it is an airframe, not anyone aboard, and not where it is now (opensky tests).",
    },
];

/// The blueprint as text: a summary line per app, then each app's fields.
#[must_use]
pub fn render() -> String {
    let mut out = String::new();
    for entry in ENTRIES {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            entry.priority,
            entry.status.label(),
            entry.app,
            entry.category,
            if entry.commands.is_empty() {
                "-".to_owned()
            } else {
                entry.commands.join(", ")
            }
        );
    }
    out
}

fn rows(entry: &Entry) -> Vec<Vec<String>> {
    let list = |items: &[&str]| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    };
    [
        ("Package", entry.package.to_owned()),
        ("Source", entry.source.to_owned()),
        ("Licence", entry.licence.to_owned()),
        ("Features", entry.features.to_owned()),
        ("Rust modules", list(entry.modules)),
        ("Huntsman commands", list(entry.commands)),
        ("Integration", entry.integration.to_owned()),
        ("Termux requirements", entry.termux.to_owned()),
        ("Priority", entry.priority.to_owned()),
        ("Status", entry.status.label().to_owned()),
        ("Gap or limit", entry.gap.to_owned()),
        ("Acceptance", entry.acceptance.to_owned()),
    ]
    .into_iter()
    .fold(
        vec![vec!["Field".to_owned(), "Value".to_owned()]],
        |mut rows, (field, value)| {
            rows.push(vec![field.to_owned(), value]);
            rows
        },
    )
}

/// The blueprint as a Word document: an overview table, then one section per category with a
/// field table for each app.
#[must_use]
pub fn docx() -> Vec<u8> {
    let mut blocks = vec![
        Block::Paragraph("Each Android app below is an OSINT method an investigator uses on a phone. The table says what Huntsman reproduces in Rust on a rootless Termux phone, through which commands, and what Android or Termux denies. Generated by `huntsman-recon blueprint --docx` from the entries compiled into Huntsman; a test holds every listed command and module to the code. Facts about each app come from its F-Droid page or source repository; a licence or package not confirmed there says \"not verified\".".to_owned()),
        Block::Heading(1, "Overview".to_owned()),
    ];
    let mut overview = vec![vec![
        "App".to_owned(),
        "Category".to_owned(),
        "Priority".to_owned(),
        "Status".to_owned(),
        "Huntsman commands".to_owned(),
    ]];
    overview.extend(ENTRIES.iter().map(|entry| {
        vec![
            entry.app.to_owned(),
            entry.category.to_owned(),
            entry.priority.to_owned(),
            entry.status.label().to_owned(),
            if entry.commands.is_empty() {
                "none".to_owned()
            } else {
                entry.commands.join(", ")
            },
        ]
    }));
    blocks.push(Block::Table(overview));
    let mut category = "";
    for entry in ENTRIES {
        if entry.category != category {
            category = entry.category;
            blocks.push(Block::Heading(1, category.to_owned()));
        }
        blocks.push(Block::Heading(2, entry.app.to_owned()));
        blocks.push(Block::Table(rows(entry)));
    }
    docx::document(
        "Huntsman OSINT app blueprint",
        "Android OSINT apps and their Rust equivalents in Huntsman on rootless Termux",
        &blocks,
    )
}

/// The file name a download of [`docx`] carries.
pub const DOCX_NAME: &str = "OSINT_APK_BLUEPRINT.docx";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xlsx::tests::part;

    #[test]
    fn every_entry_states_its_status_honestly() {
        let mut apps = std::collections::BTreeSet::new();
        for entry in ENTRIES {
            assert!(apps.insert(entry.app), "{} is listed twice", entry.app);
            assert!(
                matches!(entry.priority, "P1" | "P2" | "P3"),
                "{}",
                entry.app
            );
            assert!(entry.source.starts_with("https://"), "{}", entry.app);
            assert!(
                !entry.gap.is_empty() && !entry.acceptance.is_empty(),
                "{}",
                entry.app
            );
            match entry.status {
                // A capability Huntsman has must be reachable by a command.
                Status::Implemented | Status::Partial => assert!(
                    !entry.commands.is_empty() && !entry.modules.is_empty(),
                    "{} claims a capability no command reaches",
                    entry.app
                ),
                Status::Planned | Status::NotFeasibleRootless => assert!(
                    entry.commands.is_empty(),
                    "{} names commands for a capability it does not have",
                    entry.app
                ),
            }
        }
        // Entries of one category sit together, so the document has one section each.
        let mut seen = std::collections::BTreeSet::new();
        let mut current = "";
        for entry in ENTRIES {
            if entry.category != current {
                current = entry.category;
                assert!(seen.insert(current), "{current} is split");
            }
        }
    }

    #[test]
    fn every_module_an_entry_names_is_in_the_source_tree() {
        for entry in ENTRIES {
            for module in entry.modules {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src")
                    .join(format!("{module}.rs"));
                assert!(path.is_file(), "{}: no module {module}", entry.app);
            }
        }
    }

    #[test]
    fn the_document_holds_every_app_and_its_fields() {
        let bytes = docx();
        let body = part(&bytes, "word/document.xml");
        for entry in ENTRIES {
            assert!(
                body.contains(&crate::gexf::escape_xml(entry.app)),
                "{}",
                entry.app
            );
            assert!(
                body.contains(&crate::gexf::escape_xml(entry.acceptance)),
                "{}",
                entry.app
            );
        }
        assert_eq!(body.matches(">Acceptance</w:t>").count(), ENTRIES.len());
        assert_eq!(docx(), bytes, "the same entries make the same bytes");
        assert_eq!(render().lines().count(), ENTRIES.len());
    }
}
