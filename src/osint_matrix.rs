//! Canonical, offline OSINT discipline-to-file matrix for the existing Huntsman Rust crate.
//! This is an architecture inventory, never a live source-health or device attestation report.
//! Rhinser is part of the same binary: no second server, scripting runtime or engine.

use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct FileRow {
    pub id: &'static str,
    pub discipline: &'static str,
    /// 1 is the highest engineering priority; not a confidence score.
    pub priority: u8,
    /// The Rust component which owns the capability.
    pub owner: &'static str,
    pub files: &'static [&'static str],
    pub inputs: &'static str,
    pub outputs: &'static str,
    /// Offline, keyless network, keyed network, Android bridge, or lead only.
    pub mode: &'static str,
    /// Source-code status only; it is NOT a runtime or source-availability observation.
    pub implementation: &'static str,
    pub synergies: &'static [&'static str],
    /// The reachable modules ([`crate::module::reachable_modules`]) whose capability this group
    /// is. Every reachable module sits in exactly one group, which a test holds.
    pub modules: &'static [&'static str],
    pub limitation: &'static str,
}

/// Curated capability groups. The separate /api/modules lists reachable provider modules.
/// A group can contain multiple source files; it is not a count of live collectors.
// Compact hand-audited catalogue; each row is intentionally one machine-diffable line.
#[rustfmt::skip]
pub const FILE_ROWS: &[FileRow] = &[
    FileRow { id: "geo_coordinates", discipline: "GEOINT", priority: 1, owner: "geoint", files: &["src/geoint.rs", "src/geohash.rs", "src/postcode_au.rs"], inputs: "coordinates,addresses", outputs: "coordinates,distance,region", mode: "offline", implementation: "code_present", synergies: &["geo_places", "network_location"], modules: &[], limitation: "A coordinate does not locate a person." },
    FileRow { id: "geo_places", discipline: "GEOINT", priority: 1, owner: "nominatim", files: &["src/nominatim.rs", "src/nominatim_cli.rs"], inputs: "place,coordinates", outputs: "place_geometry,geocoded_reference", mode: "keyless_network", implementation: "code_present", synergies: &["geo_coordinates", "geo_area_events"], modules: &["nominatim", "qld_traffic_cameras"], limitation: "Place resolution is not an eyewitness observation." },
    FileRow { id: "geo_imagery", discipline: "IMINT/GEOINT", priority: 1, owner: "stac", files: &["src/stac.rs", "src/exif.rs", "src/docmeta.rs", "src/reverse_image.rs"], inputs: "coordinates,media", outputs: "scene_metadata,media_metadata", mode: "keyless_network", implementation: "partial", synergies: &["geo_places", "geo_area_events"], modules: &["stac", "google_vision", "lenso", "saucenao"], limitation: "Imagery metadata is not image interpretation." },
    FileRow { id: "geo_aircraft", discipline: "GEOINT/TRANSPORT", priority: 2, owner: "opensky", files: &["src/opensky.rs", "src/geoint.rs"], inputs: "coordinates,time", outputs: "aircraft_sightings", mode: "keyless_network", implementation: "code_present", synergies: &["geo_places", "geo_area_events"], modules: &["opensky"], limitation: "Aircraft positions do not identify occupants." },
    FileRow { id: "geo_area_events", discipline: "GEOINT/OSINT", priority: 1, owner: "osint_area_risk", files: &["src/osint_area_risk.rs", "src/osint_casework.rs"], inputs: "public_event_dataset,coordinates", outputs: "area_estimate,provenance", mode: "offline", implementation: "code_present", synergies: &["geo_places", "human_casework"], modules: &[], limitation: "Event-pressure scores are not personal safety guarantees." },
    FileRow { id: "human_public_records", discipline: "HUMINT/RECORDS", priority: 1, owner: "people_cli", files: &["src/people_cli.rs", "src/asic_persons.rs", "src/asic_director.rs", "src/acnc.rs"], inputs: "public_name,organisation", outputs: "registry_observations", mode: "keyless_network", implementation: "partial", synergies: &["human_casework", "org_records"], modules: &["asic_persons"], limitation: "Public records do not establish current location or identity linkage." },
    FileRow { id: "human_casework", discipline: "HUMINT/EVIDENCE", priority: 1, owner: "osint_casework", files: &["src/osint_casework.rs", "src/rhinser_workspace.rs"], inputs: "operator_observations,source_urls", outputs: "source_receipts,claim_review,timeline", mode: "offline", implementation: "code_present", synergies: &["geo_area_events", "identity_gate", "rhinser_cases"], modules: &["classify_module"], limitation: "Operator-submitted claims are not independent verification." },
    FileRow { id: "human_context", discipline: "HUMINT/SOCMINT", priority: 2, owner: "federated_osint", files: &["src/federated_osint.rs", "src/public_osint.rs", "src/wikidata.rs"], inputs: "public_text,source_urls", outputs: "published_statements,leads", mode: "keyless_network", implementation: "partial", synergies: &["human_casework", "social_profiles"], modules: &["wikidata", "fbi_wanted"], limitation: "No covert contact, elicitation or private-account collection." },
    FileRow { id: "human_enterprise", discipline: "HUMINT/ORGINT", priority: 2, owner: "sec_edgar", files: &["src/sec_edgar.rs", "src/gleif.rs", "src/wikidata.rs", "src/icij_offshore.rs", "src/sanctions.rs"], inputs: "entity_name,company_id", outputs: "public_entity_roles", mode: "keyless_network", implementation: "code_present", synergies: &["org_records", "human_public_records"], modules: &["sec_edgar", "icij_offshore", "sanctions"], limitation: "Organisation roles are time-sensitive; a leaked-record name match is a lead, not identity." },
    FileRow { id: "org_records", discipline: "ORGINT", priority: 2, owner: "acnc", files: &["src/acnc.rs", "src/asic_director.rs", "src/gleif.rs"], inputs: "company_name,registry_id", outputs: "public_entity_edges", mode: "keyless_network", implementation: "code_present", synergies: &["human_public_records", "net_rdap"], modules: &["asic_director", "acnc", "abn_lookup", "asic_orgs", "gleif_lei", "apple_itunes"], limitation: "Shared business details are weak person-level evidence." },
    FileRow { id: "social_profiles", discipline: "SOCMINT", priority: 2, owner: "username_cli", files: &["src/username_cli.rs", "src/github_user.rs", "src/bluesky_user.rs", "src/mastodon_user.rs"], inputs: "public_handle", outputs: "public_profile,source_links", mode: "keyless_network", implementation: "partial", synergies: &["human_context", "identity_gate"], modules: &["username_variants", "github_user", "github_repos", "gitlab_user", "npm_author", "crates_io", "docker_hub_user", "codeberg_user", "devto_user", "huggingface_user", "codewars_user", "bluesky_user", "mastodon_user", "keybase"], limitation: "A handle is not proof of a real-world identity." },
    FileRow { id: "social_other", discipline: "SOCMINT", priority: 3, owner: "tiktok_public_contact", files: &["src/tiktok_public_contact.rs", "src/hacker_news.rs", "src/gitlab_user.rs"], inputs: "public_handle", outputs: "public_profile_leads", mode: "keyless_network", implementation: "partial", synergies: &["social_profiles", "human_casework"], modules: &["tiktok_public_contact", "hacker_news", "lobsters", "chess_com", "lichess", "wikipedia"], limitation: "No claims of private email or account registration." },
    FileRow { id: "net_dns", discipline: "NETINT", priority: 1, owner: "dns", files: &["src/dns.rs", "src/crtsh.rs", "src/certspotter.rs", "src/spf.rs"], inputs: "domain", outputs: "dns_records,certificate_names", mode: "keyless_network", implementation: "code_present", synergies: &["net_rdap", "net_routing"], modules: &["domain_cli", "dns", "dnsresolve", "crtsh", "certspotter", "submd", "securitytrails", "mnemonic"], limitation: "Hosting and DNS association do not prove common ownership." },
    FileRow { id: "net_rdap", discipline: "NETINT", priority: 1, owner: "rdap", files: &["src/rdap.rs"], inputs: "domain,ip,asn", outputs: "registration_evidence", mode: "keyless_network", implementation: "partial", synergies: &["net_dns", "org_records"], modules: &["rdap", "whoxy", "domain_lifecycle"], limitation: "Registration records may be redacted or outdated." },
    FileRow { id: "net_routing", discipline: "NETINT", priority: 1, owner: "ripestat", files: &["src/ripestat.rs", "src/asn_cli.rs", "src/netblock_cli.rs", "src/peeringdb.rs"], inputs: "ip,asn,prefix", outputs: "routing_graph,announced_prefixes", mode: "keyless_network", implementation: "code_present", synergies: &["net_dns", "net_threat"], modules: &["ip_cli", "netblock_cli", "asn_cli", "ripestat", "peeringdb", "internetdb", "ipinfo", "ipinfo_lite", "robtex", "hackertarget"], limitation: "Routing adjacency is not human association." },
    FileRow { id: "net_threat", discipline: "CTI/NETINT", priority: 2, owner: "greynoise", files: &["src/greynoise.rs", "src/abuseipdb.rs", "src/virustotal.rs", "src/otx.rs"], inputs: "ip,domain,hash", outputs: "reputation,source_outcomes", mode: "keyed_network", implementation: "partial", synergies: &["net_routing", "net_dns"], modules: &["virustotal", "greynoise", "abuseipdb", "otx", "shodan", "censys", "pulsedive", "leakix", "threatfox", "ipqs", "netlas", "urlscan", "stopforumspam", "isc", "maltiverse", "phishstats", "urlhaus"], limitation: "Threat scores are provider assessments." },
    FileRow { id: "net_archive", discipline: "WEBINT", priority: 2, owner: "wayback_cdx", files: &["src/wayback_cdx.rs", "src/common_crawl.rs", "src/archived_page.rs"], inputs: "url,domain", outputs: "historical_pages,source_timestamps", mode: "keyless_network", implementation: "code_present", synergies: &["net_dns", "human_context"], modules: &["wayback_cdx", "common_crawl"], limitation: "Historic content may no longer be true." },
    FileRow { id: "radio_wifi", discipline: "SIGINT/GEOINT", priority: 1, owner: "wifi_radar", files: &["src/wifi_radar.rs", "src/rf.rs", "src/oui.rs"], inputs: "android_wifi_cache", outputs: "timestamped_radio_observations", mode: "android_bridge", implementation: "partial", synergies: &["radio_cell", "network_location"], modules: &["wifi_radar", "oui"], limitation: "Android controls freshness; no person tracking." },
    FileRow { id: "radio_cell", discipline: "SIGINT/GEOINT", priority: 1, owner: "cell_radar", files: &["src/cell_radar.rs", "src/opencellid.rs", "src/rf.rs"], inputs: "android_cell_metadata,coordinates", outputs: "cell_reference,sensor_status", mode: "android_bridge", implementation: "partial", synergies: &["radio_wifi", "network_location"], modules: &["cell_radar", "opencellid"], limitation: "Cell identifiers are not device coordinates." },
    FileRow { id: "network_location", discipline: "GEOINT/NETINT", priority: 1, owner: "network_cli", files: &["src/network_cli.rs", "src/wigle.rs", "src/network_selector.rs"], inputs: "bssid,ssid,coordinates", outputs: "geospatial_network_leads", mode: "keyed_network", implementation: "partial", synergies: &["radio_wifi", "radio_cell", "geo_places"], modules: &["wigle", "wigle_bluetooth"], limitation: "Wi-Fi databases are historical and not live geolocation." },
    FileRow { id: "network_defence", discipline: "NETINT/DEFENCE", priority: 2, owner: "mitm_guard", files: &["src/mitm_guard.rs", "src/dns_filter.rs"], inputs: "authorised_wifi_observations", outputs: "local_risk_indicators", mode: "android_bridge", implementation: "partial", synergies: &["radio_wifi", "net_dns"], modules: &["mitm_guard"], limitation: "Do not equate anomalies with verified attacks." },
    FileRow { id: "media_metadata", discipline: "DOCINT", priority: 2, owner: "docmeta", files: &["src/docmeta.rs", "src/exif.rs", "src/apk_intel.rs"], inputs: "operator_files", outputs: "metadata_observations", mode: "offline", implementation: "code_present", synergies: &["geo_imagery", "human_casework"], modules: &["exif", "docmeta"], limitation: "Metadata can be altered or forged." },
    FileRow { id: "breach_exposure", discipline: "BREACHINT", priority: 2, owner: "exposure_cli", files: &["src/exposure_cli.rs", "src/hibp/mod.rs", "src/dehashed/mod.rs", "src/oathnet.rs", "src/breach_record.rs", "src/breach_hybrid.rs"], inputs: "authorised_email,account", outputs: "exposure_indicators", mode: "keyed_network", implementation: "partial", synergies: &["human_casework", "identity_gate"], modules: &["hibp", "hibp_account", "dehashed", "oathnet", "stolen_tax", "seeknow", "xposed_or_not", "hudsonrock"], limitation: "No publishing of credentials or bulk private records." },
    FileRow { id: "identity_gate", discipline: "FUSION", priority: 1, owner: "identity_resolution", files: &["src/identity_resolution.rs", "src/identity.rs", "src/evidence_ancestry.rs", "src/correlator.rs"], inputs: "corroborated_entities", outputs: "held_or_verified_links", mode: "offline", implementation: "code_present", synergies: &["human_casework", "social_profiles", "geo_places"], modules: &[], limitation: "Independent proof required for automatic identity merging." },
    FileRow { id: "cross_scan", discipline: "FUSION", priority: 1, owner: "cross_scan", files: &["src/cross_scan.rs", "src/relation/mod.rs", "src/scan_uncertainty.rs", "src/orthogonal_osint.rs"], inputs: "saved_scan_evidence", outputs: "relations,coverage_gaps", mode: "offline", implementation: "code_present", synergies: &["identity_gate", "geo_area_events", "net_dns"], modules: &[], limitation: "Co-occurrence never suffices for person-level identification." },
    FileRow { id: "case_store", discipline: "EVIDENCE", priority: 1, owner: "scan_store", files: &["src/scan_store.rs", "src/ledger.rs", "src/scan_artifact.rs", "src/retrieval_artifact.rs"], inputs: "source_evidence", outputs: "durable_records,hashes", mode: "offline", implementation: "code_present", synergies: &["cross_scan", "human_casework"], modules: &["local_search"], limitation: "Storage does not independently verify source truth." },
    FileRow { id: "provider_gate", discipline: "INFRASTRUCTURE", priority: 1, owner: "api_leg", files: &["src/api_leg.rs", "src/source_outcome.rs", "src/egress.rs", "src/keys.rs"], inputs: "source_requests,keys", outputs: "explicit_outcomes", mode: "offline", implementation: "code_present", synergies: &["runtime_autonomy", "net_threat"], modules: &[], limitation: "A failed provider is not a negative finding." },
    FileRow { id: "runtime_autonomy", discipline: "AUTONOMY", priority: 1, owner: "autonomous_capability", files: &["src/autonomous_capability.rs", "src/planner.rs", "src/recursion.rs", "src/runtime.rs"], inputs: "scope,capability_probe", outputs: "bounded_execution_plan", mode: "offline", implementation: "partial", synergies: &["provider_gate", "case_store"], modules: &[], limitation: "No claim of continuous background execution without scheduler." },
    FileRow { id: "web_api", discipline: "INTERFACE", priority: 1, owner: "web_server", files: &["src/web_server.rs", "src/web_api_types.rs", "src/scan_api.rs"], inputs: "browser_requests", outputs: "authorised_api_results", mode: "offline", implementation: "code_present", synergies: &["rhinser_native", "rhinser_catalog", "cross_scan"], modules: &["web_server", "sf_compat"], limitation: "Loopback by default; public bind requires token." },
    FileRow { id: "rhinser_catalog", discipline: "RHINSER/WEBINT", priority: 1, owner: "rhinser_catalog", files: &["src/rhinser_catalog.rs"], inputs: "directory_filter", outputs: "unverified_source_leads", mode: "lead_only", implementation: "code_present", synergies: &["human_casework", "net_archive"], modules: &[], limitation: "The 83 link entries are not 83 functioning collectors." },
    FileRow { id: "rhinser_native", discipline: "RHINSER/SIGINT", priority: 1, owner: "rhinser_native", files: &["src/rhinser_native.rs", "src/rhinser_nfc.rs", "src/rhinser_tlv.rs"], inputs: "operator_submitted_android_json", outputs: "bounded_unverified_observations", mode: "offline", implementation: "partial", synergies: &["radio_wifi", "media_metadata", "human_casework"], modules: &[], limitation: "No Android companion attestation, radio control or active NFC access." },
    FileRow { id: "rhinser_cases", discipline: "RHINSER/HUMINT", priority: 1, owner: "rhinser_workspace", files: &["src/rhinser_workspace.rs", "src/osint_casework.rs"], inputs: "local_case_notes,source_leads", outputs: "private_workspace", mode: "offline", implementation: "partial", synergies: &["human_casework", "rhinser_catalog"], modules: &[], limitation: "Source leads must be verified before promotion." },
    FileRow { id: "rhinser_tlv", discipline: "RHINSER/DOCINT", priority: 2, owner: "rhinser_tlv", files: &["src/rhinser_tlv.rs", "src/rhinser_nfc.rs"], inputs: "operator_hex_dump", outputs: "structure_only_metadata", mode: "offline", implementation: "code_present", synergies: &["rhinser_native", "media_metadata"], modules: &[], limitation: "No card emulation, credential extraction or transmission." },
    FileRow { id: "rhinser_parity", discipline: "RHINSER/AUDIT", priority: 1, owner: "rhinser_catalog", files: &["src/rhinser_catalog.rs", "src/osint_blueprint.rs"], inputs: "source_inventory", outputs: "feature_gap_register", mode: "lead_only", implementation: "partial", synergies: &["rhinser_native", "rhinser_cases"], modules: &[], limitation: "Android APK parity requires separate device-level testing." },
    FileRow { id: "finance_public", discipline: "FININT", priority: 3, owner: "blockchain", files: &["src/blockchain.rs", "src/eth_rpc.rs", "src/base_rpc.rs", "src/solana_rpc.rs"], inputs: "public_blockchain_address", outputs: "public_chain_activity", mode: "keyless_network", implementation: "code_present", synergies: &["org_records", "human_casework"], modules: &["blockchain", "eth_rpc", "base_rpc", "solana_rpc"], limitation: "Chain addresses alone do not identify people." },
    FileRow { id: "transport_geo", discipline: "GEOINT/TRANSPORT", priority: 3, owner: "stac", files: &["src/stac.rs", "src/opensky.rs"], inputs: "public_coordinate", outputs: "published_activity_context", mode: "keyless_network", implementation: "partial", synergies: &["geo_aircraft", "geo_imagery"], modules: &[], limitation: "No live surveillance or person tracking." },
    FileRow { id: "web_public", discipline: "WEBINT", priority: 2, owner: "public_osint", files: &["src/public_osint.rs", "src/search.rs", "src/exa.rs"], inputs: "public_query", outputs: "source_candidates", mode: "keyless_network", implementation: "partial", synergies: &["human_context", "net_archive"], modules: &["exa", "web_query", "source_registry"], limitation: "Search results are discovery leads, not corroboration." },
    FileRow { id: "email_identity", discipline: "EMAIL/IDENTITY", priority: 2, owner: "email_cli", files: &["src/email_cli.rs", "src/gravatar.rs", "src/openpgp_keys.rs", "src/kickbox.rs", "src/hunter.rs", "src/duolingo.rs"], inputs: "email_address", outputs: "public_profiles,key_identities,mailbox_checks", mode: "keyless_network", implementation: "code_present", synergies: &["breach_exposure", "social_profiles"], modules: &["email_parse", "gravatar", "duolingo", "openpgp_keys", "kickbox", "hunter"], limitation: "Public profiles and keys for an address are self-published; none proves who reads the mailbox." },
    FileRow { id: "phone_numbers", discipline: "TELINT", priority: 2, owner: "phone_cli", files: &["src/phone_cli.rs", "src/phone_intl.rs", "src/numverify.rs"], inputs: "phone_number", outputs: "numbering_plan_reading,carrier_lookup", mode: "offline", implementation: "code_present", synergies: &["email_identity", "human_casework"], modules: &["phone_intl", "phone_au", "phone_nanp", "phone_ae", "numverify"], limitation: "A numbering plan names a range's area or type, never the subscriber or their location." },
    FileRow { id: "net_blocklists", discipline: "CTI/NETINT", priority: 2, owner: "threat_feeds", files: &["src/threat_feeds.rs", "src/dnsbl.rs", "src/dns_filter.rs"], inputs: "ip,domain", outputs: "blocklist_listings,feed_entries,filter_blocks", mode: "keyless_network", implementation: "code_present", synergies: &["net_threat", "net_dns"], modules: &["spamhaus", "spamcop", "uceprotect", "dronebl", "sorbs", "surbl", "adguard_dns", "cleanbrowsing", "cloudflaredns", "comodo", "dns_for_family", "opendns", "quad9", "yandexdns", "abusech", "alienvaultiprep", "blocklistde", "botvrij", "cinsscore", "cleantalk", "cybercrimetracker", "emergingthreats", "greensnow", "openphish", "phishtank", "stevenblack_hosts", "torexits", "voipbl", "vxvault"], limitation: "A listing is its list owner's assessment, and a list past its age answers for nothing current." },
];

/// Stable, read-only JSON contract, shared by the CLI and protected Web API.
#[must_use]
pub fn report() -> serde_json::Value {
    let disciplines = FILE_ROWS
        .iter()
        .map(|row| row.discipline)
        .collect::<BTreeSet<_>>()
        .len();
    let files = FILE_ROWS
        .iter()
        .flat_map(|row| row.files.iter().copied())
        .collect::<BTreeSet<_>>()
        .len();
    let modules = FILE_ROWS.iter().map(|row| row.modules.len()).sum::<usize>();
    serde_json::json!({
        "schema_version": 1,
        "status": "source_inventory_not_live_verification",
        "canonical_binary": "huntsman-recon",
        "target": "android-aarch64-termux-rootless",
        "runtime_llm": false,
        "rows_count": FILE_ROWS.len(),
        "source_files_count": files,
        "disciplines_count": disciplines,
        "reachable_modules_count": crate::module::reachable_modules().len(),
        "modules_in_rows_count": modules,
        "rhinser_incorporation": "native_rust_partial_compatibility",
        "rows": FILE_ROWS,
        "notice": "Code presence, public links and operator-provided captures never prove live source availability, personal identity or present location."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn every_row_owns_real_rust_files_and_links_only_existing_groups() {
        let mut ids = BTreeSet::new();
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for row in FILE_ROWS {
            assert!(ids.insert(row.id), "duplicate matrix id {}", row.id);
            assert!(!row.files.is_empty(), "{} has no files", row.id);
            assert!((1..=3).contains(&row.priority));
            assert!(
                row.files
                    .iter()
                    .any(|file| file.ends_with(&format!("/{}.rs", row.owner))),
                "owner file missing: {}",
                row.id
            );
            for file in row.files {
                assert!(manifest.join(file).is_file(), "missing source file: {file}");
            }
        }
        for row in FILE_ROWS {
            for synergy in row.synergies {
                assert!(
                    ids.contains(synergy),
                    "unknown synergy {synergy} in {}",
                    row.id
                );
                assert_ne!(row.id, *synergy, "self synergy in {}", row.id);
            }
        }
    }

    /// Every reachable module (`module::reachable_modules`, which `/api/modules` and the web UI
    /// list) sits in exactly one capability group, and every module a group names is reachable.
    /// A module added without a group, or a group naming one that is gone, fails here.
    #[test]
    fn every_reachable_module_sits_in_exactly_one_group() {
        let mut placed: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for row in FILE_ROWS {
            for module in row.modules {
                placed.entry(module).or_default().push(row.id);
            }
        }
        let reachable: BTreeSet<&str> = crate::module::reachable_modules()
            .iter()
            .map(|module| module.name)
            .collect();
        let unplaced: Vec<&str> = reachable
            .iter()
            .copied()
            .filter(|name| !placed.contains_key(name))
            .collect();
        assert!(
            unplaced.is_empty(),
            "reachable modules in no OSINT matrix group; add each to the FileRow whose \
             capability it is: {unplaced:?}"
        );
        let twice: Vec<String> = placed
            .iter()
            .filter(|(_, rows)| rows.len() > 1)
            .map(|(module, rows)| format!("{module} in {rows:?}"))
            .collect();
        assert!(twice.is_empty(), "a module sits in two groups: {twice:?}");
        let unknown: Vec<&str> = placed
            .keys()
            .copied()
            .filter(|name| !reachable.contains(name))
            .collect();
        assert!(
            unknown.is_empty(),
            "matrix groups name modules that are not reachable: {unknown:?}"
        );
        assert_eq!(
            report()["modules_in_rows_count"],
            report()["reachable_modules_count"]
        );
    }

    #[test]
    fn rhinser_and_geo_human_net_are_first_class_disciplines() {
        for id in [
            "rhinser_native",
            "rhinser_catalog",
            "rhinser_cases",
            "rhinser_tlv",
            "geo_coordinates",
            "human_casework",
            "net_dns",
            "identity_gate",
        ] {
            assert!(FILE_ROWS.iter().any(|row| row.id == id), "missing {id}");
        }
        assert_eq!(
            report()["rows_count"].as_u64(),
            Some(FILE_ROWS.len() as u64)
        );
        assert_eq!(
            report()["rhinser_incorporation"],
            "native_rust_partial_compatibility"
        );
    }
}
