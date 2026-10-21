use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use super::*;
use crate::http::{Request, Response, Transport, TransportFailure};
use crate::keys::Keys;
use crate::module::{module_of, reachable_modules, selection};
use crate::module_selection::Selected;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::threat_feeds::Feeds;
use crate::{
    asn_cli, crypto_cli, domain_cli, email_cli, environment, exposure_cli, ip_cli, netblock_cli,
    network_cli, people_cli, phone_cli, stolen_tax, username_cli,
};

const NOW: u64 = 1_760_000_000;

/// A `RIPEstat` answer every data call reads as knowing nothing.
const RIPESTAT: &[u8] =
    br#"{"status":"ok","data":{"announced":false,"prefixes":[],"neighbours":[],"resources":[]}}"#;

/// A network that answers each threat feed with one unlisted address, `RIPEstat` and the CKAN
/// registers with empty data, and everything else "not found"; resolves every name to nothing;
/// answers no UDP; and keeps everything it was asked. Each lookup then has a leg that answers, so
/// it prints its report, and its every row, instead of failing.
#[derive(Clone, Default)]
struct Everywhere {
    asked: Arc<Mutex<Vec<String>>>,
}

impl Everywhere {
    fn note(&self, what: String) {
        if let Ok(mut asked) = self.asked.lock() {
            asked.push(what);
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked
            .lock()
            .map(|asked| asked.clone())
            .unwrap_or_default()
    }
}

impl Transport for Everywhere {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let url = request.url.as_str();
        self.note(url.to_owned());
        let (status, body): (u16, &[u8]) = if url.contains("onionoo") {
            (200, br#"{"relays":[]}"#)
        } else if threat_feeds::FEEDS.iter().any(|feed| feed.url == url) {
            (200, b"192.0.2.1\n")
        } else if url.contains("stat.ripe.net") {
            (200, RIPESTAT)
        } else if url.contains("datastore_search") {
            (
                200,
                br#"{"success":true,"result":{"records":[],"total":0}}"#,
            )
        } else {
            (404, b"{}")
        };
        Ok(Response {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
            truncated: false,
        })
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, TransportFailure> {
        self.note(format!("resolve {name}"));
        Ok(Vec::new())
    }

    fn exchange_udp(&self, server: SocketAddr, _: &[u8]) -> Result<Vec<u8>, TransportFailure> {
        self.note(format!("udp {server}"));
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: format!("no UDP to {server}"),
            blocked: false,
        })
    }
}

/// A key for every keyed leg, so each runs.
fn keys() -> Keys {
    let mut slots: Vec<&str> = indicator_legs::SOURCES
        .iter()
        .filter_map(|source| source.api.key.map(|key| key.slot))
        .collect();
    for api in [
        &abuseipdb::API,
        &virustotal::API,
        &hunter::API,
        &numverify::API,
        &greynoise::API,
    ] {
        slots.extend(api.key.map(|key| key.slot));
    }
    slots.extend([
        stolen_tax::KEY_SLOT,
        oathnet::KEY_SLOT,
        wigle::USER_SLOT,
        wigle::TOKEN_SLOT,
        environment::GITHUB_TOKEN_ENV,
        environment::CERTSPOTTER_KEY_ENV,
    ]);
    let text: Vec<String> = slots.iter().map(|slot| format!("{slot}=k")).collect();
    Keys::parse(&text.join("\n")).expect("key lines parse")
}

/// The rows `kind`'s lookup left over `net`, asking only what `chosen` runs, or why it printed no
/// report.
fn rows(
    kind: ScanKind,
    chosen: &Selection,
    net: &Everywhere,
) -> Result<Vec<SourceExecutionOutcome>, String> {
    let transport = Selected::new(net.clone(), chosen.clone());
    let feeds = Feeds::new(Box::new(Selected::new(net.clone(), chosen.clone())), None);
    let keys = keys();
    match kind {
        ScanKind::Ip => match ip_cli::run(&transport, &keys, &feeds, "93.184.216.34", NOW) {
            ip_cli::IpRun::Printed { report, .. } => Ok(report.outcomes),
            ip_cli::IpRun::Network(why) | ip_cli::IpRun::Failed(why) => Err(why),
        },
        ScanKind::Domain => {
            match domain_cli::run(&transport, &keys, &feeds, "huntsman-shop.net", NOW) {
                domain_cli::DomainRun::Printed { report, .. } => Ok(report.outcomes),
                domain_cli::DomainRun::Network(why) | domain_cli::DomainRun::Failed(why) => {
                    Err(why)
                }
            }
        }
        ScanKind::Netblock => match netblock_cli::run(&transport, &feeds, "93.184.216.0/30", NOW) {
            netblock_cli::NetblockRun::Printed { report, .. } => Ok(report.outcomes),
            netblock_cli::NetblockRun::Network(why) | netblock_cli::NetblockRun::Failed(why) => {
                Err(why)
            }
        },
        ScanKind::Asn => match asn_cli::run(&transport, "AS15133", NOW) {
            asn_cli::AsnRun::Printed { report, .. } => Ok(report.outcomes),
            asn_cli::AsnRun::Network(why) | asn_cli::AsnRun::Failed(why) => Err(why),
        },
        ScanKind::Email => {
            match email_cli::run_keyed(&transport, &keys, "ada@huntsman-shop.net", NOW) {
                email_cli::EmailRun::Printed { report, .. } => Ok(report.outcomes),
                email_cli::EmailRun::Network(why) | email_cli::EmailRun::Failed(why) => Err(why),
            }
        }
        ScanKind::Username => match username_cli::run(&transport, &keys, "ada_lovelace", NOW) {
            username_cli::UsernameRun::Printed { report, .. } => Ok(report.outcomes),
            username_cli::UsernameRun::Failed(why) => Err(why),
        },
        ScanKind::Phone => match phone_cli::run_keyed(&transport, &keys, "+61412345678", NOW) {
            phone_cli::PhoneRun::Printed { report, .. } => Ok(report.outcomes),
            phone_cli::PhoneRun::Failed(why) => Err(why),
        },
        ScanKind::People => match people_cli::run(&transport, "Ada Lovelace", NOW) {
            people_cli::PeopleRun::Printed { report, .. } => Ok(report.outcomes),
            people_cli::PeopleRun::Network(why) | people_cli::PeopleRun::Failed(why) => Err(why),
        },
        ScanKind::Network => {
            match network_cli::run(Some((&transport, &keys)), "00:11:22:33:44:55", NOW) {
                network_cli::NetworkRun::Printed { report, .. } => Ok(report.outcomes),
                network_cli::NetworkRun::Network(why) | network_cli::NetworkRun::Failed(why) => {
                    Err(why)
                }
            }
        }
        ScanKind::CryptoAddress => {
            match crypto_cli::run(&transport, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", NOW) {
                crypto_cli::CryptoRun::Printed { report, .. } => Ok(report.outcomes),
                crypto_cli::CryptoRun::Network(why) | crypto_cli::CryptoRun::Failed(why) => {
                    Err(why)
                }
            }
        }
        ScanKind::Exposure => {
            let sources = exposure_cli::Sources {
                stolen_tax: Some((&transport, &keys)),
                oathnet: Some((&transport, &keys)),
                selection: Some(chosen),
                ..exposure_cli::Sources::default()
            };
            match exposure_cli::run(sources, "ada@huntsman-shop.net", NOW) {
                exposure_cli::ExposureRun::Printed { report, .. } => Ok(report.outcomes),
                exposure_cli::ExposureRun::Network(why)
                | exposure_cli::ExposureRun::Failed(why) => Err(why),
            }
        }
    }
}

/// Modules that parse the target itself and ask nothing, which every lookup runs.
fn offline(module: &str) -> bool {
    reachable_modules()
        .iter()
        .any(|reachable| reachable.name == module && !reachable.network)
}

#[test]
fn every_module_a_lookup_asks_is_on_its_list() {
    for kind in ScanKind::ALL {
        let net = Everywhere::default();
        let rows = rows(kind, &Selection::all(), &net)
            .unwrap_or_else(|why| panic!("{kind:?} printed no report: {why}"));
        let listed = modules(kind);
        for row in &rows {
            let module = module_of(&row.module);
            assert!(
                listed.contains(&module) || offline(module),
                "{kind:?} asked {module}, which its list leaves out"
            );
        }
    }
}

#[test]
fn every_listed_module_is_one_a_scan_can_choose() {
    for kind in ScanKind::ALL {
        for module in modules(kind) {
            let chosen = selection(&[module.to_owned()])
                .unwrap_or_else(|error| panic!("{kind:?} lists {module}: {error}"));
            assert!(chosen.runs(module), "choosing {module} runs it");
            assert!(asks_any(kind, &chosen), "{kind:?} asks {module}");
        }
    }
}

#[test]
fn a_lookup_that_asks_no_chosen_module_sends_nothing() {
    let none = Selection::only(Vec::<String>::new());
    for kind in ScanKind::ALL {
        let net = Everywhere::default();
        let rows = rows(kind, &none, &net).unwrap_or_default();
        assert_eq!(
            net.asked(),
            Vec::<String>::new(),
            "{kind:?} asked something no module chosen asks"
        );
        for row in &rows {
            assert!(
                offline(module_of(&row.module)),
                "{kind:?} left a row for {}",
                row.module
            );
        }
        assert!(!asks_any(kind, &none));
    }
}

/// A module each lookup that can fail answers over [`Everywhere`], chosen beside another so the
/// lookup prints every row it left.
fn anchor(kind: ScanKind) -> Option<&'static str> {
    match kind {
        ScanKind::Ip | ScanKind::Netblock => Some("voipbl"),
        ScanKind::Domain => Some(certspotter::SOURCE),
        ScanKind::Asn => Some(ripestat::SOURCE),
        ScanKind::Email => Some(gravatar::SRC),
        ScanKind::People => Some("asic_persons"),
        ScanKind::Username
        | ScanKind::Phone
        | ScanKind::Network
        | ScanKind::Exposure
        | ScanKind::CryptoAddress => None,
    }
}

#[test]
fn a_lookup_asks_only_the_chosen_modules() {
    for kind in ScanKind::ALL {
        for module in modules(kind) {
            let net = Everywhere::default();
            let chosen: Vec<&str> = std::iter::once(module).chain(anchor(kind)).collect();
            let rows = rows(kind, &Selection::only(chosen.clone()), &net)
                .unwrap_or_else(|why| panic!("{kind:?} with {chosen:?} printed no report: {why}"));
            for row in rows {
                let asked = module_of(&row.module);
                assert!(
                    chosen.contains(&asked) || offline(asked),
                    "{kind:?} with {chosen:?} chosen asked {asked}"
                );
            }
        }
    }
}

#[test]
fn a_chosen_module_still_runs() {
    for (kind, module) in [
        (ScanKind::Ip, internetdb::SOURCE),
        (ScanKind::Ip, "spamhaus"),
        (ScanKind::Ip, "torexits"),
        (ScanKind::Domain, "crtsh"),
        (ScanKind::Domain, "adguard_dns"),
        (ScanKind::Netblock, crate::dns::RESOLVE_SOURCE),
        (ScanKind::Asn, rdap::SOURCE),
        (ScanKind::Email, openpgp_keys::SRC),
        (ScanKind::Username, github_user::SRC),
        (ScanKind::People, "asic_director"),
        (ScanKind::Exposure, oathnet::SOURCE),
    ] {
        let net = Everywhere::default();
        let chosen: Vec<&str> = std::iter::once(module).chain(anchor(kind)).collect();
        let rows = rows(kind, &Selection::only(chosen), &net)
            .unwrap_or_else(|why| panic!("{kind:?} with {module} printed no report: {why}"));
        assert!(
            rows.iter().any(|row| module_of(&row.module) == module),
            "{kind:?} with {module} chosen did not run it: {rows:?}"
        );
    }
}

#[test]
fn a_spiderfoot_name_chooses_every_module_that_does_its_work() {
    let chosen = selection(&["sfp_abusech".to_owned(), " SFP_Spamhaus ".to_owned()])
        .expect("Spiderfoot names choose modules");
    for module in ["abusech", "urlhaus", "threatfox", "spamhaus"] {
        assert!(
            chosen.runs(module),
            "sfp_abusech or sfp_spamhaus runs {module}"
        );
    }
    assert!(!chosen.runs("shodan"));
    let resolve = selection(&["sfp_dnsresolve".to_owned()]).expect("a Spiderfoot name");
    assert!(resolve.runs("dns") && resolve.runs("dnsresolve"));
    assert!(selection(&[]).expect("no name").is_all());
    let error = selection(&[
        "shodan".to_owned(),
        "sfp_spider".to_owned(),
        "nope".to_owned(),
    ])
    .expect_err("unknown names are refused");
    assert!(error.contains("sfp_spider, nope"), "{error}");
}

#[test]
fn each_module_names_the_lookups_that_ask_it() {
    assert_eq!(lookups_asking("spamhaus"), ["domain", "ip"]);
    assert_eq!(lookups_asking("rdap"), ["domain", "ip", "netblock", "asn"]);
    assert_eq!(lookups_asking("oathnet"), ["email", "exposure", "username"]);
    assert_eq!(lookups_asking("wigle"), ["network"]);
    assert!(lookups_asking("source_registry").is_empty());
}
