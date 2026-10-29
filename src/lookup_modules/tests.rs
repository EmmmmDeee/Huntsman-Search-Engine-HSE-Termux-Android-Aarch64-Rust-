use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use super::*;
use crate::dehashed::DehashedClient;
use crate::hibp::rate_limit::RateLimiter;
use crate::hibp::{ApiKey, Auth, HibpClient, HibpConfig};
use crate::http::{Request, Response, Transport, TransportFailure};
use crate::keys::{Keys, Secret};
use crate::module::{module_of, reachable_modules, selection};
use crate::module_selection::Selected;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceRun};
use crate::test_support::{Attempt, Failing, Recording, Refusing, Silent};
use crate::threat_feeds::Feeds;
use crate::{
    asn_cli, crypto_cli, domain_cli, email_cli, environment, exposure_cli, ip_cli, netblock_cli,
    network_cli, nominatim_cli, people_cli, phone_cli, stolen_tax, username_cli,
};

const NOW: u64 = 1_760_000_000;

/// A `RIPEstat` answer every data call reads as knowing nothing.
const RIPESTAT: &[u8] =
    br#"{"status":"ok","data":{"announced":false,"prefixes":[],"neighbours":[],"resources":[]}}"#;

/// One Nominatim place, as its forward search lists it and its reverse search returns it.
const PLACE: &[u8] = br#"{"osm_type":"way","osm_id":1,"lat":"48.8584","lon":"2.2945","category":"tourism","type":"attraction","place_rank":30,"importance":0.5,"addresstype":"tourism","name":"Eiffel Tower","display_name":"Eiffel Tower, Paris, France","address":{"tourism":"Eiffel Tower","city":"Paris","country":"France","country_code":"fr"}}"#;
const PLACES: &[u8] = br#"[{"osm_type":"way","osm_id":1,"lat":"48.8584","lon":"2.2945","category":"tourism","type":"attraction","place_rank":30,"importance":0.5,"addresstype":"tourism","name":"Eiffel Tower","display_name":"Eiffel Tower, Paris, France","address":{"tourism":"Eiffel Tower","city":"Paris","country":"France","country_code":"fr"}}]"#;

/// A network that answers each threat feed with one unlisted address, `RIPEstat` and the CKAN
/// registers with empty data, Nominatim with one place, and everything else "not found"; resolves every name to nothing;
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
        } else if url == crate::base_rpc::RPC_URL {
            (
                200,
                br#"[{"jsonrpc":"2.0","id":1,"result":"0x2105"},{"jsonrpc":"2.0","id":2,"result":"0x0"},{"jsonrpc":"2.0","id":3,"result":"0x0"},{"jsonrpc":"2.0","id":4,"result":"0x"}]"#,
            )
        } else if url == crate::eth_rpc::RPC_URL {
            (
                200,
                br#"[{"jsonrpc":"2.0","id":1,"result":"0x1"},{"jsonrpc":"2.0","id":2,"result":"0x0"},{"jsonrpc":"2.0","id":3,"result":"0x0"},{"jsonrpc":"2.0","id":4,"result":"0x"}]"#,
            )
        } else if url.contains("earth-search") {
            (200, br#"{"type":"FeatureCollection","features":[]}"#)
        } else if url.contains("opensky-network.org") {
            (200, br#"{"time":1,"states":null}"#)
        } else if url.contains("nominatim") {
            (
                200,
                if url.contains("/reverse?") {
                    PLACE
                } else {
                    PLACES
                },
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

/// How a lookup ended, as `profiles::source_report` maps it to an exit status.
#[derive(Debug)]
enum Verdict {
    /// It printed its report (exit 0), with every row it left.
    Printed(Vec<SourceExecutionOutcome>),
    /// A network refusal (`SourceRun::Network`, exit 77), with its reason.
    Refused(String),
    /// No usable response (`SourceRun::Failed`, exit 69), with its reason.
    Unavailable(String),
}

/// The verdict of a lookup that ends as a [`SourceRun`], reading its report's rows with `rows`.
fn ended<R>(run: SourceRun<R>, rows: impl FnOnce(R) -> Vec<SourceExecutionOutcome>) -> Verdict {
    match run {
        SourceRun::Printed { report, .. } => Verdict::Printed(rows(report)),
        SourceRun::Network(why) => Verdict::Refused(why),
        SourceRun::Failed(why) => Verdict::Unavailable(why),
    }
}

/// How `kind`'s lookup of `target` at `now` ended over `net`, asking only what `chosen` runs, with
/// a key for every keyed leg.
fn verdict<N: Transport + Clone + Send + Sync + 'static>(
    kind: ScanKind,
    target: &str,
    chosen: &Selection,
    net: &N,
    now: u64,
) -> Verdict {
    let transport = Selected::new(net.clone(), chosen.clone());
    let feeds = Feeds::new(Box::new(Selected::new(net.clone(), chosen.clone())), None);
    let keys = keys();
    match kind {
        ScanKind::Ip => ended(
            ip_cli::run(&transport, &keys, &feeds, target, now),
            |report| report.outcomes,
        ),
        ScanKind::Domain => ended(
            domain_cli::run(&transport, &keys, &feeds, target, now),
            |report| report.outcomes,
        ),
        ScanKind::Netblock => ended(
            netblock_cli::run(&transport, &feeds, target, now),
            |report| report.outcomes,
        ),
        ScanKind::Asn => ended(asn_cli::run(&transport, target, now), |report| {
            report.outcomes
        }),
        ScanKind::Network => ended(
            network_cli::run(Some((&transport, &keys)), target, now),
            |report| report.outcomes,
        ),
        ScanKind::CryptoAddress => ended(crypto_cli::run(&transport, target, now), |report| {
            report.outcomes
        }),
        ScanKind::Place => ended(nominatim_cli::run(&transport, target, now), |report| {
            report.outcomes
        }),
        ScanKind::Email => match email_cli::run_keyed(&transport, &keys, target, now) {
            email_cli::EmailRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            email_cli::EmailRun::Network(why) => Verdict::Refused(why),
            email_cli::EmailRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::Username => match username_cli::run(&transport, &keys, target, now) {
            username_cli::UsernameRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            username_cli::UsernameRun::Network(why) => Verdict::Refused(why),
            username_cli::UsernameRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::Phone => match phone_cli::run_keyed(&transport, &keys, target, now) {
            phone_cli::PhoneRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            phone_cli::PhoneRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::People => match people_cli::run(&transport, target, now) {
            people_cli::PeopleRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            people_cli::PeopleRun::Network(why) => Verdict::Refused(why),
            people_cli::PeopleRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::Exposure => exposure(&transport, &keys, target, chosen, net, now),
    }
}

/// The exposure lookup of `target` at `now` with every breach leg configured: HIBP and `DeHashed`
/// over `net` with local pacing off, stolen.tax and `OathNet` over `transport`.
fn exposure<N: Transport + Clone + Send + Sync + 'static>(
    transport: &(dyn Transport + Sync),
    keys: &Keys,
    target: &str,
    chosen: &Selection,
    net: &N,
    now: u64,
) -> Verdict {
    let key = ApiKey::new("0123456789abcdef0123456789abcdef").expect("a valid HIBP key");
    let hibp = HibpClient::with_config(
        Arc::new(net.clone()),
        Auth::ApiKey(key),
        HibpConfig::default(),
        Arc::new(RateLimiter::per_minute(0)),
    );
    let secret = Secret::new("dh-test-key-0123456789").unwrap_or_else(|e| panic!("{e}"));
    let dehashed =
        DehashedClient::with_limiter(Arc::new(net.clone()), secret, RateLimiter::per_minute(0));
    let sources = exposure_cli::Sources {
        hibp: Some(&hibp),
        stolen_tax: Some((transport, keys)),
        oathnet: Some((transport, keys)),
        dehashed: Some(&dehashed),
        selection: Some(chosen),
    };
    match exposure_cli::run(sources, target, now) {
        exposure_cli::ExposureRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
        exposure_cli::ExposureRun::Network(why) => Verdict::Refused(why),
        exposure_cli::ExposureRun::Failed(why) => Verdict::Unavailable(why),
    }
}

/// The rows `kind`'s lookup of its [`target`] left over `net`, asking only what `chosen` runs, or
/// why it printed no report.
fn rows(
    kind: ScanKind,
    chosen: &Selection,
    net: &Everywhere,
) -> Result<Vec<SourceExecutionOutcome>, String> {
    match verdict(kind, target(kind), chosen, net, NOW) {
        Verdict::Printed(rows) => Ok(rows),
        Verdict::Refused(why) | Verdict::Unavailable(why) => Err(why),
    }
}

/// The selector each lookup kind's tests look up.
const fn target(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Ip => "93.184.216.34",
        ScanKind::Domain => "huntsman-shop.net",
        ScanKind::Netblock => "93.184.216.0/30",
        ScanKind::Asn => "AS15133",
        ScanKind::Email | ScanKind::Exposure => "ada@huntsman-shop.net",
        ScanKind::Username => "ada_lovelace",
        ScanKind::Phone => "+61412345678",
        ScanKind::People => "Ada Lovelace",
        ScanKind::Network => "00:11:22:33:44:55",
        ScanKind::CryptoAddress => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ScanKind::Place => "Eiffel Tower",
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
        ScanKind::Username => Some(keybase::SRC),
        ScanKind::Phone
        | ScanKind::Network
        | ScanKind::Exposure
        | ScanKind::CryptoAddress
        | ScanKind::Place => None,
    }
}

#[test]
fn a_lookup_asks_only_the_chosen_modules() {
    for kind in ScanKind::ALL {
        for module in modules(kind) {
            let net = Everywhere::default();
            let chosen: Vec<&str> = std::iter::once(module).chain(anchor(kind)).collect();
            let address = if kind == ScanKind::CryptoAddress && module == crate::base_rpc::SOURCE {
                "base:0x1111111111111111111111111111111111111111"
            } else if kind == ScanKind::CryptoAddress && module == crate::eth_rpc::SOURCE {
                "eth:0x1111111111111111111111111111111111111111"
            } else if kind == ScanKind::Place
                && (module == crate::stac::SOURCE || module == crate::opensky::SOURCE)
            {
                // The imagery catalogue and the aircraft states take a point, not a place name.
                "-33.8688,151.2093"
            } else {
                target(kind)
            };
            let rows = match verdict(kind, address, &Selection::only(chosen.clone()), &net, NOW) {
                Verdict::Printed(rows) => rows,
                Verdict::Refused(why) | Verdict::Unavailable(why) => {
                    panic!("{kind:?} with {chosen:?} printed no report: {why}")
                }
            };
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

/// Each use case leaves every lookup a module to ask, so no target is refused for its use case
/// alone, and Footprint and Investigate are each narrower than All.
#[test]
fn every_use_case_leaves_each_lookup_a_module_to_ask() {
    for usecase in crate::scan_service::USE_CASES {
        let chosen = crate::module::use_case_selection(usecase, &Selection::all());
        for kind in ScanKind::ALL {
            assert!(
                asks_any(kind, &chosen),
                "{usecase} leaves the {kind:?} lookup nothing to ask"
            );
        }
    }
    for usecase in ["footprint", "investigate"] {
        let chosen = crate::module::use_case_selection(usecase, &Selection::all());
        assert!(
            ScanKind::ALL
                .iter()
                .any(|kind| modules(*kind).iter().any(|module| !chosen.runs(module))),
            "{usecase} runs every module, so it is All under another name"
        );
    }
}

#[test]
fn each_module_names_the_lookups_that_ask_it() {
    assert_eq!(lookups_asking("spamhaus"), ["domain", "ip"]);
    assert_eq!(lookups_asking("rdap"), ["domain", "ip", "netblock", "asn"]);
    assert_eq!(lookups_asking("oathnet"), ["email", "exposure", "username"]);
    assert_eq!(lookups_asking("wigle"), ["network"]);
    assert!(lookups_asking("source_registry").is_empty());
    // The labels a Sources table shows for a module's legs name the module's lookups too.
    assert_eq!(lookups_asking("hibp_account"), ["email", "exposure"]);
    assert_eq!(lookups_asking("wigle_bluetooth"), ["network"]);
    assert_eq!(lookups_asking("asic_persons.banned"), ["people"]);
}

/// A name the Sources table shows chooses the module whose leg it labels, so a scan can be re-run
/// with just that source by the name the page showed.
#[test]
fn a_source_label_chooses_its_module() {
    let hibp = selection(&["hibp_account".to_owned()]).expect("hibp_account names hibp");
    assert!(hibp.runs("hibp") && !hibp.runs("oathnet"));
    assert!(asks_any(ScanKind::Email, &hibp) && asks_any(ScanKind::Exposure, &hibp));
    let bluetooth =
        selection(&["WiGLE_Bluetooth".to_owned()]).expect("wigle_bluetooth names wigle");
    assert!(bluetooth.runs("wigle"));
    assert!(asks_any(ScanKind::Network, &bluetooth));
    let part = selection(&["asic_persons.banned".to_owned()]).expect("a part names its module");
    assert!(part.runs("asic_persons"));
    let leg_part = selection(&["hibp_account.breach".to_owned()]).expect("a leg's part names it");
    assert!(leg_part.runs("hibp"));
    let error = selection(&["nonesuch.part".to_owned()]).expect_err("an unknown part is refused");
    assert!(error.contains("nonesuch.part"), "{error}");
}

/// The offline modules a lookup runs over the target itself are reachable modules no lookup asks,
/// and every offline row a lookup leaves is one of them, so the page can say "always runs offline
/// in" for exactly the modules a scan's Sources table shows without a network leg.
#[test]
fn offline_modules_a_lookup_runs_are_named_and_asked_by_none() {
    for kind in ScanKind::ALL {
        let runs = offline_runs(kind);
        for module in &runs {
            assert!(
                offline(module),
                "{kind:?} runs {module}, which is not an offline module"
            );
            assert!(
                !modules(kind).contains(module),
                "{kind:?} lists {module}, which asks nothing"
            );
            assert!(
                lookups_asking(module).is_empty(),
                "{module} is asked by a lookup"
            );
            assert!(
                lookups_running_offline(module).contains(&kind.command()),
                "{module} does not name {kind:?}"
            );
        }
        let net = Everywhere::default();
        let rows = rows(kind, &Selection::all(), &net)
            .unwrap_or_else(|why| panic!("{kind:?} printed no report: {why}"));
        let left: Vec<&str> = rows
            .iter()
            .map(|row| module_of(&row.module))
            .filter(|module| offline(module))
            .collect();
        for module in &left {
            assert!(
                runs.contains(module),
                "{kind:?} left an offline row for {module}, which offline_runs leaves out"
            );
        }
        if matches!(kind, ScanKind::Phone | ScanKind::Network) {
            let mut left = left;
            left.sort_unstable();
            left.dedup();
            let mut runs = runs;
            runs.sort_unstable();
            assert_eq!(
                left, runs,
                "{kind:?} runs other offline modules than it names"
            );
        }
    }
    assert_eq!(lookups_running_offline("phone_au"), ["phone"]);
    assert_eq!(lookups_running_offline("oui"), ["network"]);
    assert!(lookups_running_offline("rdap").is_empty());
    assert!(lookups_running_offline("exif").is_empty());
}

/// The network a refusal contract case runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Net {
    /// [`Refusing`]: the egress policy refuses every HTTP request and UDP exchange.
    Refusing,
    /// [`Silent`]: no HTTP response, no system resolver answer and no UDP answer.
    Silent,
    /// [`Failing`]: every source answers HTTP 500.
    Failing,
}

/// The lookups the refusal contract holds. Each ends from its rows: a refusal (exit 77) when a
/// chosen source was refused before anything was sent, unavailable (exit 69) when it got no
/// response.
const IN_SCOPE: [ScanKind; 8] = [
    ScanKind::Ip,
    ScanKind::Netblock,
    ScanKind::Asn,
    ScanKind::Domain,
    ScanKind::Email,
    ScanKind::Username,
    ScanKind::Exposure,
    ScanKind::Network,
];

/// Every `(kind, module, net)` that breaks the refusal contract today: the module, chosen alone,
/// breaks it over `net` for at least one of its [`targets`]. Each net's broken set must equal its
/// entries here exactly: a module that newly breaks the contract fails naming it, and so does an
/// entry no case breaks any more. The refusal-routing plan seeded 203 triples and deleted each
/// one as it fixed it; the last, stolen.tax reporting no response as a path failure with no
/// transport kind, left with [`crate::stolen_tax::PathFailure::kind`]. Empty is the contract
/// held in full; an entry is a reviewed, named exception, never a second list.
const BROKEN: &[(ScanKind, &str, Net)] = &[];

/// Every `(kind, module, target)` case whose module, chosen alone, asks nothing: domain
/// `dnsresolve` resolves only the hosts other sources found; the profile front-ends, not the
/// email and username lookups, run seeknow and the breach modules; `ada_lovelace` is no GitHub
/// login or Bluesky handle; `WiGLE` takes no cell and `OpenCelliD` no SSID. Over every net the
/// cases that asked nothing must be exactly these (the three nets agree), so a module that falls
/// silent (a renamed key slot, a `runs_module` name that no longer matches, a pacing hold) fails
/// instead of passing with nothing to hold it to.
const ASKS_NOTHING: &[(ScanKind, &str, &str)] = &[
    (ScanKind::Domain, "dnsresolve", "huntsman-shop.net"),
    (ScanKind::Email, "seeknow", "ada@huntsman-shop.net"),
    (ScanKind::Email, "hibp", "ada@huntsman-shop.net"),
    (ScanKind::Email, "stolen_tax", "ada@huntsman-shop.net"),
    (ScanKind::Email, "oathnet", "ada@huntsman-shop.net"),
    (ScanKind::Email, "dehashed", "ada@huntsman-shop.net"),
    (ScanKind::Username, "github_user", "ada_lovelace"),
    (ScanKind::Username, "github_repos", "ada_lovelace"),
    (ScanKind::Username, "bluesky_user", "ada_lovelace"),
    (ScanKind::Username, "crates_io", "ada_lovelace"),
    (ScanKind::Username, "seeknow", "ada_lovelace"),
    (ScanKind::Username, "seeknow", "adalovelace"),
    (ScanKind::Username, "stolen_tax", "ada_lovelace"),
    (ScanKind::Username, "stolen_tax", "adalovelace"),
    (ScanKind::Username, "oathnet", "ada_lovelace"),
    (ScanKind::Username, "oathnet", "adalovelace"),
    (ScanKind::Network, "wigle", "cell:505:01:17:91"),
    (ScanKind::Network, "opencellid", "ssid:Cafe Guest"),
];

/// A time past every pacing hold another test can leave at a real host. A probe at it reaches
/// every host its case asks, so the case can close their circuits before it runs.
const PROBE_NOW: u64 = NOW + 1_000_000_000;

/// Held by each contract test while it runs, so their failures at the same real hosts never
/// interleave in the process-wide pacing breaker. A test that panics poisons it; the others
/// still take it.
static CONTRACT: Mutex<()> = Mutex::new(());

/// The selectors the contract looks up for `kind`. A network lookup takes each selector form that
/// asks a source; a BSSID is left out, because its OUI row always answers. `ada_lovelace` is no
/// GitHub login or Bluesky handle, so a username lookup also takes `adalovelace`, which every
/// profile source asks about.
fn targets(kind: ScanKind) -> Vec<&'static str> {
    match kind {
        ScanKind::Network => vec!["ssid:Cafe Guest", "cell:505:01:17:91", "-27.47,153.02"],
        ScanKind::Username => vec![target(kind), "adalovelace"],
        _ => vec![target(kind)],
    }
}

/// What `kind`'s lookup of `target` says before its reason when no source answered.
fn lead(kind: ScanKind, target: &str) -> String {
    match kind {
        ScanKind::Ip => format!("no source answered for ip {target}"),
        ScanKind::Netblock => format!("no source answered for netblock {target}"),
        ScanKind::Domain => format!("no source answered for domain {target}"),
        ScanKind::Network => "no source answered the network lookup".to_owned(),
        _ => format!("no source answered for {target}"),
    }
}

/// The module `why` names: past `lead` and its `": "` when it starts with them, the text before
/// the first `':'`.
fn named<'a>(why: &'a str, lead: &str) -> &'a str {
    let why = why
        .strip_prefix(lead)
        .and_then(|rest| rest.strip_prefix(": "))
        .unwrap_or(why);
    why.split(':').next().unwrap_or(why)
}

/// One module chosen alone for one target: what it asked, and how its lookup ended.
#[derive(Debug)]
struct Case {
    kind: ScanKind,
    module: &'static str,
    target: &'static str,
    asked: Vec<Attempt>,
    verdict: Verdict,
}

impl Case {
    /// Whether `why` names this case's module, by [`module_of`], so `hibp_account` names `hibp`.
    fn names_its_module(&self, why: &str) -> bool {
        module_of(named(why, &lead(self.kind, self.target))) == self.module
    }

    fn refused_naming_it(&self) -> bool {
        matches!(&self.verdict, Verdict::Refused(why) if self.names_its_module(why))
    }

    fn unavailable_naming_it(&self) -> bool {
        matches!(&self.verdict, Verdict::Unavailable(why) if self.names_its_module(why))
    }

    const fn refused(&self) -> bool {
        matches!(self.verdict, Verdict::Refused(_))
    }

    /// Whether the module asked anything at all.
    fn asked_any(&self) -> bool {
        !self.asked.is_empty()
    }

    /// Whether the module sent anything the egress policy can refuse: an HTTP request or a UDP
    /// exchange. The policy never refuses the system resolver.
    fn sent(&self) -> bool {
        self.asked
            .iter()
            .any(|attempt| matches!(attempt, Attempt::Http(_) | Attempt::Udp(_)))
    }

    /// The case on one line, with its first few attempts.
    fn line(&self) -> String {
        let first: Vec<&Attempt> = self.asked.iter().take(3).collect();
        format!(
            "{:?} {} {:?}: {:?} after {} attempts, first {first:?}",
            self.kind,
            self.module,
            self.target,
            self.verdict,
            self.asked.len()
        )
    }
}

/// Close the pacing circuit of every host `asked` sent to. The breaker is shared by the whole
/// process, so the cases' failures at real hosts would otherwise add up with other tests' and
/// could pace a later request down.
fn forget_pacing(asked: &[Attempt]) {
    let hosts = asked.iter().filter_map(|attempt| match attempt {
        Attempt::Http(url) => crate::circuit::host_of(url),
        Attempt::SystemResolver(_) | Attempt::Udp(_) => None,
    });
    for host in hosts {
        crate::circuit::record_success(&host);
    }
}

/// What `module`, chosen alone, asked of a fresh `Recording<N>`, and how `kind`'s lookup of
/// `target` at `now` ended.
fn ask<N: Transport + Clone + Default + Send + Sync + 'static>(
    kind: ScanKind,
    module: &'static str,
    target: &str,
    now: u64,
) -> (Vec<Attempt>, Verdict) {
    let net = Recording::new(N::default());
    let verdict = verdict(kind, target, &Selection::only([module]), &net, now);
    (net.attempts(), verdict)
}

/// Every case over `N`: each lookup in [`IN_SCOPE`], each module on its list that is not
/// [`offline`], chosen alone, for each of its [`targets`]. A module that asks nothing for a target
/// is still a case, and [`ASKS_NOTHING`] lists it. A probe at [`PROBE_NOW`] first learns the hosts
/// the case reaches, and their pacing circuits are closed before the case runs and again after.
fn cases<N: Transport + Clone + Default + Send + Sync + 'static>() -> Vec<Case> {
    let mut cases = Vec::new();
    for kind in IN_SCOPE {
        for module in modules(kind).into_iter().filter(|module| !offline(module)) {
            for target in targets(kind) {
                let (probed, _) = ask::<N>(kind, module, target, PROBE_NOW);
                forget_pacing(&probed);
                let (asked, verdict) = ask::<N>(kind, module, target, NOW);
                forget_pacing(&asked);
                cases.push(Case {
                    kind,
                    module,
                    target,
                    asked,
                    verdict,
                });
            }
        }
    }
    cases
}

/// `(kind, module, net)` as a [`BROKEN`] entry, in Rust.
fn triple(kind: ScanKind, module: &str, net: Net) -> String {
    format!("(ScanKind::{kind:?}, {module:?}, Net::{net:?})")
}

/// `(kind, module, target)` as an [`ASKS_NOTHING`] entry, in Rust.
fn silent((kind, module, target): &(ScanKind, &str, &str)) -> String {
    format!("(ScanKind::{kind:?}, {module:?}, {target:?})")
}

/// Hold every case over `net` to the refusal contract:
///
/// - a case that asked nothing is never a refusal, whatever [`BROKEN`] lists;
/// - the cases that asked nothing are exactly [`ASKS_NOTHING`];
/// - every case that asked something `keeps` the contract, except that the `(kind, module)` pairs
///   it breaks for are exactly [`BROKEN`]'s entries for `net`.
///
/// On failure the message names each difference, says how many cases asked something, and gives
/// `BROKEN`'s entries for `net` and the `ASKS_NOTHING` list as this run found them, in Rust.
fn hold(net: Net, cases: &[Case], keeps: impl Fn(&Case) -> bool) {
    let mut wrong: Vec<String> = cases
        .iter()
        .filter(|case| !case.asked_any() && case.refused())
        .map(|case| format!("  asked nothing, yet is a refusal: {}", case.line()))
        .collect();

    let quiet: Vec<(ScanKind, &str, &str)> = cases
        .iter()
        .filter(|case| !case.asked_any())
        .map(|case| (case.kind, case.module, case.target))
        .collect();
    wrong.extend(
        quiet
            .iter()
            .filter(|case| !ASKS_NOTHING.contains(case))
            .map(|case| {
                format!(
                    "  asked nothing, unlisted in ASKS_NOTHING: {}",
                    silent(case)
                )
            }),
    );
    wrong.extend(
        ASKS_NOTHING
            .iter()
            .filter(|listed| !quiet.contains(listed))
            .map(|listed| {
                format!(
                    "  stale ASKS_NOTHING entry, asked or never run: {}",
                    silent(listed)
                )
            }),
    );

    let breaks = |case: &&Case| case.asked_any() && !keeps(case);
    let mut broken: Vec<(ScanKind, &str)> = cases
        .iter()
        .filter(breaks)
        .map(|case| (case.kind, case.module))
        .collect();
    broken.dedup();
    let listed: Vec<(ScanKind, &str)> = BROKEN
        .iter()
        .filter(|(_, _, listed)| *listed == net)
        .map(|(kind, module, _)| (*kind, *module))
        .collect();
    wrong.extend(
        cases
            .iter()
            .filter(breaks)
            .filter(|case| !listed.contains(&(case.kind, case.module)))
            .map(|case| format!("  new breakage, which BROKEN leaves out: {}", case.line())),
    );
    wrong.extend(
        listed
            .iter()
            .filter(|pair| !broken.contains(pair))
            .map(|(kind, module)| {
                let entry = triple(*kind, module, net);
                format!("  stale BROKEN entry, no case breaks it: {entry}")
            }),
    );
    if wrong.is_empty() {
        return;
    }

    let asking = cases.iter().filter(|case| case.asked_any()).count();
    let broken_now: Vec<String> = broken
        .iter()
        .map(|(kind, module)| format!("    {},", triple(*kind, module, net)))
        .collect();
    let quiet_now: Vec<String> = quiet
        .iter()
        .map(|case| format!("    {},", silent(case)))
        .collect();
    panic!(
        "the refusal contract over Net::{net:?}: {asking} of {} cases asked something.\n\
         {} differences:\n{}\n\
         BROKEN's Net::{net:?} entries, as this run found them:\n{}\n\
         ASKS_NOTHING, as this run found it:\n&[\n{}\n]",
        cases.len(),
        wrong.len(),
        wrong.join("\n"),
        broken_now.join("\n"),
        quiet_now.join("\n"),
    );
}

/// A module chosen alone whose requests the egress policy refused is a refusal (exit 77) naming
/// it. One that asked only the system resolver, which the policy never refuses, got no response
/// (exit 69) and names it. One that asked nothing is never a refusal.
#[test]
fn a_module_chosen_alone_and_refused_is_a_refusal_naming_it() {
    let _serial = CONTRACT.lock().unwrap_or_else(PoisonError::into_inner);
    hold(Net::Refusing, &cases::<Refusing>(), |case| {
        if case.sent() {
            case.refused_naming_it()
        } else {
            case.unavailable_naming_it()
        }
    });
}

/// A module chosen alone that got no response is unavailable (exit 69) naming it, never a
/// refusal. One that asked nothing is never a refusal.
#[test]
fn a_module_chosen_alone_without_a_response_is_unavailable_naming_it() {
    let _serial = CONTRACT.lock().unwrap_or_else(PoisonError::into_inner);
    hold(Net::Silent, &cases::<Silent>(), Case::unavailable_naming_it);
}

/// A source that answered, even with an error, was reached, so its lookup is never a refusal.
#[test]
fn a_module_whose_source_answered_with_an_error_is_never_a_refusal() {
    let _serial = CONTRACT.lock().unwrap_or_else(PoisonError::into_inner);
    hold(Net::Failing, &cases::<Failing>(), |case| !case.refused());
}

/// Every module the catalogue lists under `people NAME` is one the people lookup asks, so a
/// source `people` stopped asking cannot stay listed as reachable through it.
#[test]
fn every_module_listed_under_people_is_one_it_asks() {
    for module in reachable_modules()
        .iter()
        .filter(|module| module.command == "people NAME")
    {
        assert_eq!(lookups_asking(module.name), ["people"], "{}", module.name);
    }
}
