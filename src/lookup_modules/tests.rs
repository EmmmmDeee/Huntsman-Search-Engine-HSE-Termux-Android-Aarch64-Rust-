use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

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

/// How `kind`'s lookup of `target` ended over `net`, asking only what `chosen` runs, with a key
/// for every keyed leg.
fn verdict<N: Transport + Clone + Send + Sync + 'static>(
    kind: ScanKind,
    target: &str,
    chosen: &Selection,
    net: &N,
) -> Verdict {
    let transport = Selected::new(net.clone(), chosen.clone());
    let feeds = Feeds::new(Box::new(Selected::new(net.clone(), chosen.clone())), None);
    let keys = keys();
    match kind {
        ScanKind::Ip => ended(
            ip_cli::run(&transport, &keys, &feeds, target, NOW),
            |report| report.outcomes,
        ),
        ScanKind::Domain => ended(
            domain_cli::run(&transport, &keys, &feeds, target, NOW),
            |report| report.outcomes,
        ),
        ScanKind::Netblock => ended(
            netblock_cli::run(&transport, &feeds, target, NOW),
            |report| report.outcomes,
        ),
        ScanKind::Asn => ended(asn_cli::run(&transport, target, NOW), |report| {
            report.outcomes
        }),
        ScanKind::Network => ended(
            network_cli::run(Some((&transport, &keys)), target, NOW),
            |report| report.outcomes,
        ),
        ScanKind::CryptoAddress => ended(crypto_cli::run(&transport, target, NOW), |report| {
            report.outcomes
        }),
        ScanKind::Email => match email_cli::run_keyed(&transport, &keys, target, NOW) {
            email_cli::EmailRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            email_cli::EmailRun::Network(why) => Verdict::Refused(why),
            email_cli::EmailRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::Username => match username_cli::run(&transport, &keys, target, NOW) {
            username_cli::UsernameRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            username_cli::UsernameRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::Phone => match phone_cli::run_keyed(&transport, &keys, target, NOW) {
            phone_cli::PhoneRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            phone_cli::PhoneRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::People => match people_cli::run(&transport, target, NOW) {
            people_cli::PeopleRun::Printed { report, .. } => Verdict::Printed(report.outcomes),
            people_cli::PeopleRun::Network(why) => Verdict::Refused(why),
            people_cli::PeopleRun::Failed(why) => Verdict::Unavailable(why),
        },
        ScanKind::Exposure => exposure(&transport, &keys, target, chosen, net),
    }
}

/// The exposure lookup of `target` with every breach leg configured: HIBP and `DeHashed` over
/// `net` with local pacing off, stolen.tax and `OathNet` over `transport`.
fn exposure<N: Transport + Clone + Send + Sync + 'static>(
    transport: &(dyn Transport + Sync),
    keys: &Keys,
    target: &str,
    chosen: &Selection,
    net: &N,
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
    match exposure_cli::run(sources, target, NOW) {
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
    match verdict(kind, target(kind), chosen, net) {
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

/// The lookups that do not keep the contract over a network yet, as the first run found them. Each
/// entry must still break it in at least one case, so the fix that makes a lookup keep it fails
/// until its entry is deleted: the list only shrinks.
const PENDING: &[(ScanKind, Net)] = &[
    (ScanKind::Ip, Net::Refusing),
    (ScanKind::Netblock, Net::Refusing),
    (ScanKind::Asn, Net::Refusing),
    (ScanKind::Domain, Net::Refusing),
    (ScanKind::Email, Net::Refusing),
    (ScanKind::Username, Net::Refusing),
    (ScanKind::Exposure, Net::Refusing),
    (ScanKind::Network, Net::Refusing),
    (ScanKind::Ip, Net::Silent),
    (ScanKind::Netblock, Net::Silent),
    (ScanKind::Asn, Net::Silent),
    (ScanKind::Domain, Net::Silent),
    (ScanKind::Username, Net::Silent),
    (ScanKind::Exposure, Net::Silent),
    (ScanKind::Network, Net::Silent),
];

/// Modules that break the contract over a network for a reason outside their lookup: stolen.tax
/// reports no response as a path failure that carries no transport kind. Held to the same rule as
/// [`PENDING`].
const KNOWN_GAPS: &[(ScanKind, &str, Net)] = &[(ScanKind::Exposure, "stolen_tax", Net::Silent)];

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

/// Every case over `N`: each lookup in [`IN_SCOPE`], each module on its list that asks anything,
/// chosen alone, for each of its [`targets`].
fn cases<N: Transport + Clone + Default + Send + Sync + 'static>() -> Vec<Case> {
    let mut cases = Vec::new();
    for kind in IN_SCOPE {
        for module in modules(kind).into_iter().filter(|module| !offline(module)) {
            for target in targets(kind) {
                let net = Recording::new(N::default());
                let verdict = verdict(kind, target, &Selection::only([module]), &net);
                let asked = net.attempts();
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

/// Hold every case over `net` to `keeps`, except the lookups [`PENDING`] and the modules
/// [`KNOWN_GAPS`] list, and hold each entry listed for `net` to still breaking it in at least one
/// case. On failure the message gives what this run calls for as Rust literals.
fn ratchet(net: Net, cases: &[Case], keeps: impl Fn(&Case) -> bool) {
    let broken: Vec<&Case> = cases.iter().filter(|case| !keeps(case)).collect();
    let unexpected: Vec<String> = broken
        .iter()
        .filter(|case| {
            !PENDING.contains(&(case.kind, net))
                && !KNOWN_GAPS.contains(&(case.kind, case.module, net))
        })
        .map(|case| format!("  {}", case.line()))
        .collect();
    let stale_pending = PENDING
        .iter()
        .filter(|(kind, listed)| *listed == net && !broken.iter().any(|case| case.kind == *kind))
        .map(|(kind, _)| format!("  PENDING (ScanKind::{kind:?}, Net::{net:?})"));
    let stale_gaps = KNOWN_GAPS
        .iter()
        .filter(|(kind, module, listed)| {
            *listed == net
                && !broken
                    .iter()
                    .any(|case| case.kind == *kind && case.module == *module)
        })
        .map(|(kind, module, _)| {
            format!("  KNOWN_GAPS (ScanKind::{kind:?}, {module:?}, Net::{net:?})")
        });
    let stale: Vec<String> = stale_pending.chain(stale_gaps).collect();
    if unexpected.is_empty() && stale.is_empty() {
        return;
    }
    let pending: Vec<String> = IN_SCOPE
        .iter()
        .filter(|kind| broken.iter().any(|case| case.kind == **kind))
        .map(|kind| format!("    (ScanKind::{kind:?}, Net::{net:?}),"))
        .collect();
    let mut triples: Vec<String> = broken
        .iter()
        .map(|case| {
            format!(
                "    (ScanKind::{:?}, {:?}, Net::{net:?}),",
                case.kind, case.module
            )
        })
        .collect();
    triples.dedup();
    panic!(
        "the refusal contract over Net::{net:?} ran {} cases.\n\
         {} cases break it that neither PENDING nor KNOWN_GAPS lists:\n{}\n\
         {} listed entries no case breaks any more; delete them:\n{}\n\
         Every (kind, net) that breaks it over Net::{net:?}, as PENDING entries:\n&[\n{}\n]\n\
         Every (kind, module, net) that breaks it over Net::{net:?}:\n&[\n{}\n]",
        cases.len(),
        unexpected.len(),
        unexpected.join("\n"),
        stale.len(),
        stale.join("\n"),
        pending.join("\n"),
        triples.join("\n"),
    );
}

/// A module chosen alone whose requests the egress policy refused is a refusal (exit 77) naming
/// it. One that asked only the system resolver, which the policy never refuses, got no response
/// (exit 69) and names it. One that asks nothing alone is never a refusal.
#[test]
fn a_module_chosen_alone_and_refused_is_a_refusal_naming_it() {
    ratchet(Net::Refusing, &cases::<Refusing>(), |case| {
        if case.asked.is_empty() {
            !case.refused()
        } else if case.sent() {
            case.refused_naming_it()
        } else {
            case.unavailable_naming_it()
        }
    });
}

/// A module chosen alone that got no response is unavailable (exit 69) naming it, never a
/// refusal. One that asks nothing alone is never a refusal.
#[test]
fn a_module_chosen_alone_without_a_response_is_unavailable_naming_it() {
    ratchet(Net::Silent, &cases::<Silent>(), |case| {
        if case.asked.is_empty() {
            !case.refused()
        } else {
            case.unavailable_naming_it()
        }
    });
}

/// A source that answered, even with an error, was reached, so its lookup is never a refusal.
#[test]
fn a_module_whose_source_answered_with_an_error_is_never_a_refusal() {
    ratchet(Net::Failing, &cases::<Failing>(), |case| !case.refused());
}
