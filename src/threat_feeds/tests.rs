use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::http::{Response, TransportFailure};

/// What the fake network answers for one feed.
#[derive(Debug, Clone)]
enum Reply {
    Body(String),
    Status(u16),
    Truncated,
    Down,
}

/// Each feed's answer by URL, every URL asked recorded. A URL with no answer set is down.
#[derive(Default)]
struct Net {
    replies: Mutex<HashMap<&'static str, Reply>>,
    asked: Mutex<Vec<String>>,
}

impl Net {
    /// Every feed answering with its sample body.
    fn serving() -> Arc<Self> {
        let net = Arc::new(Self::default());
        for feed in FEEDS {
            net.set(feed.id, Reply::Body(sample(feed.id).to_owned()));
        }
        net
    }

    fn set(&self, id: &str, reply: Reply) {
        let feed = FEEDS.iter().find(|feed| feed.id == id).expect("a feed");
        self.replies
            .lock()
            .expect("replies")
            .insert(feed.url, reply);
    }

    fn asked(&self) -> Vec<String> {
        std::mem::take(&mut *self.asked.lock().expect("asked"))
    }
}

/// The fake network as a transport the feeds can own.
struct Shared(Arc<Net>);

impl Transport for Shared {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.0
            .asked
            .lock()
            .expect("asked")
            .push(request.url.clone());
        let reply = self
            .0
            .replies
            .lock()
            .expect("replies")
            .get(request.url.as_str())
            .cloned()
            .unwrap_or(Reply::Down);
        let response = |status, body: &str, truncated| Response {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated,
        };
        match reply {
            Reply::Body(body) => Ok(response(200, &body, false)),
            Reply::Status(status) => Ok(response(status, "", false)),
            Reply::Truncated => Ok(response(200, "192.0.2.1\n", true)),
            Reply::Down => Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "connection refused".into(),
                blocked: false,
            }),
        }
    }
}

/// Each feed's body in the form it is published in, cut down.
fn sample(id: &str) -> &'static str {
    match id {
        "feodotracker" => {
            "################################################################\n\
             # abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #\n\
             # DstIP\n\
             162.243.103.246\n\
             198.51.100.20\n"
        }
        "urlhaus" => {
            "################################################################\n\
             # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\
             \"3001\",\"2026-10-15 19:00:01\",\"http://198.51.100.20:8080/bins/x86\",\"online\",\"2026-10-15 19:00:01\",\"malware_download\",\"elf,mirai\",\"https://urlhaus.abuse.ch/url/3001/\",\"r\"\n\
             \"3002\",\"2026-10-15 19:00:02\",\"https://evil.example/drop.exe\",\"online\",\"\",\"malware_download\",\"exe\",\"https://urlhaus.abuse.ch/url/3002/\",\"r\"\n"
        }
        "alienvaultiprep" => {
            "###\n# Alienvault IP Reputation Database\n###\n\
             198.51.100.20 # Malicious Host NL,Amsterdam,52.37,4.89\n\
             203.0.113.50 # Scanning Host US,,37.75,-97.82\n"
        }
        "blocklistde" => "1.10.247.40\n198.51.100.20\n2001:db8::bad\n",
        "botvrij" => {
            "value,decay_sore,value_type,event_id,event_info\n\
             evil.example,0,domain,8,\"phishing, covid19\"\n\
             other.example,0,domain,9,\"x\"\n"
        }
        "cinsscore" => "1.12.229.231\n198.51.100.20\n",
        "cleantalk" => "#\n# cleantalk_7d\n#\n# ipv4 hash:ip ipset\n#\n2.56.10.21\n198.51.100.20\n",
        "coinblocker" => "# CoinBlocker\nminer.evil.example\npool.example\n",
        "cybercrimetracker" => {
            "5.182.86.32/auth/login\nevil.example/wp-content/plugins/x/mail.php\n"
        }
        "emergingthreats" => "101.33.78.144\n",
        "greensnow" => "194.180.49.70\n",
        "openphish" => "https://login.evil.example/account/\nhttp://[2001:db8::66]:8080/x\n",
        "phishtank" => {
            "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n\
             9544505,\"http://Login.Evil.Example/a,b\",http://www.phishtank.com/phish_detail.php?phish_id=9544505,2026-10-15T09:56:57+00:00,yes,2026-10-15T13:41:50+00:00,yes,Allegro\n"
        }
        "stevenblack_hosts" => {
            "# Title: StevenBlack/hosts\n127.0.0.1 localhost\n127.0.0.1 localhost.localdomain\n\
             255.255.255.255 broadcasthost\n::1 localhost ip6-localhost ip6-loopback\n\
             0.0.0.0 0.0.0.0\n0.0.0.0 ads.example # an advert host\n0.0.0.0 tracker.example\n"
        }
        "torexits" => {
            r#"{"version":"8.0","relays":[
{"nickname":"Quintex152","fingerprint":"0008D9640FE4947F73E355F67E20C2D290BBC72C","or_addresses":["204.8.96.141:444","[2620:7:6003::141]:81"],"exit_addresses":["204.8.96.141"],"country":"us"},
{"nickname":"Other","fingerprint":"AB","or_addresses":["192.0.2.9:9001"],"exit_addresses":["198.51.100.20"]}
]}"#
        }
        "voipbl" => "# TOTAL NETBLOCK: 3\n0.0.0.0/31\n203.0.113.0/28\n192.0.2.77/32\n",
        "vxvault" => {
            "<pre>\nVX Vault last 100 Links\nThu, 15 Oct 2026 19:57:02 +0000\n\
             http://95.155.151.113/d/xd.arm\nhttps://evil.example/stub.txt\n</pre>\n"
        }
        _ => panic!("no sample for {id}"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hse-feeds-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn address(text: &str) -> Subject {
    Subject::Address(text.parse().expect("address"))
}

fn row<'a>(rows: &'a [SourceExecutionOutcome], source: &str) -> &'a SourceExecutionOutcome {
    rows.iter()
        .find(|row| row.module == source)
        .unwrap_or_else(|| panic!("no {source} row in {rows:#?}"))
}

fn detail(rows: &[SourceExecutionOutcome], source: &str) -> String {
    row(rows, source).detail.clone().unwrap_or_default()
}

/// The listings on one subject: (source, feed or tor, the entries kept).
fn listings(entities: &[Entity], value: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = entities
        .iter()
        .filter(|entity| entity.value == value)
        .flat_map(|entity| &entity.evidence)
        .map(|evidence| {
            let attr = |key: &str| evidence.attributes.get(key).cloned().unwrap_or_default();
            let (feed, entries) = if attr("tor") == "true" {
                ("tor".to_owned(), attr("tor_relays"))
            } else {
                (attr("threat_feed"), attr("threat_feed_entries"))
            };
            (evidence.provenance.source.clone(), feed, entries)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_published_form_reads_as_its_entries() {
    let read = |id: &str| {
        let feed = FEEDS.iter().find(|feed| feed.id == id).expect("feed");
        index(feed.format, sample(id))
    };
    let counts: Vec<(&str, usize)> = FEEDS
        .iter()
        .map(|feed| (feed.id, read(feed.id).entries))
        .collect();
    assert_eq!(
        counts,
        [
            ("feodotracker", 2),
            ("urlhaus", 2),
            ("alienvaultiprep", 2),
            ("blocklistde", 3),
            ("botvrij", 2),
            ("cinsscore", 2),
            ("cleantalk", 2),
            ("coinblocker", 2),
            ("cybercrimetracker", 2),
            ("emergingthreats", 1),
            ("greensnow", 1),
            ("openphish", 2),
            ("phishtank", 1),
            ("stevenblack_hosts", 2),
            ("torexits", 2),
            ("voipbl", 3),
            ("vxvault", 2),
        ]
    );
    // A URL's host, with its port, user and brackets taken off and its case folded.
    assert_eq!(
        read("phishtank").lookup(&Subject::Name("login.evil.example".into())),
        [
            "9544505,\"http://Login.Evil.Example/a,b\",http://www.phishtank.com/phish_detail.php?phish_id=9544505,2026-10-15T09:56:57+00:00,yes,2026-10-15T13:41:50+00:00,yes,Allegro"
        ]
    );
    assert_eq!(
        read("openphish").lookup(&address("2001:db8::66")),
        ["http://[2001:db8::66]:8080/x"]
    );
    assert_eq!(read("urlhaus").lookup(&address("198.51.100.20")).len(), 1);
    assert_eq!(
        read("cybercrimetracker").lookup(&address("5.182.86.32")),
        ["5.182.86.32/auth/login"]
    );
    // A block of one address is that address; a wider block holds every address in it.
    let voipbl = read("voipbl");
    assert_eq!(voipbl.lookup(&address("192.0.2.77")), ["192.0.2.77/32"]);
    assert_eq!(voipbl.lookup(&address("203.0.113.9")), ["203.0.113.0/28"]);
    assert!(voipbl.lookup(&address("203.0.113.16")).is_empty());
    // A hosts file's names, never its own loopback names or addresses.
    let hosts = read("stevenblack_hosts");
    assert_eq!(
        hosts.lookup(&Subject::Name("ads.example".into())),
        ["0.0.0.0 ads.example # an advert host"]
    );
    assert!(hosts.addresses.is_empty());
    assert!(
        hosts
            .lookup(&Subject::Name("localhost.localdomain".into()))
            .is_empty()
    );
    // A relay is found by the address it exits from and the addresses it listens on.
    let relays = read("torexits");
    for listens in [
        "204.8.96.141",
        "2620:7:6003::141",
        "192.0.2.9",
        "198.51.100.20",
    ] {
        assert_eq!(relays.lookup(&address(listens)).len(), 1, "{listens}");
    }
    assert!(relays.lookup(&address("204.8.96.141"))[0].contains("\"nickname\":\"Quintex152\""));
    // The HTML around VXVault's list is not an entry.
    assert_eq!(
        read("vxvault").lookup(&Subject::Name("evil.example".into())),
        ["https://evil.example/stub.txt"]
    );
}

#[test]
fn a_lookup_checks_every_subject_and_keeps_each_entry_whole() {
    let net = Net::serving();
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), None);
    let subjects = [
        address("198.51.100.20"),
        Subject::Name("evil.example".into()),
        Subject::Name("ads.example".into()),
        Subject::Block(Netblock::parse("203.0.113.0/24").expect("block")),
        address("192.0.2.200"),
    ];
    let (entities, rows) = check(&feeds, &subjects, "s", now());
    assert_eq!(net.asked().len(), FEEDS.len());
    let address_listings = listings(&entities, "198.51.100.20");
    let sources: Vec<(&str, &str)> = address_listings
        .iter()
        .map(|(source, feed, _)| (source.as_str(), feed.as_str()))
        .collect();
    assert_eq!(
        sources,
        [
            ("abusech", "abuse.ch Feodo Tracker"),
            ("abusech", "abuse.ch URLhaus"),
            ("alienvaultiprep", "AlienVault IP Reputation"),
            ("blocklistde", "blocklist.de"),
            ("cinsscore", "CINS Army"),
            ("cleantalk", "CleanTalk Spam List"),
            ("torexits", "tor"),
        ]
    );
    assert!(address_listings[1].2.contains("\"elf,mirai\""));
    assert_eq!(
        address_listings[2].2,
        "198.51.100.20 # Malicious Host NL,Amsterdam,52.37,4.89"
    );
    let name_sources: Vec<String> = listings(&entities, "evil.example")
        .into_iter()
        .map(|(source, _, _)| source)
        .collect();
    assert_eq!(
        name_sources,
        ["abusech", "botvrij", "cybercrimetracker", "vxvault"]
    );
    // A block holds the listed addresses and blocks inside it, every entry kept.
    assert_eq!(
        listings(&entities, "203.0.113.0/24"),
        [
            (
                "alienvaultiprep".into(),
                "AlienVault IP Reputation".into(),
                "203.0.113.50 # Scanning Host US,,37.75,-97.82".into()
            ),
            ("voipbl".into(), "VoIPBL".into(), "203.0.113.0/28".into()),
        ]
    );
    // A threat feed's listing is malicious; Steven Black's and Tor's are not.
    let tagged = |value: &str, source: &str| {
        entities
            .iter()
            .filter(|entity| entity.value == value)
            .filter(|entity| entity.evidence[0].provenance.source == source)
            .all(|entity| entity.has_tag(tags::MALICIOUS))
    };
    assert!(tagged("198.51.100.20", "cinsscore"));
    assert!(!tagged("ads.example", "stevenblack_hosts"));
    assert!(!tagged("198.51.100.20", "torexits"));
    assert!(
        entities
            .iter()
            .any(|entity| entity.value == "198.51.100.20" && entity.has_tag(tags::TOR_EXIT))
    );
    // One row per source, saying what each of its feeds listed.
    assert_eq!(rows.len(), 16);
    assert_eq!(row(&rows, "abusech").kind, SourceOutcomeKind::Success);
    assert_eq!(row(&rows, "abusech").found, Some(3));
    assert_eq!(
        detail(&rows, "abusech"),
        "abuse.ch Feodo Tracker: lists 198.51.100.20 (2 entries, downloaded now); abuse.ch URLhaus: \
         lists 198.51.100.20, evil.example (2 entries, downloaded now)"
    );
    assert_eq!(row(&rows, "greensnow").kind, SourceOutcomeKind::ValidZero);
    assert_eq!(
        detail(&rows, "greensnow"),
        "GreenSnow: not listed (1 entries, downloaded now)"
    );
}

#[test]
fn a_copy_is_read_until_it_is_old_then_downloaded_again() {
    let dir = scratch("copies");
    let net = Net::serving();
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let start = now();
    let subjects = [address("198.51.100.20")];
    let (first, _) = check(&feeds, &subjects, "s", start);
    assert_eq!(net.asked().len(), FEEDS.len());
    for feed in FEEDS {
        assert_eq!(
            std::fs::read_to_string(dir.join(feed.id)).expect("copy"),
            sample(feed.id)
        );
    }
    // Within the hour every feed is read from its copy, with the same result.
    let (again, rows) = check(&feeds, &subjects, "s", start + 60);
    assert!(net.asked().is_empty());
    assert_eq!(
        listings(&again, "198.51.100.20"),
        listings(&first, "198.51.100.20")
    );
    assert!(detail(&rows, "cinsscore").contains("(2 entries, copy from "));
    // After an hour only the Tor exit list is old; after 18 hours every feed but Steven Black's.
    let _ = check(&feeds, &subjects, "s", start + 3_601);
    let tor = FEEDS
        .iter()
        .find(|feed| feed.id == "torexits")
        .expect("tor");
    assert_eq!(net.asked(), [tor.url]);
    let _ = check(&feeds, &subjects, "s", start + 18 * 3_600 + 60);
    assert_eq!(net.asked().len(), FEEDS.len() - 1);
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_feed_that_cannot_be_read_says_so_instead_of_not_listed() {
    let dir = scratch("failing");
    let net = Net::serving();
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let start = now();
    let subjects = [address("198.51.100.20"), address("194.180.49.70")];
    let _ = check(&feeds, &subjects, "s", start);
    net.asked();
    // A feed down keeps answering from its old copy, and says how old that is.
    net.set("cinsscore", Reply::Down);
    // A list that turns into a page of HTML, as Talos's did, is no list.
    let page = "<!DOCTYPE html><html><head><title>Terms</title></head></html>";
    net.set("greensnow", Reply::Body(page.into()));
    let later = start + 19 * 3_600;
    let (entities, rows) = check(&feeds, &subjects, "s", later);
    assert_eq!(row(&rows, "cinsscore").kind, SourceOutcomeKind::Success);
    let cins = detail(&rows, "cinsscore");
    assert!(
        cins.starts_with("CINS Army: lists 198.51.100.20 (2 entries, copy from ")
            && cins.ends_with(", could not be downloaded again (no answer (connection refused)))"),
        "{cins}"
    );
    assert!(
        listings(&entities, "198.51.100.20")
            .iter()
            .any(|(source, _, _)| source == "cinsscore")
    );
    assert_eq!(
        row(&rows, "greensnow").kind,
        SourceOutcomeKind::ProtocolDrift
    );
    assert_eq!(
        detail(&rows, "greensnow"),
        format!(
            "GreenSnow: no entry it could read in {} bytes; the feed may have changed form",
            page.len()
        )
    );
    assert!(listings(&entities, "194.180.49.70").is_empty());
    std::fs::remove_dir_all(&dir).expect("cleanup");

    // With no copy, a feed that is down, refuses or is larger than the limit is a failed row.
    let net = Net::serving();
    net.set("cinsscore", Reply::Down);
    net.set("emergingthreats", Reply::Status(503));
    net.set("phishtank", Reply::Truncated);
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), None);
    let (_, rows) = check(&feeds, &subjects, "s", start);
    assert_eq!(
        row(&rows, "cinsscore").kind,
        SourceOutcomeKind::ConnectFailure
    );
    assert_eq!(
        detail(&rows, "emergingthreats"),
        "Emerging Threats: HTTP 503"
    );
    assert_eq!(
        row(&rows, "phishtank").kind,
        SourceOutcomeKind::ProtocolDrift
    );
    assert_eq!(
        detail(&rows, "phishtank"),
        format!("PhishTank: larger than {MAX_FEED_BYTES} bytes")
    );
}

#[test]
fn an_unreachable_network_is_not_asked_feed_after_feed() {
    let net = Arc::new(Net::default());
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), None);
    let (entities, rows) = check(&feeds, &[address("198.51.100.20")], "s", now());
    assert!(entities.is_empty());
    assert!(net.asked().len() < FEEDS.len());
    assert!(rows.iter().all(|row| !row.kind.is_accepted()));
    assert!(rows.iter().any(|row| {
        row.detail
            .as_deref()
            .unwrap_or_default()
            .contains("not asked")
    }));
}

#[test]
fn no_feeds_asks_nothing() {
    let (entities, rows) = check(&Feeds::none(), &[address("198.51.100.20")], "s", now());
    assert!(entities.is_empty() && rows.is_empty());
}

#[test]
fn a_lookups_subjects_are_its_target_then_each_address_name_and_block_once() {
    let entity = |kind, value: &str| Entity::new(kind, value, 0.5, "s");
    let found = [
        entity(EntityKind::Domain, "WWW.Example.COM."),
        entity(EntityKind::IpAddress, "192.0.2.1"),
        entity(EntityKind::Domain, "www.example.com"),
        entity(EntityKind::Netblock, "192.0.2.0/24"),
        entity(EntityKind::Email, "a@example.com"),
        entity(EntityKind::IpAddress, "192.0.2.1"),
    ];
    assert_eq!(
        subjects(Subject::Name("example.com".into()), &found),
        [
            Subject::Name("example.com".into()),
            Subject::Name("www.example.com".into()),
            address("192.0.2.1"),
            Subject::Block(Netblock::parse("192.0.2.0/24").expect("block")),
        ]
    );
}

#[test]
fn a_saved_scan_lists_threats_as_malicious_and_tor_exits_as_tor_exit_nodes() {
    let net = Net::serving();
    let feeds = Feeds::new(Box::new(Shared(net)), None);
    let subjects = [
        address("101.33.78.144"),
        address("204.8.96.141"),
        Subject::Name("tracker.example".into()),
    ];
    let (entities, _) = check(&feeds, &subjects, "s", now());
    let target = crate::sf_elements::Target {
        value: "101.33.78.144",
        kind: "IP_ADDRESS",
    };
    let found = crate::sf_elements::elements(target, &entities, 1);
    let of = |kind: &str| -> Vec<&str> {
        found
            .iter()
            .filter(|element| element.kind == kind)
            .map(|element| element.data.as_str())
            .collect()
    };
    assert_eq!(
        of("BLACKLISTED_IPADDR"),
        ["Emerging Threats [101.33.78.144]"]
    );
    assert_eq!(of("MALICIOUS_IPADDR"), ["Emerging Threats [101.33.78.144]"]);
    assert_eq!(of("TOR_EXIT_NODE"), ["204.8.96.141"]);
    assert_eq!(
        of("BLACKLISTED_INTERNET_NAME"),
        ["Steven Black Hosts [tracker.example]"]
    );
    assert!(of("MALICIOUS_INTERNET_NAME").is_empty());
}
