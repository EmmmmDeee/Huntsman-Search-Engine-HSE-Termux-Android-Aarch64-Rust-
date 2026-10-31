use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::http::{Response, TransportFailure};

/// What the fake network answers for one feed.
#[derive(Debug, Clone)]
enum Reply {
    Body(String),
    /// A body with the `Last-Modified` date its publisher sent.
    Dated(String, String),
    Status(u16),
    /// A status with a body, as a server's own error page.
    Page(u16, String),
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
            Reply::Dated(body, date) => Ok(Response {
                headers: vec![("Last-Modified".into(), date)],
                ..response(200, &body, false)
            }),
            Reply::Status(status) => Ok(response(status, "", false)),
            Reply::Page(status, body) => Ok(response(status, &body, false)),
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

/// `unix` as the IMF-fixdate a `Last-Modified` header carries (the weekday is never read).
fn http_date(unix: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let iso = crate::timefmt::format_unix(i64::try_from(unix).expect("a date"));
    let month = MONTHS[iso[5..7].parse::<usize>().expect("a month") - 1];
    format!(
        "Mon, {} {month} {} {} GMT",
        &iso[8..10],
        &iso[..4],
        &iso[11..19]
    )
}

/// The feed with `id`.
fn feed(id: &str) -> &'static Feed {
    FEEDS.iter().find(|feed| feed.id == id).expect("a feed")
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
            let (feed, entries) = if evidence.attributes.contains_key("tor_relays") {
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
            ("alienvaultiprep", 2),
            ("blocklistde", 3),
            ("botvrij", 2),
            ("cinsscore", 2),
            ("cleantalk", 2),
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
    assert_eq!(
        read("cybercrimetracker").lookup(&address("5.182.86.32")),
        ["5.182.86.32/auth/login"]
    );
    // A block of one address is that address; a wider block holds every address in it.
    let voipbl = read("voipbl");
    assert_eq!(voipbl.lookup(&address("192.0.2.77")), ["192.0.2.77/32"]);
    assert_eq!(voipbl.lookup(&address("203.0.113.9")), ["203.0.113.0/28"]);
    assert!(voipbl.lookup(&address("203.0.113.16")).is_empty());
    assert_eq!(voipbl.lookup(&address("0.0.0.1")), ["0.0.0.0/31"]);
    assert!(
        voipbl
            .addresses
            .contains_key(&"192.0.2.77".parse::<IpAddr>().unwrap()),
        "a /32 is kept as its address"
    );
    assert_eq!(voipbl.blocks.len(), 2, "the /31 and the /28 stay blocks");
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
            ("alienvaultiprep", "AlienVault IP Reputation"),
            ("blocklistde", "blocklist.de"),
            ("cinsscore", "CINS Army"),
            ("cleantalk", "CleanTalk Spam List"),
            ("torexits", "tor"),
        ]
    );
    assert_eq!(
        address_listings[1].2,
        "198.51.100.20 # Malicious Host NL,Amsterdam,52.37,4.89"
    );
    let name_sources: Vec<String> = listings(&entities, "evil.example")
        .into_iter()
        .map(|(source, _, _)| source)
        .collect();
    assert_eq!(name_sources, ["botvrij", "cybercrimetracker", "vxvault"]);
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
    assert_eq!(rows.len(), 15);
    assert_eq!(row(&rows, "abusech").kind, SourceOutcomeKind::Success);
    assert_eq!(row(&rows, "abusech").found, Some(1));
    assert_eq!(
        detail(&rows, "abusech"),
        "abuse.ch Feodo Tracker: lists 198.51.100.20 (2 entries, downloaded now)"
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
    // A copy's age is its modification time, which the filesystem sets in whole seconds from when
    // the write happened. Pin it to `start`, so the offsets below measure from the fetch however
    // long the first check took.
    for feed in FEEDS {
        std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join(feed.id))
            .expect("copy")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(start)),
            )
            .expect("pin the copy's time");
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
    // A list that turns into a page of HTML, as Talos's did, is no list: it is not kept, and the
    // copy kept before it still answers, saying the list could not be downloaded again.
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
    assert_eq!(row(&rows, "greensnow").kind, SourceOutcomeKind::Success);
    let green = detail(&rows, "greensnow");
    assert!(
        green.starts_with("GreenSnow: lists 194.180.49.70 (1 entries, copy from ")
            && green.ends_with(&format!(
                ", could not be downloaded again (an HTML page of {} bytes in place of the list))",
                page.len()
            )),
        "{green}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("greensnow")).expect("copy"),
        sample("greensnow")
    );
    assert!(
        listings(&entities, "194.180.49.70")
            .iter()
            .any(|(source, _, _)| source == "greensnow")
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");

    // With no copy, a feed that is down, refuses, is larger than the limit or is a page is a
    // failed row.
    let net = Net::serving();
    net.set("greensnow", Reply::Body(page.into()));
    net.set("cinsscore", Reply::Down);
    net.set("emergingthreats", Reply::Status(503));
    net.set(
        "botvrij",
        Reply::Page(
            404,
            "<!DOCTYPE html><html><body>Not Found</body></html>".into(),
        ),
    );
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
    // A server's error page is its status, not a page in the list's place.
    assert_eq!(detail(&rows, "botvrij"), "botvrij.eu: HTTP 404");
    assert_eq!(
        row(&rows, "phishtank").kind,
        SourceOutcomeKind::ProtocolDrift
    );
    assert_eq!(
        detail(&rows, "phishtank"),
        format!("PhishTank: larger than {MAX_FEED_BYTES} bytes")
    );
    assert_eq!(
        row(&rows, "greensnow").kind,
        SourceOutcomeKind::ProtocolDrift
    );
    assert_eq!(
        detail(&rows, "greensnow"),
        format!(
            "GreenSnow: an HTML page of {} bytes in place of the list",
            page.len()
        )
    );
}

/// A page served in a list's place (a "feed has moved" page whose markup holds URLs, a refresh
/// stub, a challenge page) is no download: it is never kept over the list, and never reads as "not
/// listed". A challenge is a challenge, as the fetch reads it, and Tor's list is no exception.
#[test]
fn a_page_served_in_a_lists_place_never_reads_as_not_listed() {
    let moved = "<html><head><link rel=\"stylesheet\" href=\"https://openphish.com/static/main.css\">\
                 </head>\n<body><a href=\"https://openphish.com/\">The feed has moved</a></body></html>\n";
    let challenge = "<html><title>Just a moment...</title>Cloudflare</html>";
    let stub = "<meta http-equiv=\"refresh\" content=\"0; url=https://new.example/feed.txt\">\n\
                https://new.example/feed.txt\n";
    let subjects = [Subject::Name("login.evil.example".into())];
    for (page, kind) in [
        (moved, SourceOutcomeKind::ProtocolDrift),
        (challenge, SourceOutcomeKind::BotWaf),
        (stub, SourceOutcomeKind::ProtocolDrift),
    ] {
        let net = Net::serving();
        net.set("openphish", Reply::Body(page.into()));
        let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), None);
        let (entities, rows) = check(&feeds, &subjects, "s", now());
        assert_eq!(row(&rows, "openphish").kind, kind, "{page}");
        assert!(
            listings(&entities, "login.evil.example")
                .iter()
                .all(|(source, _, _)| source != "openphish")
        );
    }
    // With a copy, the page is not kept and the copy still answers.
    let dir = scratch("pages");
    let net = Net::serving();
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let start = now();
    let _ = check(&feeds, &subjects, "s", start);
    for page in [moved, challenge, stub] {
        net.set("openphish", Reply::Body(page.into()));
        let (entities, rows) = check(&feeds, &subjects, "s", start + 19 * 3_600);
        assert_eq!(row(&rows, "openphish").kind, SourceOutcomeKind::Success);
        assert!(
            detail(&rows, "openphish").contains("could not be downloaded again ("),
            "{}",
            detail(&rows, "openphish")
        );
        assert!(
            listings(&entities, "login.evil.example")
                .iter()
                .any(|(source, _, _)| source == "openphish")
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("openphish")).expect("copy"),
            sample("openphish")
        );
    }
    // Tor's relay list, JSON, is replaced by no page either.
    let relay = [address("204.8.96.141")];
    let _ = check(&feeds, &relay, "s", start);
    net.set("torexits", Reply::Body(challenge.into()));
    let (entities, rows) = check(&feeds, &relay, "s", start + 2 * 3_600);
    assert_eq!(row(&rows, "torexits").kind, SourceOutcomeKind::Success);
    assert!(
        listings(&entities, "204.8.96.141")
            .iter()
            .any(|(source, _, _)| source == "torexits")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("torexits")).expect("copy"),
        sample("torexits")
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// A body is a page by how it opens, never by what its entries spell: a tag after any byte-order
/// mark, white space, XML declaration and comments, other than the `<pre>` VX Vault wraps its list
/// in.
#[test]
fn a_body_is_a_page_by_how_it_opens() {
    let padding = " ".repeat(2_048);
    for page in [
        "<!DOCTYPE html><html></html>".to_owned(),
        "\u{feff}<?xml version=\"1.0\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\">"
            .to_owned(),
        "<meta http-equiv=\"refresh\" content=\"0; url=https://new.example/feed.txt\">".to_owned(),
        "<script>location = 'https://new.example/feed.txt'</script>".to_owned(),
        "<br />\n<b>Warning</b>: feed.php on line 3<br />\n198.51.100.20\n".to_owned(),
        format!("{padding}<!-- generated -->\n<html><body>moved</body></html>"),
        "<!-- never closed".to_owned(),
        "<?php echo 1;".to_owned(),
        "<prefix>".to_owned(),
    ] {
        assert!(is_page(page.as_bytes()), "{page}");
    }
    for list in [
        sample("vxvault").to_owned(),
        "<PRE>\nhttp://203.0.113.5/<header><body>.exe\n</PRE>\n".to_owned(),
        sample("torexits").to_owned(),
        "# <html> is no entry\n198.51.100.20\n".to_owned(),
        "\u{feff}http://evil.example/<body>\n".to_owned(),
        "<203.0.113.5>\n".to_owned(),
        "<!-- generated -->\n198.51.100.20\n".to_owned(),
        "<!-- x -->\n<pre class=\"l\">\nhttp://e.example/a\n".to_owned(),
        String::new(),
    ] {
        assert!(!is_page(list.as_bytes()), "{list}");
    }
}

/// An entry is read by its host however a `://` falls in it: after its scheme, in its query (the
/// entry is read without a scheme) or in markup (no host); and a list's byte-order mark is no part
/// of its first entry.
#[test]
fn an_entry_is_read_by_its_host_wherever_a_scheme_falls_in_it() {
    let host = |entry: &str| match url_key(entry) {
        Some(Key::Name(name)) => Some(name),
        _ => None,
    };
    assert_eq!(
        host("https://login.evil.example/x").as_deref(),
        Some("login.evil.example")
    );
    assert_eq!(
        host("evil.example/g.php?u=http://x.example/").as_deref(),
        Some("evil.example")
    );
    assert_eq!(host("<link href=\"https://cdn.example/main.css\">"), None);
    let listed = index(
        Format::Urls,
        "\u{feff}http://first.example/a\nhttp://second.example/b\n",
    );
    assert_eq!(listed.entries, 2);
    assert!(listed.names.contains_key("first.example"));
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
fn a_blocked_egress_refuses_every_feed_before_sending() {
    // A blocked egress is not a transport failure, so it never aborts the fan-out: every feed is
    // asked and every row is refused, not connect_failure.
    let feeds = Feeds::new(Box::new(crate::test_support::Refusing), None);
    let (entities, rows) = check(&feeds, &[address("198.51.100.20")], "s", now());
    assert!(entities.is_empty());
    assert!(!rows.is_empty());
    assert!(
        rows.iter()
            .all(|row| row.kind == SourceOutcomeKind::RefusedBeforeSending),
        "{rows:?}"
    );
    assert!(!rows.iter().any(|row| {
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

/// 30 October 2026, noon UTC, as the stale-list tests read it.
fn stale_now() -> u64 {
    crate::timefmt::parse_http_date("Fri, 30 Oct 2026 12:00:00 GMT", 0)
        .and_then(|now| u64::try_from(now).ok())
        .expect("now")
}

/// Every feed serving its sample, as published at `now`: `AlienVault`'s reputation list last on 12
/// November 2021 (it still downloads), Tor's relays four days before, CINS Army an hour before
/// (its date returned), `CleanTalk`'s seven-day list ten days before and blocklist.de's 48-hour
/// list three days before.
fn stale_feeds(now: u64) -> (Feeds, String) {
    let net = Net::serving();
    net.set(
        "alienvaultiprep",
        Reply::Dated(
            sample("alienvaultiprep").into(),
            "Fri, 12 Nov 2021 14:10:50 GMT".to_owned(),
        ),
    );
    net.set(
        "torexits",
        Reply::Dated(sample("torexits").into(), http_date(now - 4 * 86_400)),
    );
    let fresh = http_date(now - 3_600);
    net.set(
        "cinsscore",
        Reply::Dated(sample("cinsscore").into(), fresh.clone()),
    );
    // A list of the last seven days, or 48 hours, is stale once older than that.
    net.set(
        "cleantalk",
        Reply::Dated(sample("cleantalk").into(), http_date(now - 10 * 86_400)),
    );
    net.set(
        "blocklistde",
        Reply::Dated(sample("blocklistde").into(), http_date(now - 3 * 86_400)),
    );
    (Feeds::new(Box::new(Shared(net)), None), fresh)
}

#[test]
fn a_list_its_publisher_stopped_updating_cannot_say_a_subject_is_not_listed() {
    let now = stale_now();
    let (feeds, fresh) = stale_feeds(now);
    // Absent from a list that stopped updating is not "not listed".
    let (entities, rows) = check(&feeds, &[address("192.0.2.200")], "s", now);
    assert!(entities.is_empty());
    assert_eq!(
        row(&rows, "alienvaultiprep").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert!(!row(&rows, "alienvaultiprep").kind.is_accepted());
    assert_eq!(
        detail(&rows, "alienvaultiprep"),
        "AlienVault IP Reputation: not listed (2 entries, downloaded now, a list last updated \
         2021-11-12T14:10:50Z, too old to say what is listed now)"
    );
    assert_eq!(row(&rows, "torexits").kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(
        row(&rows, "cleantalk").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(
        row(&rows, "blocklistde").kind,
        SourceOutcomeKind::Inconclusive
    );
    // A current list still answers, saying when it was published; an undated one as before.
    assert_eq!(row(&rows, "cinsscore").kind, SourceOutcomeKind::ValidZero);
    let updated =
        crate::timefmt::format_unix(crate::timefmt::parse_http_date(&fresh, now).expect("a date"));
    assert_eq!(
        detail(&rows, "cinsscore"),
        format!("CINS Army: not listed (2 entries, downloaded now, list updated {updated})")
    );
    assert_eq!(row(&rows, "greensnow").kind, SourceOutcomeKind::ValidZero);
    assert_eq!(
        detail(&rows, "greensnow"),
        "GreenSnow: not listed (1 entries, downloaded now)"
    );
}

#[test]
fn what_a_stale_list_holds_is_kept_but_never_a_current_verdict() {
    let now = stale_now();
    let (feeds, _) = stale_feeds(now);
    // What such a list holds is kept whole, as an entry on an old list, never a current threat.
    let subjects = [address("203.0.113.50"), address("204.8.96.141")];
    let (entities, rows) = check(&feeds, &subjects, "s", now);
    assert_eq!(
        row(&rows, "alienvaultiprep").kind,
        SourceOutcomeKind::Success
    );
    let listed = entities
        .iter()
        .find(|entity| entity.value == "203.0.113.50")
        .expect("the listing");
    assert!(!listed.has_tag(tags::MALICIOUS));
    let evidence = &listed.evidence[0];
    let attr = |key: &str| evidence.attributes.get(key).map(String::as_str);
    assert_eq!(
        evidence.summary,
        "203.0.113.50 is listed by AlienVault IP Reputation (on a list last updated \
         2021-11-12T14:10:50Z)"
    );
    assert_eq!(
        attr("threat_feed_entries"),
        Some("203.0.113.50 # Scanning Host US,,37.75,-97.82")
    );
    assert_eq!(attr("threat_feed_threat"), Some("false"));
    assert_eq!(attr("threat_feed_updated"), Some("2021-11-12T14:10:50Z"));
    assert_eq!(attr("threat_feed_stale"), Some("true"));
    assert_eq!(attr("blocklists"), None);
    let relay = entities
        .iter()
        .find(|entity| entity.value == "204.8.96.141")
        .expect("the relay");
    assert!(!relay.has_tag(tags::TOR_EXIT));
    assert!(
        relay.evidence[0]
            .summary
            .starts_with("204.8.96.141 is listed as a Tor exit relay (on a list last updated "),
        "{}",
        relay.evidence[0].summary
    );
    let attr = |key: &str| relay.evidence[0].attributes.get(key).map(String::as_str);
    assert_eq!(attr("tor"), None, "never said not to be a Tor exit either");
    assert_eq!(attr("tor_relays_stale"), Some("true"));
    assert!(attr("tor_relays").is_some_and(|relays| relays.contains("Quintex152")));

    // A saved scan names it neither blacklisted nor malicious, which Spiderfoot's correlations
    // would read as a current verdict, nor a Tor exit node.
    let target = crate::sf_elements::Target {
        value: "203.0.113.50",
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
    assert!(of("BLACKLISTED_IPADDR").is_empty());
    assert!(of("MALICIOUS_IPADDR").is_empty());
    assert!(of("TOR_EXIT_NODE").is_empty());
}

#[test]
fn a_kept_copy_is_read_with_its_own_publishers_date() {
    let dir = scratch("dated");
    let net = Net::serving();
    let start = now();
    net.set(
        "alienvaultiprep",
        Reply::Dated(
            sample("alienvaultiprep").into(),
            http_date(start - 400 * 86_400),
        ),
    );
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let subjects = [address("192.0.2.200")];
    let _ = check(&feeds, &subjects, "s", start);
    assert_eq!(net.asked().len(), FEEDS.len());
    let kept = |id: &str| read_updated(&dir.join(id), sample(id).as_bytes());
    assert_eq!(
        kept("alienvaultiprep"),
        KeptDate::Kept(Some(start - 400 * 86_400))
    );
    assert_eq!(kept("greensnow"), KeptDate::Kept(None));
    // Read from its copy, the old list is still too old to answer.
    let (_, rows) = check(&feeds, &subjects, "s", start + 60);
    assert!(net.asked().is_empty());
    assert_eq!(
        row(&rows, "alienvaultiprep").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert!(detail(&rows, "alienvaultiprep").contains(", copy from "));
    assert_eq!(row(&rows, "greensnow").kind, SourceOutcomeKind::ValidZero);
    // A copy with no date beside it, as an earlier version kept them, is downloaded again, and so
    // is one rewritten since its date was kept (by an earlier version, or another process).
    std::fs::remove_file(dir.join("cinsscore.updated")).expect("remove the date");
    std::fs::write(dir.join("greensnow"), "194.180.49.70\n198.51.100.99\n").expect("rewrite");
    let _ = check(&feeds, &subjects, "s", start + 120);
    let mut asked = net.asked();
    asked.sort();
    let mut again = [feed("cinsscore").url, feed("greensnow").url];
    again.sort_unstable();
    assert_eq!(asked, again);
    // A later download without a date never keeps the old one.
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("alienvaultiprep"))
        .expect("copy")
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(start)),
        )
        .expect("pin the copy's time");
    net.set(
        "alienvaultiprep",
        Reply::Body(sample("alienvaultiprep").into()),
    );
    let (_, rows) = check(&feeds, &subjects, "s", start + 19 * 3_600);
    assert_eq!(
        row(&rows, "alienvaultiprep").kind,
        SourceOutcomeKind::ValidZero
    );
    assert_eq!(kept("alienvaultiprep"), KeptDate::Kept(None));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_source_says_not_listed_only_when_every_one_of_its_lists_answered_for_now() {
    // Two lists under one source, as abuse.ch's Feodo Tracker and URLhaus once were: one that
    // cannot be read, or one too old, leaves "not listed" unsaid.
    let first = Feed {
        id: "first",
        source: "both",
        name: "First",
        ..*feed("feodotracker")
    };
    let second = Feed {
        id: "second",
        source: "both",
        name: "Second",
        ..*feed("feodotracker")
    };
    let read = |stale| -> Result<Read, Failure> {
        Ok(Read {
            matches: Vec::new(),
            entries: 2,
            fetched: 0,
            updated: Some(0),
            as_of: Some(0),
            stale,
            downloaded: true,
            note: None,
        })
    };
    let kind = |said: &[(&Feed, Result<Read, Failure>)]| rows(said, 1)[0].kind;
    assert_eq!(
        kind(&[(&first, read(false)), (&second, read(false))]),
        SourceOutcomeKind::ValidZero
    );
    let gone = Err((SourceOutcomeKind::ConfirmedDead, "HTTP 410".to_owned()));
    assert_eq!(
        kind(&[(&first, read(false)), (&second, gone.clone())]),
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(
        kind(&[(&first, read(false)), (&second, read(true))]),
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(
        kind(&[(&first, gone.clone()), (&second, gone)]),
        SourceOutcomeKind::ConfirmedDead
    );
}

#[test]
fn a_copy_that_cannot_be_refreshed_answers_only_for_when_it_was_downloaded() {
    let dir = scratch("unrefreshed");
    let start = now();
    let net = Net::serving();
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let subjects = [address("194.180.49.70"), address("192.0.2.200")];
    let _ = check(&feeds, &subjects, "s", start);
    // Every copy was downloaded 40 days ago, the network is now down, and the date kept beside
    // blocklist.de's copy is gone.
    let old = start - 40 * 86_400;
    for feed in FEEDS {
        std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join(feed.id))
            .expect("copy")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(old)),
            )
            .expect("age the copy");
    }
    std::fs::remove_file(dir.join("blocklistde.updated")).expect("remove the date");
    let down = Feeds::new(
        Box::new(Shared(Arc::new(Net::default()))),
        Some(dir.clone()),
    );
    let (entities, rows) = check(&down, &subjects, "s", start);
    // GreenSnow publishes no date, so its copy answers for when it was downloaded: 40 days ago.
    assert_eq!(row(&rows, "greensnow").kind, SourceOutcomeKind::Success);
    let listing = entities
        .iter()
        .find(|entity| entity.value == "194.180.49.70")
        .expect("the listing");
    assert!(!listing.has_tag(tags::MALICIOUS));
    let copy = crate::timefmt::format_unix(i64::try_from(old).expect("a date"));
    assert_eq!(
        listing.evidence[0].summary,
        format!("194.180.49.70 is listed by GreenSnow (on a copy downloaded {copy})")
    );
    let greensnow = detail(&rows, "greensnow");
    assert!(
        greensnow.contains(&format!(
            "(1 entries, copy from {copy}, too old to say what is listed now, could not be \
             downloaded again"
        )),
        "{greensnow}"
    );
    assert_eq!(
        row(&rows, "cinsscore").kind,
        SourceOutcomeKind::Inconclusive
    );
    // A copy whose date is unknown cannot say either.
    assert_eq!(
        row(&rows, "blocklistde").kind,
        SourceOutcomeKind::Inconclusive
    );
    assert!(
        detail(&rows, "blocklistde")
            .contains(", a copy of unknown date, which cannot say what is listed now"),
        "{}",
        detail(&rows, "blocklistde")
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// A list is read as the list whatever its entries spell, a listed URL the fetch reads as a
/// challenge's marker included; a list that empties replaces its copy rather than leaving the old one answering; and a
/// page an earlier version kept in a list's place, with its date beside it, is downloaded again.
#[test]
fn a_list_is_the_list_however_it_reads_and_a_kept_page_is_no_copy() {
    let net = Net::serving();
    let vxvault = format!(
        "{}http://45.131.135.227/sorry/index\nhttp://203.0.113.5/<header><body>.exe\n",
        sample("vxvault").replace("</pre>\n", "")
    );
    net.set("vxvault", Reply::Body(vxvault));
    let dir = scratch("emptied");
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let start = now();
    let feodo = address("162.243.103.246");
    let (entities, rows) = check(
        &feeds,
        &[
            address("45.131.135.227"),
            address("203.0.113.5"),
            feodo.clone(),
        ],
        "s",
        start,
    );
    assert_eq!(row(&rows, "vxvault").kind, SourceOutcomeKind::Success);
    for listed in ["45.131.135.227", "203.0.113.5"] {
        assert!(
            listings(&entities, listed)
                .iter()
                .any(|(source, _, _)| source == "vxvault"),
            "{listed}"
        );
    }
    assert!(
        listings(&entities, "162.243.103.246")
            .iter()
            .any(|(source, _, _)| source == "abusech")
    );

    let emptied = "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist\n# END 0 entries\n";
    net.set("feodotracker", Reply::Body(emptied.into()));
    let (entities, rows) = check(&feeds, &[feodo], "s", start + 19 * 3_600);
    assert_eq!(row(&rows, "abusech").kind, SourceOutcomeKind::ProtocolDrift);
    assert!(listings(&entities, "162.243.103.246").is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.join("feodotracker")).expect("copy"),
        emptied
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");

    let dir = scratch("kept-page");
    let net = Net::serving();
    let page =
        "<!DOCTYPE html><html><body><a href=\"https://openphish.com/\">moved</a></body></html>";
    keep(&dir.join("openphish"), page.as_bytes(), None).expect("keep a page");
    let feeds = Feeds::new(Box::new(Shared(Arc::clone(&net))), Some(dir.clone()));
    let (entities, rows) = check(
        &feeds,
        &[Subject::Name("login.evil.example".into())],
        "s",
        now(),
    );
    let openphish = FEEDS
        .iter()
        .find(|feed| feed.id == "openphish")
        .expect("openphish");
    assert!(net.asked().contains(&openphish.url.to_owned()));
    assert_eq!(row(&rows, "openphish").kind, SourceOutcomeKind::Success);
    assert!(
        listings(&entities, "login.evil.example")
            .iter()
            .any(|(source, _, _)| source == "openphish")
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}
