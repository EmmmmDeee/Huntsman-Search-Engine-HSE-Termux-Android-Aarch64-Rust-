//! Threat feeds: whether an address, a host name or an address block is on the public threat
//! lists Spiderfoot downloads, as its `sfp_abusech` (Feodo Tracker and `URLhaus`),
//! `sfp_alienvaultiprep`, `sfp_blocklistde`, `sfp_botvrij`, `sfp_cinsscore`, `sfp_coinblocker`,
//! `sfp_cybercrimetracker`, `sfp_emergingthreats`, `sfp_greensnow`, `sfp_openphish`,
//! `sfp_phishtank`, `sfp_stevenblack_hosts`, `sfp_torexits`, `sfp_voipbl` and `sfp_vxvault` read
//! them.
//!
//! Each feed is downloaded whole and kept in the directory [`Feeds`] names for as long as
//! Spiderfoot keeps it (18 hours; an hour for the Tor exit list), so a lookup after the first
//! reads the copy and sends nothing. A feed that cannot be refreshed is read from its last copy,
//! and its row says how old that copy is; one never downloaded is a failed row, not "not listed".
//! A feed that downloads but holds no entry this module can read has changed form, and says so
//! instead of reading as "not listed".
//!
//! Matching is local, so a lookup checks every address, host name and address block it found, not
//! only its target: an address against the feed's addresses and blocks, a host name exactly, as
//! Spiderfoot matches it (a URL feed's entries by their host), and a block against every listed
//! address or block inside or around it. Every match keeps the feed's whole entry: the line, the
//! CSV row or the relay record. A threat feed's listing is both the blacklisted and the malicious
//! element, as Spiderfoot writes them. Steven Black's hosts list, mostly advertising and tracking
//! hosts, is a listing only, and a Tor exit relay is a Tor exit node, not a verdict.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, TransportConfig};
use crate::netblock::Netblock;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::tags;

/// How a feed's body reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One entry a line, its first word an address, a block or a host name. Lines starting `#`
    /// or `;` are comments.
    Lines,
    /// A hosts file: each line an address, then the host names it maps.
    Hosts,
    /// One URL a line, with or without its scheme. A line that is not a URL, such as the HTML
    /// around a list, is skipped.
    Urls,
    /// CSV whose given column (from 0) holds a URL or a host name. Lines starting `#` are
    /// comments, and a header row reads as no entry.
    Csv(usize),
    /// Tor's Onionoo relay details: each exit relay's addresses.
    Onionoo,
}

/// What being on a feed says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Meaning {
    /// A list of threats: listed is malicious.
    Threat,
    /// A blocklist that is not only threats: listed is blacklisted, not malicious.
    Listing,
    /// The Tor network's exit relays.
    TorExit,
}

/// One downloaded feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feed {
    /// The name of its copy in the feed directory.
    pub id: &'static str,
    /// The source label: Spiderfoot's module name without `sfp_`.
    pub source: &'static str,
    /// The feed's name, as an element's data starts.
    pub name: &'static str,
    pub url: &'static str,
    pub format: Format,
    pub meaning: Meaning,
    /// How long a copy is read before it is downloaded again, in seconds.
    pub max_age: u64,
}

/// Spiderfoot's cache period for its feeds.
const SPIDERFOOT_CACHE: u64 = 18 * 3_600;

/// Every feed read, grouped by source.
pub const FEEDS: &[Feed] = &[
    Feed {
        id: "feodotracker",
        source: "abusech",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "urlhaus",
        source: "abusech",
        name: "abuse.ch URLhaus",
        url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
        format: Format::Csv(2),
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "alienvaultiprep",
        source: "alienvaultiprep",
        name: "AlienVault IP Reputation",
        url: "https://reputation.alienvault.com/reputation.generic",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "blocklistde",
        source: "blocklistde",
        name: "blocklist.de",
        url: "https://lists.blocklist.de/lists/all.txt",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "botvrij",
        source: "botvrij",
        name: "botvrij.eu",
        url: "https://www.botvrij.eu/data/blocklist/blocklist_full.csv",
        format: Format::Csv(0),
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "cinsscore",
        source: "cinsscore",
        name: "CINS Army",
        url: "https://cinsscore.com/list/ci-badguys.txt",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "coinblocker",
        source: "coinblocker",
        name: "CoinBlocker",
        url: "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "cybercrimetracker",
        source: "cybercrimetracker",
        name: "CyberCrime-Tracker.net",
        url: "https://cybercrime-tracker.net/all.php",
        format: Format::Urls,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "emergingthreats",
        source: "emergingthreats",
        name: "Emerging Threats",
        url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "greensnow",
        source: "greensnow",
        name: "GreenSnow",
        url: "https://blocklist.greensnow.co/greensnow.txt",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "openphish",
        source: "openphish",
        name: "OpenPhish",
        url: "https://openphish.com/feed.txt",
        format: Format::Urls,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "phishtank",
        source: "phishtank",
        name: "PhishTank",
        url: "https://data.phishtank.com/data/online-valid.csv",
        format: Format::Csv(1),
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "stevenblack_hosts",
        source: "stevenblack_hosts",
        name: "Steven Black Hosts",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        format: Format::Hosts,
        meaning: Meaning::Listing,
        max_age: 24 * 3_600,
    },
    Feed {
        id: "torexits",
        source: "torexits",
        name: "Tor exit relay",
        url: "https://onionoo.torproject.org/details?search=flag:exit&fields=nickname,fingerprint,or_addresses,exit_addresses,last_seen,first_seen,country,as,as_name,contact",
        format: Format::Onionoo,
        meaning: Meaning::TorExit,
        max_age: 3_600,
    },
    Feed {
        id: "voipbl",
        source: "voipbl",
        name: "VoIPBL",
        url: "https://voipbl.org/update",
        format: Format::Lines,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
    Feed {
        id: "vxvault",
        source: "vxvault",
        name: "VXVault",
        url: "http://vxvault.net/URL_List.php",
        format: Format::Urls,
        meaning: Meaning::Threat,
        max_age: SPIDERFOOT_CACHE,
    },
];

/// The largest feed read, in bytes: `PhishTank`'s list runs to about 12 MiB and `URLhaus`'s to 8.
pub const MAX_FEED_BYTES: usize = 64 * 1024 * 1024;
/// How long one feed's download may take.
pub const FEED_TIMEOUT: Duration = Duration::from_secs(90);
/// The confidence of a listing.
const LISTED_CONFIDENCE: f64 = 0.90;

/// The transport the feeds are downloaded over: long enough and large enough for the biggest.
#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: FEED_TIMEOUT,
        max_body: MAX_FEED_BYTES,
        ..TransportConfig::default()
    }
}

/// Where feeds come from and where their copies are kept: a transport to download them over, and
/// the directory the copies live in (none keeps no copy, so every lookup downloads).
/// [`Feeds::none`] consults no feed at all.
pub struct Feeds {
    transport: Option<Box<dyn Transport + Send + Sync>>,
    dir: Option<PathBuf>,
}

impl Feeds {
    /// No feed is consulted.
    #[must_use]
    pub fn none() -> Self {
        Self {
            transport: None,
            dir: None,
        }
    }

    /// Feeds downloaded over `transport`, their copies kept in `dir`.
    #[must_use]
    pub fn new(transport: Box<dyn Transport + Send + Sync>, dir: Option<PathBuf>) -> Self {
        Self {
            transport: Some(transport),
            dir,
        }
    }
}

/// What a lookup asks the feeds about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Address(IpAddr),
    /// A host name, lower case, without a trailing dot.
    Name(String),
    Block(Netblock),
}

impl Subject {
    fn kind(&self) -> EntityKind {
        match self {
            Self::Address(_) => EntityKind::IpAddress,
            Self::Name(_) => EntityKind::Domain,
            Self::Block(_) => EntityKind::Netblock,
        }
    }

    fn value(&self) -> String {
        match self {
            Self::Address(address) => address.to_string(),
            Self::Name(name) => name.clone(),
            Self::Block(block) => block.to_string(),
        }
    }
}

/// `first`, then every address, host name and address block among `entities`, each once.
#[must_use]
pub fn subjects(first: Subject, entities: &[Entity]) -> Vec<Subject> {
    let mut out = vec![first];
    for entity in entities {
        let subject = match entity.kind {
            EntityKind::IpAddress => entity.value.parse().ok().map(Subject::Address),
            EntityKind::Domain => host_name(&entity.value).map(Subject::Name),
            EntityKind::Netblock => Netblock::parse(&entity.value).map(Subject::Block),
            _ => None,
        };
        if let Some(subject) = subject {
            if !out.contains(&subject) {
                out.push(subject);
            }
        }
    }
    out
}

/// Check `target` and every address, host name and address block among `entities` against the
/// feeds: each listing joins `entities`, and each source's row joins `outcomes`.
pub fn check_found(
    feeds: &Feeds,
    target: Subject,
    entities: &mut Vec<Entity>,
    outcomes: &mut Vec<SourceExecutionOutcome>,
    scan_id: &str,
    now_unix: u64,
) {
    let subjects = subjects(target, entities);
    let (listed, rows) = check(feeds, &subjects, scan_id, now_unix);
    entities.extend(listed);
    outcomes.extend(rows);
}

/// What the feeds say about `subjects`: each listing as evidence on its subject, and one row per
/// source the feeds' transport asks. With [`Feeds::none`], nothing.
#[must_use]
pub fn check(
    feeds: &Feeds,
    subjects: &[Subject],
    scan_id: &str,
    now_unix: u64,
) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    let Some(transport) = feeds.transport.as_deref() else {
        return (Vec::new(), Vec::new());
    };
    let asked: Vec<&Feed> = FEEDS
        .iter()
        .filter(|feed| transport.runs_module(feed.source))
        .collect();
    let read = crate::dns::ask_all(
        &asked,
        |feed| read_feed(transport, feeds.dir.as_deref(), feed, subjects, now_unix),
        |result| matches!(result, Err((kind, _)) if unreachable(*kind)),
    );
    let mut entities = Vec::new();
    let mut said = Vec::new();
    for (feed, result) in asked.into_iter().zip(read) {
        let result = result.unwrap_or_else(|| {
            Err((
                SourceOutcomeKind::Inconclusive,
                "not asked: the first feeds asked could not be reached".to_owned(),
            ))
        });
        if let Ok(read) = &result {
            for (subject, entries) in &read.matches {
                push_listing(&mut entities, feed, read, subject, entries, scan_id);
            }
        }
        said.push((feed, result));
    }
    (entities, rows(&said, now_unix))
}

/// Why a feed could not be read: the kind of failure and why.
type Failure = (SourceOutcomeKind, String);

/// What one feed said about the subjects.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Read {
    /// Each subject listed, with every entry that lists it.
    matches: Vec<(Subject, Vec<String>)>,
    /// How many entries the feed holds.
    entries: usize,
    /// When the copy read was downloaded.
    fetched: u64,
    /// Whether it was downloaded by this lookup.
    downloaded: bool,
    /// What the row should say about the copy read: why it is old, or why it was not kept.
    note: Option<String>,
}

fn unreachable(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::ConnectFailure
            | SourceOutcomeKind::DnsFailure
            | SourceOutcomeKind::TlsFailure
            | SourceOutcomeKind::TtfbTimeout
            | SourceOutcomeKind::BodyTimeout
    )
}

/// Read `feed` (its copy, or a download) and match `subjects` against it.
fn read_feed(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    feed: &Feed,
    subjects: &[Subject],
    now_unix: u64,
) -> Result<Read, Failure> {
    let copy = load(transport, dir, feed, now_unix)?;
    let text = String::from_utf8_lossy(&copy.body);
    let listed = index(feed.format, &text);
    if listed.entries == 0 {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!(
                "no entry it could read in {} bytes; the feed may have changed form",
                copy.body.len()
            ),
        ));
    }
    let matches = subjects
        .iter()
        .filter_map(|subject| {
            let entries = listed.lookup(subject);
            (!entries.is_empty()).then(|| (subject.clone(), entries))
        })
        .collect();
    Ok(Read {
        matches,
        entries: listed.entries,
        fetched: copy.fetched,
        downloaded: copy.downloaded,
        note: copy.note,
    })
}

/// A feed's body as read: when it was downloaded, whether by this lookup, and anything its row
/// should say about it.
struct Copy {
    body: Vec<u8>,
    fetched: u64,
    downloaded: bool,
    note: Option<String>,
}

/// The feed's body: the copy in `dir` while it is younger than the feed's age, else a download
/// (kept in `dir`), else the old copy.
fn load(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    feed: &Feed,
    now_unix: u64,
) -> Result<Copy, Failure> {
    let path = dir.map(|dir| dir.join(feed.id));
    let kept = path.as_deref().and_then(read_copy);
    if let Some((body, fetched)) = &kept {
        if now_unix.saturating_sub(*fetched) < feed.max_age {
            return Ok(Copy {
                body: body.clone(),
                fetched: *fetched,
                downloaded: false,
                note: None,
            });
        }
    }
    match download(transport, feed, now_unix) {
        Ok(body) => {
            let note = path.and_then(|path| {
                crate::fsio::write_atomic(&path, &body, MAX_FEED_BYTES as u64)
                    .err()
                    .map(|error| format!("its copy could not be kept ({error})"))
            });
            Ok(Copy {
                body,
                fetched: now_unix,
                downloaded: true,
                note,
            })
        }
        Err((kind, why)) => match kept {
            Some((body, fetched)) => Ok(Copy {
                body,
                fetched,
                downloaded: false,
                note: Some(format!("could not be downloaded again ({why})")),
            }),
            None => Err((kind, why)),
        },
    }
}

/// The copy at `path` and when it was written, when there is one.
fn read_copy(path: &Path) -> Option<(Vec<u8>, u64)> {
    let modified = std::fs::symlink_metadata(path).ok()?.modified().ok()?;
    let fetched = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let body = crate::fsio::read_bounded(path, MAX_FEED_BYTES as u64).ok()?;
    Some((body, fetched))
}

/// Download `feed` whole.
fn download(
    transport: &(dyn Transport + Send + Sync),
    feed: &Feed,
    now_unix: u64,
) -> Result<Vec<u8>, Failure> {
    let request = Request::get(feed.url).with_timeout(FEED_TIMEOUT);
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::default(),
        feed.source,
        now_unix,
    )
    .map_err(|error| (SourceOutcomeKind::Inconclusive, error.to_string()))?;
    match fetched.response {
        Some(response) if response.truncated => Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("larger than {MAX_FEED_BYTES} bytes"),
        )),
        Some(response) if response.status == 200 => Ok(response.body),
        Some(response) => Err((fetched.outcome.kind, format!("HTTP {}", response.status))),
        None => Err((
            fetched.outcome.kind,
            format!(
                "no answer ({})",
                fetched.outcome.detail.as_deref().unwrap_or("no response")
            ),
        )),
    }
}

/// One feed's entries, by what they list.
#[derive(Debug, Default)]
struct Listed {
    addresses: HashMap<IpAddr, Vec<String>>,
    blocks: Vec<(Netblock, String)>,
    names: HashMap<String, Vec<String>>,
    entries: usize,
}

/// What one entry lists.
enum Key {
    Address(IpAddr),
    Block(Netblock),
    Name(String),
}

impl Listed {
    fn add(&mut self, key: Key, entry: &str) {
        let entry = entry.trim().to_owned();
        match key {
            Key::Address(address) => self.addresses.entry(address).or_default().push(entry),
            Key::Block(block) => self.blocks.push((block, entry)),
            Key::Name(name) => self.names.entry(name).or_default().push(entry),
        }
    }

    /// Every entry listing `subject`.
    fn lookup(&self, subject: &Subject) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        match subject {
            Subject::Address(address) => {
                out.extend(self.addresses.get(address).into_iter().flatten().cloned());
                out.extend(
                    self.blocks
                        .iter()
                        .filter(|(block, _)| block.contains(*address))
                        .map(|(_, entry)| entry.clone()),
                );
            }
            Subject::Name(name) => out.extend(self.names.get(name).into_iter().flatten().cloned()),
            Subject::Block(within) => {
                let mut inside: Vec<(&IpAddr, &Vec<String>)> = self
                    .addresses
                    .iter()
                    .filter(|(address, _)| within.contains(**address))
                    .collect();
                inside.sort_by_key(|(address, _)| **address);
                out.extend(inside.into_iter().flat_map(|(_, entries)| entries.clone()));
                out.extend(
                    self.blocks
                        .iter()
                        .filter(|(block, _)| {
                            within.contains(block.network()) || block.contains(within.network())
                        })
                        .map(|(_, entry)| entry.clone()),
                );
            }
        }
        out.dedup();
        out
    }
}

/// Every entry of a feed body in `format`.
fn index(format: Format, body: &str) -> Listed {
    let mut listed = Listed::default();
    if format == Format::Onionoo {
        index_relays(body, &mut listed);
        return listed;
    }
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let keys: Vec<Key> = match format {
            Format::Lines => trimmed
                .split_whitespace()
                .next()
                .and_then(listed_key)
                .into_iter()
                .collect(),
            Format::Hosts => trimmed
                .split_whitespace()
                .skip(1)
                .take_while(|word| !word.starts_with('#'))
                .filter(|word| word.parse::<IpAddr>().is_err())
                .filter_map(host_name)
                .filter(|name| !name.ends_with(".localdomain"))
                .map(Key::Name)
                .collect(),
            Format::Urls => url_key(trimmed).into_iter().collect(),
            Format::Csv(column) => csv_fields(trimmed)
                .get(column)
                .and_then(|field| url_key(field))
                .into_iter()
                .collect(),
            Format::Onionoo => Vec::new(),
        };
        if !keys.is_empty() {
            listed.entries += 1;
        }
        for key in keys {
            listed.add(key, line);
        }
    }
    listed
}

/// An address, a block or a host name, as a list line's first word gives one. A block of one
/// address is that address.
fn listed_key(word: &str) -> Option<Key> {
    if let Ok(address) = word.parse::<IpAddr>() {
        return Some(Key::Address(address));
    }
    if let Some(block) = Netblock::parse(word) {
        let whole = if block.is_ipv6() { 128 } else { 32 };
        return Some(if block.prefix_len() == whole {
            Key::Address(block.network())
        } else {
            Key::Block(block)
        });
    }
    host_name(word).map(Key::Name)
}

/// The host of a URL, with or without its scheme, or of a bare host name: an address or a name.
fn url_key(url: &str) -> Option<Key> {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(bracketed)
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    if let Ok(address) = host.parse::<IpAddr>() {
        return Some(Key::Address(address));
    }
    host_name(host).map(Key::Name)
}

/// `raw` as a host name in lower case without a trailing dot, when it is one: dotted labels of
/// letters, digits, `-` and `_`, at most 253 characters.
fn host_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && name.parse::<IpAddr>().is_err();
    valid.then_some(name)
}

/// The fields of one CSV line: commas separate them, and a field in double quotes may hold commas
/// and doubled quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// Each exit relay in an Onionoo details document, under every address it exits from or listens
/// on, with its whole record as the entry.
fn index_relays(body: &str, listed: &mut Listed) {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    let Some(relays) = document.get("relays").and_then(serde_json::Value::as_array) else {
        return;
    };
    for relay in relays {
        let record = relay.to_string();
        let strings = |key: &str| -> Vec<String> {
            relay
                .get(key)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        };
        let mut addresses: Vec<IpAddr> = strings("exit_addresses")
            .iter()
            .filter_map(|address| address.parse().ok())
            .collect();
        for listen in strings("or_addresses") {
            if let Some(Key::Address(address)) = url_key(&listen) {
                addresses.push(address);
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        if !addresses.is_empty() {
            listed.entries += 1;
        }
        for address in addresses {
            listed.add(Key::Address(address), &record);
        }
    }
}

/// One listing of `subject` on `feed`, as evidence on it.
fn push_listing(
    entities: &mut Vec<Entity>,
    feed: &Feed,
    read: &Read,
    subject: &Subject,
    entries: &[String],
    scan_id: &str,
) {
    let value = subject.value();
    let copy = crate::timefmt::format_unix(i64::try_from(read.fetched).unwrap_or(i64::MAX));
    let provenance = EvidenceProvenance::for_scan(feed.source, scan_id);
    let entries = entries.join("\n");
    let (evidence, tags): (Evidence, &[&str]) = match feed.meaning {
        Meaning::TorExit => (
            Evidence::new(provenance, format!("{value} is a Tor exit relay"))
                .with_attr("tor", "true")
                .with_attr("tor_relays", entries)
                .with_attr("tor_relays_url", feed.url)
                .with_attr("tor_relays_copy", copy),
            &[tags::TOR_EXIT],
        ),
        Meaning::Threat | Meaning::Listing => {
            let threat = feed.meaning == Meaning::Threat;
            let mut evidence =
                Evidence::new(provenance, format!("{value} is listed by {}", feed.name))
                    .with_attr("threat_feed", feed.name)
                    .with_attr("threat_feed_threat", if threat { "true" } else { "false" })
                    .with_attr("threat_feed_url", feed.url)
                    .with_attr("threat_feed_entries", entries)
                    .with_attr("threat_feed_copy", copy);
            if threat {
                evidence = evidence.with_attr("blocklists", feed.name);
            }
            (evidence, if threat { &[tags::MALICIOUS] } else { &[] })
        }
    };
    push_entity(
        entities,
        subject.kind(),
        &value,
        LISTED_CONFIDENCE,
        scan_id,
        evidence,
        tags,
    );
}

/// One row per source, joining what each of its feeds said.
fn rows(said: &[(&Feed, Result<Read, Failure>)], now_unix: u64) -> Vec<SourceExecutionOutcome> {
    let mut sources: Vec<&str> = said.iter().map(|(feed, _)| feed.source).collect();
    sources.dedup();
    sources
        .into_iter()
        .map(|source| {
            let mine: Vec<&(&Feed, Result<Read, Failure>)> = said
                .iter()
                .filter(|(feed, _)| feed.source == source)
                .collect();
            let detail = mine
                .iter()
                .map(|(feed, result)| format!("{}: {}", feed.name, row_detail(result)))
                .collect::<Vec<_>>()
                .join("; ");
            let listed: usize = mine
                .iter()
                .filter_map(|(_, result)| result.as_ref().ok())
                .map(|read| read.matches.len())
                .sum();
            let failure = mine.iter().find_map(|(_, result)| result.as_ref().err());
            let answered = mine.iter().any(|(_, result)| result.is_ok());
            match (listed, failure) {
                (0, Some((kind, _))) if !answered => {
                    SourceExecutionOutcome::failed(source, now_unix, *kind, None, &detail)
                }
                (0, _) => SourceExecutionOutcome::valid_zero(source, now_unix).with_detail(detail),
                (count, _) => {
                    SourceExecutionOutcome::success(source, now_unix, count).with_detail(detail)
                }
            }
        })
        .collect()
}

/// What one feed said, for its source's row.
fn row_detail(result: &Result<Read, Failure>) -> String {
    let read = match result {
        Ok(read) => read,
        Err((_, why)) => return why.clone(),
    };
    let said = if read.matches.is_empty() {
        "not listed".to_owned()
    } else {
        format!(
            "lists {}",
            read.matches
                .iter()
                .map(|(subject, _)| subject.value())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let copy = if read.downloaded {
        "downloaded now".to_owned()
    } else {
        format!(
            "copy from {}",
            crate::timefmt::format_unix(i64::try_from(read.fetched).unwrap_or(i64::MAX))
        )
    };
    let note = read
        .note
        .as_ref()
        .map_or(String::new(), |why| format!(", {why}"));
    format!("{said} ({} entries, {copy}{note})", read.entries)
}

#[cfg(test)]
mod tests;
