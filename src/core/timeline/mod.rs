//! Timeline engine — semantic temporal reconstruction over the entity graph.
//!
//! SpiderFoot surfaces dates as opaque per-event metadata. The charter's
//! superiority condition is *streaming timeline reconstruction*: a single,
//! continuously-rebuildable chronology of the meaningful events implied by the
//! graph — when a breach happened, when a domain was registered or expires,
//! when an account was created, when an org was incorporated or dissolved.
//!
//! [`reconstruct`] is a pure function over a slice of entities: it walks each
//! entity's evidence attributes, maps known date-bearing keys to a typed
//! [`TimelineEventKind`], parses the value into a Unix timestamp, and returns
//! the events sorted oldest-first. No I/O, no allocation beyond the output —
//! so the engine can call it incrementally during ingestion (streaming) or the
//! CLI/API can render it on demand (batch) from the same code path.
//!
//! Date parsing is dependency-free (no `chrono`): it accepts Unix seconds,
//! Unix milliseconds, ISO-8601 dates/datetimes, `YYYY/MM/DD`, and bare years,
//! converting calendar dates via Howard Hinnant's `days_from_civil` algorithm.

use serde::{Deserialize, Serialize};

use crate::core::entity::Entity;

/// The semantic class of a reconstructed event. Drives ordering ties,
/// display grouping, and downstream attribution reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    /// Credentials/data exposed in a breach (breach_date, data_breach).
    BreachExposure,
    /// Domain/registration created (registered, created, created_at).
    Registered,
    /// Resource expiry (expires).
    Expiry,
    /// Account/profile creation on a platform.
    AccountCreated,
    /// Company incorporation.
    Incorporation,
    /// Company dissolution.
    Dissolution,
    /// First time an artefact was observed in the wild.
    FirstSeen,
    /// Most recent observation of an artefact.
    LastSeen,
    /// Person date of birth.
    DateOfBirth,
    /// A geolocated observation instant — currently `exif_geo`'s `shot_time`
    /// (the EXIF `DateTimeOriginal`/`DateTime` tag) tied to the photo's
    /// extracted `Coordinates` entity: proof the subject (or their device)
    /// was physically at that place at that time. The movement/timeline geo
    /// signal `PROBLEM_TREE` C5/C1(c) name as remaining — two or more of
    /// these across a scan chart where the subject has actually been, not
    /// just where they claim to live.
    LocationVisited,
    /// Anything date-like we recognised but can't classify more precisely.
    Generic,
}

impl TimelineEventKind {
    /// Human-display label for the timeline UI/export. **Deliberately NOT the
    /// serde wire form** (CONVENTIONS.md §3, display-variant clause): every
    /// arm matches the `snake_case` serde tag *except* `Generic`, which
    /// renders as the friendlier `"event"` rather than serde's `"generic"`.
    /// Do not "align" it to serde — the divergence is intentional, which is
    /// why this type has no serde-agreement pin.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BreachExposure => "breach_exposure",
            Self::Registered => "registered",
            Self::Expiry => "expiry",
            Self::AccountCreated => "account_created",
            Self::Incorporation => "incorporation",
            Self::Dissolution => "dissolution",
            Self::FirstSeen => "first_seen",
            Self::LastSeen => "last_seen",
            Self::DateOfBirth => "date_of_birth",
            Self::LocationVisited => "location_visited",
            Self::Generic => "event",
        }
    }
}

/// One reconstructed point on the chronology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Unix seconds — the sort key and canonical instant. **Signed**: pre-1970
    /// instants (e.g. a date of birth) are legitimately negative, so this must
    /// not be `u64` or `reconstruct`'s oldest-first sort would place every
    /// pre-epoch event *after* the 1970+ ones.
    pub ts: i64,
    /// Normalised `YYYY-MM-DD` (or `YYYY-MM-DDTHH:MM:SSZ`) for display.
    pub iso: String,
    pub kind: TimelineEventKind,
    /// Human-readable one-liner.
    pub label: String,
    pub entity_uid: String,
    pub entity_value: String,
    pub entity_kind: String,
    /// The module/attribute that supplied the date.
    pub source: String,
    /// Confidence inherited from the originating entity.
    pub confidence: f64,
}

/// Maps an evidence attribute key to the event class it represents. Returning
/// `None` means the attribute is not a recognised timeline date.
///
/// `AccountCreated`'s keys are real, live evidence attributes stamped by
/// first-party modules (`account_created`: `oathnet_pro`/`stackoverflow_user`;
/// `joined_at`: `devto`; `discord_created_date`/`discord_created_unix_ms`:
/// `discord_snowflake`'s decoded snowflake timestamp; `uuid_created_date`:
/// `structured_id`'s decoded UUIDv1 timestamp) — before this match gained
/// them, none mapped to anything, so `TimelineEventKind::AccountCreated` was
/// unreachable dead code and every one of these dates was silently absent
/// from the timeline. The same fix originally landed only 1 of `structured_id`'s
/// 4 timestamp-embedding ID decoders: `objectid_created_date`/`ulid_created_date`/
/// `ksuid_created_date` (MongoDB ObjectID, ULID, KSUID — `structured_id::emit_creation`,
/// the sibling code path to the UUIDv1 case right beside it in the same module)
/// were left out of this match, so 3 of the module's 4 decoded creation dates
/// stayed silently dropped from the timeline even after `uuid_created_date` was
/// fixed. `birth_date`/`death_date` (`wikidata`'s Wikidata-claim
/// dates) and `verified_at` (`mastodon_user`'s profile-field verification
/// timestamp) were equally live and equally unmatched. `shot_time`
/// (`exif_geo`'s `DateTimeOriginal`/`DateTime` EXIF tag, stamped on every
/// entity a photo yields — including its extracted `Coordinates`) was the
/// same story: defined nowhere in this match, so a photo's capture instant
/// was silently dropped from the timeline even when its GPS location made it
/// there. Recognising it closes the C5/C1(c) "movement/timeline geo" gap:
/// dated `Coordinates` events are exactly what tells the footprint timeline
/// *where* the subject was, not just *when* something about them happened.
fn classify(attr_key: &str) -> Option<TimelineEventKind> {
    use TimelineEventKind::*;
    let kind = match attr_key.to_ascii_lowercase().as_str() {
        "breach_date" | "data_breach" => BreachExposure,
        "incorporation_date" => Incorporation,
        "dissolution_date" => Dissolution,
        "registered" | "created" | "created_at" | "created_at_unix" => Registered,
        "account_created"
        | "joined_at"
        | "discord_created_date"
        | "discord_created_unix_ms"
        | "uuid_created_date"
        | "objectid_created_date"
        | "ulid_created_date"
        | "ksuid_created_date" => AccountCreated,
        "expires" | "expire_secs" => Expiry,
        "first_seen" | "first_seen_iso" | "first_pulse_created" => FirstSeen,
        "last_seen" | "last_seen_iso" | "last_updated" | "last_update" | "updated" => LastSeen,
        "date_of_birth" | "birth_date" => DateOfBirth,
        "shot_time" => LocationVisited,
        "start_date" | "review_date" | "end_date" | "date" | "timestamp" | "death_date"
        | "verified_at" => Generic,
        _ => return None,
    };
    Some(kind)
}

/// Reconstruct the chronological timeline implied by `entities`.
///
/// Pure: walks evidence attributes, parses recognised date keys, and returns
/// the events sorted oldest-first (ties broken by entity value then kind for
/// determinism). Duplicate (ts, kind, entity, source) tuples are collapsed.
///
/// Candidate-quarantined entities (`tags::CANDIDATE` — breach co-occurrence
/// strangers who merely sat near the subject in a dump) are excluded: the
/// footprint timeline is the SUBJECT's chronology, so a neighbour's birth date /
/// address / email must never appear as if it were the subject's life event. This
/// mirrors the candidate exclusion the correlator and exposure index already
/// apply.
pub fn reconstruct(entities: &[Entity]) -> Vec<TimelineEvent> {
    let mut events: Vec<TimelineEvent> = Vec::new();
    for e in entities {
        if e.has_tag(crate::core::tags::CANDIDATE) {
            continue;
        }
        for ev in &e.evidence {
            for (key, raw) in &ev.attributes {
                let Some(kind) = classify(key) else { continue };
                let Some((ts, iso)) = parse_date(raw) else {
                    continue;
                };
                events.push(TimelineEvent {
                    ts,
                    iso,
                    kind,
                    label: format!("{} {} ({} = {raw})", e.kind, e.value, key),
                    entity_uid: e.uid.clone(),
                    entity_value: e.value.clone(),
                    entity_kind: e.kind.to_string(),
                    source: format!("{}:{key}", ev.source),
                    confidence: e.confidence,
                });
            }
        }
    }
    events.sort_by(|a, b| {
        a.ts.cmp(&b.ts)
            .then_with(|| a.entity_value.cmp(&b.entity_value))
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
            .then_with(|| a.source.cmp(&b.source))
    });
    events.dedup_by(|a, b| {
        a.ts == b.ts && a.kind == b.kind && a.entity_uid == b.entity_uid && a.source == b.source
    });
    events
}

/// A summary of the subject's **online tenure** — how long their digital footprint
/// has existed and how exposed it is. The headline temporal fact: "online since
/// 2008, a 17-year footprint across 9 breaches".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnlineTenure {
    /// Earliest presence instant (Unix seconds) and its `YYYY-MM-DD…` form.
    pub earliest_ts: i64,
    pub earliest_iso: String,
    /// Most recent presence instant.
    pub latest_ts: i64,
    pub latest_iso: String,
    /// Whole-year span from earliest to latest presence — the footprint's age.
    pub span_years: u32,
    /// Presence events counted (everything except DOB and future expiries).
    pub event_count: usize,
    /// Distinct breach-exposure events — the depth of the subject's breach history.
    pub breach_count: usize,
}

/// Summarise the subject's online tenure from a reconstructed [`reconstruct`]
/// timeline — the span and exposure depth of their digital footprint.
///
/// Counts only **presence** events: a [`TimelineEventKind::DateOfBirth`] predates
/// the online footprint (it would wrongly stretch tenure back to the birth year)
/// and an [`TimelineEventKind::Expiry`] is a future resource event, so both are
/// excluded; everything else (breach exposure, account creation, registration,
/// first/last seen) dates the subject's actual presence. `span_years` is the
/// whole-year gap between the earliest and latest such event (mean Gregorian
/// year). Pure and order-independent. `None` when the timeline carries no presence
/// event at all — so a footprint dated only by a DOB reports no tenure rather than
/// a misleading multi-decade span.
#[must_use]
pub fn online_tenure(events: &[TimelineEvent]) -> Option<OnlineTenure> {
    let presence: Vec<&TimelineEvent> = events
        .iter()
        .filter(|e| {
            !matches!(
                e.kind,
                TimelineEventKind::DateOfBirth | TimelineEventKind::Expiry
            )
        })
        .collect();
    let first = presence.iter().min_by_key(|e| e.ts)?;
    let last = presence.iter().max_by_key(|e| e.ts)?;
    Some(OnlineTenure {
        earliest_ts: first.ts,
        earliest_iso: first.iso.clone(),
        latest_ts: last.ts,
        latest_iso: last.iso.clone(),
        // Mean Gregorian year (365.2425 d); `max(0)` guards a pathological
        // out-of-order pair from underflowing.
        span_years: u32::try_from((last.ts - first.ts).max(0) / 31_556_952).unwrap_or(u32::MAX),
        event_count: presence.len(),
        breach_count: presence
            .iter()
            .filter(|e| e.kind == TimelineEventKind::BreachExposure)
            .count(),
    })
}

/// How current the subject's online footprint is, by the age of its most recent
/// dated activity — the difference between a live subject and a long-dormant one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintStatus {
    /// Under 1 whole year (0 years elapsed) — a live, current footprint.
    Active,
    /// 1–2 whole years — recently active.
    Recent,
    /// 3–6 whole years — going cold.
    Aging,
    /// 7 or more whole years since any dated activity — a dormant/historical footprint.
    Dormant,
}

impl FootprintStatus {
    /// Stable snake_case label (matches the serde wire form).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Recent => "recent",
            Self::Aging => "aging",
            Self::Dormant => "dormant",
        }
    }
}

/// The recency of the subject's footprint: how long since its most recent dated
/// activity, and the resulting [`FootprintStatus`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FootprintRecency {
    /// Whole years since the latest presence event.
    pub years_since_latest: u32,
    pub status: FootprintStatus,
}

/// Classify how current a footprint is from its `latest_ts` (the most recent
/// presence instant, e.g. [`OnlineTenure::latest_ts`]) relative to `now_unix`.
///
/// A recent footprint matters operationally: a current account / fresh breach
/// means the subject's exposed credentials are likely still in use (live
/// account-takeover risk), whereas a decade-dormant footprint is historical.
/// Pure; thresholds are whole-year bands (mean Gregorian year). A future
/// `latest_ts` clamps to zero years ([`FootprintStatus::Active`]).
#[must_use]
pub fn footprint_recency(latest_ts: i64, now_unix: i64) -> FootprintRecency {
    let years = u32::try_from((now_unix - latest_ts).max(0) / 31_556_952).unwrap_or(u32::MAX);
    let status = match years {
        0 => FootprintStatus::Active,
        1..=2 => FootprintStatus::Recent,
        3..=6 => FootprintStatus::Aging,
        _ => FootprintStatus::Dormant,
    };
    FootprintRecency {
        years_since_latest: years,
        status,
    }
}

/// One leg of a reconstructed movement path — the straight-line hop between
/// two consecutive [`TimelineEventKind::LocationVisited`] fixes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MovementLeg {
    pub from_iso: String,
    pub from_coords: String,
    pub to_iso: String,
    pub to_coords: String,
    /// Great-circle distance between the two fixes ([`crate::util::geo::haversine_km`]).
    pub distance_km: f64,
}

/// A reconstructed movement path: the subject's (or their device's) dated
/// location fixes, walked in chronological order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Movement {
    pub legs: Vec<MovementLeg>,
    /// Sum of every leg's `distance_km` — the total great-circle distance
    /// covered across all fixes. **Not** a real travel distance (no road/route
    /// modelling, just point-to-point straight lines), so callers should label
    /// it accordingly.
    pub total_km: f64,
    /// Count of location fixes the path was built from (`legs.len() + 1`).
    pub locations_visited: usize,
}

/// Reconstruct a chronological movement path from a [`reconstruct`]ed
/// timeline's [`TimelineEventKind::LocationVisited`] events — "the subject's
/// device was physically at A on date 1, then B on date 2, C km apart".
///
/// The C5/C1(c) "movement/timeline geo" capability's path-reconstruction
/// increment: `LocationVisited` events already exist (currently sourced from
/// `exif_geo`'s `shot_time`, tied to the photo's extracted `Coordinates`
/// entity), and multiple photos taken at different times/places are exactly
/// the evidence a movement path is built from. This is a thin, pure fold over
/// already-reconstructed events — no new data source, no new module.
///
/// `events` is expected pre-sorted oldest-first (as [`reconstruct`] returns
/// it); this function does not re-sort, so a caller passing already-sorted
/// events gets a deterministic, chronological path. Events whose
/// `entity_value` does not parse as a coordinate (defensive — every current
/// `LocationVisited` producer emits a `Coordinates` entity, but the mapping is
/// keyed on evidence-attribute name, not entity kind, so this stays honest
/// rather than assuming) are skipped rather than breaking the chain.
///
/// Returns `None` when fewer than two parseable fixes exist — a single
/// location is a point, not a path, and fabricating a one-node "movement"
/// would misstate what was actually observed.
#[must_use]
pub fn movement_path(events: &[TimelineEvent]) -> Option<Movement> {
    let fixes: Vec<&TimelineEvent> = events
        .iter()
        .filter(|e| e.kind == TimelineEventKind::LocationVisited)
        .collect();
    let mut legs = Vec::new();
    let mut total_km = 0.0;
    let mut located = 0usize;
    let mut prev: Option<(&TimelineEvent, f64, f64)> = None;
    for fix in fixes {
        let Some(here) = crate::util::geo::coords::parse(&fix.entity_value) else {
            continue;
        };
        let (lat, lon) = (here.lat, here.lon);
        located += 1;
        if let Some((prev_ev, prev_lat, prev_lon)) = prev {
            let km = crate::util::geo::haversine_km(prev_lat, prev_lon, lat, lon);
            total_km += km;
            legs.push(MovementLeg {
                from_iso: prev_ev.iso.clone(),
                from_coords: prev_ev.entity_value.clone(),
                to_iso: fix.iso.clone(),
                to_coords: fix.entity_value.clone(),
                distance_km: km,
            });
        }
        prev = Some((fix, lat, lon));
    }
    if located < 2 {
        return None;
    }
    Some(Movement {
        legs,
        total_km,
        locations_visited: located,
    })
}

// ─── Dependency-free date parsing ────────────────────────────────────────────

/// Days from the civil date 1970-01-01 to `y-m-d` (Howard Hinnant's algorithm).
/// Exact for every real Gregorian date; returns a signed day count.
///
/// **Caller precondition — bound the year first.** This helper does *not*
/// validate its inputs, and neither its own `era * 146097` nor the `days *
/// 86_400` that every second-converting caller applies to the result is
/// overflow-checked — so an absurd, out-of-calendar-range year wraps (release)
/// or panics under overflow-checks (test) instead of erroring. Real calendar
/// years are nowhere near that bound, but a caller parsing an *untrusted* date
/// string must reject a wild year before calling, as every current caller
/// already does: `parse_date` (`1900..=2100`), `age_from_dob` (a 4-ASCII-digit
/// year, so `<= 9999`), and `hudsonrock`'s `parse_iso_epoch` (`2000..=2100`).
/// That last guard is not decoration: a 13-digit year reaching this function
/// unbounded was the root of the hudsonrock breach-date overflow.
///
/// `pub(crate)` so other modules that need an exact date→epoch conversion can
/// reuse this leap-year-correct implementation rather than re-deriving an
/// approximate one (e.g. the `hudsonrock` module's freshness check).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Parse a date-ish string into `(unix_seconds, normalised_iso)`.
///
/// Accepts: Unix seconds (10 digits), Unix milliseconds (13 digits), bare year
/// (`1998`), `YYYY-MM-DD`, `YYYY/MM/DD`, `YYYY:MM:DD` (the EXIF
/// `DateTimeOriginal`/`DateTime` tag's own separator — `exif_geo`'s `shot_time`
/// evidence attribute is stamped verbatim from the file, so the timeline parser
/// must speak the format the source actually uses, not a normalised one), and
/// `YYYY-MM-DDTHH:MM:SS[Z]` (or the EXIF form's `YYYY:MM:DD HH:MM:SS`).
/// Anything else (or an out-of-range field) returns `None` so callers skip it
/// cleanly.
pub fn parse_date(raw: &str) -> Option<(i64, String)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // Pure-digit forms: epoch seconds / milliseconds, or a bare year.
    if s.bytes().all(|b| b.is_ascii_digit()) {
        match s.len() {
            13 => return s.parse::<i64>().ok().map(|ms| from_unix(ms / 1000)),
            10 => return s.parse::<i64>().ok().map(from_unix),
            4 => {
                let y: i64 = s.parse().ok()?;
                if (1900..=2100).contains(&y) {
                    return Some(civil_to_unix(y, 1, 1, 0, 0, 0));
                }
                return None;
            }
            _ => return None,
        }
    }

    // Calendar forms: split date from optional time.
    let (date_part, time_part) = match s.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    // `:` is EXIF's own date separator (`DateTimeOriginal`/`DateTime`:
    // `"2019:03:15 08:30:00"`) — safe to accept here because `date_part` is
    // already isolated from any `HH:MM:SS` time component by the `split_once`
    // above, so there is no ambiguity with the time's own colons.
    let sep = if date_part.contains('-') {
        '-'
    } else if date_part.contains('/') {
        '/'
    } else if date_part.contains(':') {
        ':'
    } else {
        return None;
    };
    let mut it = date_part.split(sep);
    let y: i64 = it.next()?.parse().ok()?;
    let mo: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    if !(1900..=2100).contains(&y) {
        return None;
    }
    // Reject impossible day-of-month (e.g. 2-30) so junk doesn't slip through.
    let dim = [
        31,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d > dim[(mo - 1) as usize] {
        return None;
    }

    let (mut hh, mut mm, mut ss) = (0i64, 0i64, 0i64);
    if let Some(t) = time_part {
        let t = t.trim_end_matches('Z');
        let mut tit = t.split(':');
        // A present time component must actually parse — otherwise a malformed
        // time (e.g. "2019-03-15Tinvalid") would silently coerce to 00:00:00
        // and be accepted as midnight. The hour is mandatory once a time part
        // exists; the minute is mandatory when present (no standard format
        // glues a timezone offset onto it).
        hh = tit.next()?.parse().ok()?;
        mm = match tit.next() {
            Some(v) => v.parse().ok()?,
            None => 0,
        };
        // Seconds may carry a fractional part / timezone offset, which split(':')
        // glues onto this token (e.g. "00+05" from "+05:00"); take the leading
        // integer and tolerate the rest rather than rejecting offset timestamps.
        ss = tit
            .next()
            .map(|v| v.trim_matches(|c: char| !c.is_ascii_digit() && c != '-'))
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if !(0..24).contains(&hh) || !(0..60).contains(&mm) || !(0..60).contains(&ss) {
            return None;
        }
    }
    Some(civil_to_unix(y, mo, d, hh, mm, ss))
}

fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> (i64, String) {
    let days = days_from_civil(y, m, d);
    // Signed: a pre-1970 date yields a negative instant. Do NOT clamp to 0 —
    // that would collapse every pre-epoch event onto the same sort key and
    // break the oldest-first chronology while the ISO string stayed correct.
    let ts = days * 86400 + hh * 3600 + mm * 60 + ss;
    let iso = if hh == 0 && mm == 0 && ss == 0 {
        format!("{y:04}-{m:02}-{d:02}")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    };
    (ts, iso)
}

/// UTC `YYYY-MM-DD` for a Unix-seconds instant — Hinnant's `civil_from_days`,
/// the exact inverse of [`days_from_civil`]. `div_euclid` floors toward
/// negative infinity so a negative `unix_secs` (pre-1970) maps to the correct
/// civil day rather than truncating toward zero. Pure, dependency-free,
/// deterministic.
///
/// The single home for this calendar conversion. Modules that decode a
/// timestamp out of an identifier — [`crate::modules::structured_id`] (UUIDv1 /
/// ULID) and [`crate::modules::discord_snowflake`] — render it through this
/// rather than each re-deriving the arithmetic: three divergent copies of
/// leap-year math is a latent bug-farm where a fix to one silently skips the
/// others.
pub(crate) fn utc_date(unix_secs: i64) -> String {
    let z = unix_secs.div_euclid(86400) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert Unix seconds back into a normalised `YYYY-MM-DD` display string,
/// pairing it with the input timestamp.
fn from_unix(ts: i64) -> (i64, String) {
    (ts, utc_date(ts))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
