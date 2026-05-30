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
    /// Anything date-like we recognised but can't classify more precisely.
    Generic,
}

impl TimelineEventKind {
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
            Self::Generic => "event",
        }
    }
}

/// One reconstructed point on the chronology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Unix seconds — the sort key and canonical instant.
    pub ts: u64,
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
fn classify(attr_key: &str) -> Option<TimelineEventKind> {
    use TimelineEventKind::*;
    let kind = match attr_key.to_ascii_lowercase().as_str() {
        "breach_date" | "data_breach" => BreachExposure,
        "incorporation_date" => Incorporation,
        "dissolution_date" => Dissolution,
        "registered" | "created" | "created_at" | "created_at_unix" => Registered,
        "expires" | "expire_secs" => Expiry,
        "first_seen" | "first_seen_iso" => FirstSeen,
        "last_seen" | "last_seen_iso" | "last_updated" | "last_update" | "updated" => LastSeen,
        "date_of_birth" => DateOfBirth,
        "start_date" | "review_date" | "end_date" | "date" | "timestamp" => Generic,
        _ => return None,
    };
    Some(kind)
}

/// Reconstruct the chronological timeline implied by `entities`.
///
/// Pure: walks evidence attributes, parses recognised date keys, and returns
/// the events sorted oldest-first (ties broken by entity value then kind for
/// determinism). Duplicate (ts, kind, entity, source) tuples are collapsed.
pub fn reconstruct(entities: &[Entity]) -> Vec<TimelineEvent> {
    let mut events: Vec<TimelineEvent> = Vec::new();
    for e in entities {
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

// ─── Dependency-free date parsing ────────────────────────────────────────────

/// Days from the civil date 1970-01-01 to `y-m-d` (Howard Hinnant's algorithm).
/// Valid for any Gregorian date; returns a signed day count.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
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
/// (`1998`), `YYYY-MM-DD`, `YYYY/MM/DD`, and `YYYY-MM-DDTHH:MM:SS[Z]`. Anything
/// else (or an out-of-range field) returns `None` so callers skip it cleanly.
pub fn parse_date(raw: &str) -> Option<(u64, String)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // Pure-digit forms: epoch seconds / milliseconds, or a bare year.
    if s.bytes().all(|b| b.is_ascii_digit()) {
        match s.len() {
            13 => return s.parse::<u64>().ok().map(|ms| from_unix(ms / 1000)),
            10 => return s.parse::<u64>().ok().map(from_unix),
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
    let sep = if date_part.contains('-') {
        '-'
    } else if date_part.contains('/') {
        '/'
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

fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> (u64, String) {
    let days = days_from_civil(y, m, d);
    let secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    let ts = secs.max(0) as u64;
    let iso = if hh == 0 && mm == 0 && ss == 0 {
        format!("{y:04}-{m:02}-{d:02}")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    };
    (ts, iso)
}

/// Convert Unix seconds back into a normalised `YYYY-MM-DD` display string,
/// pairing it with the input timestamp.
fn from_unix(ts: u64) -> (u64, String) {
    // Inverse of days_from_civil (Hinnant's civil_from_days).
    let z = (ts / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (ts, format!("{y:04}-{m:02}-{d:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn entity_with_attrs(
        kind: EntityKind,
        value: &str,
        src: &str,
        attrs: &[(&str, &str)],
    ) -> Entity {
        let mut e = Entity::new(kind, value, 0.9, "scan");
        let mut ev = Evidence::new(src, "t");
        for (k, v) in attrs {
            ev = ev.with_attr(*k, *v);
        }
        e.add_evidence(ev);
        e
    }

    #[test]
    fn parses_epoch_seconds() {
        let (ts, iso) = parse_date("1262304000").unwrap();
        assert_eq!(ts, 1_262_304_000);
        assert_eq!(iso, "2010-01-01");
    }

    #[test]
    fn parses_epoch_millis() {
        let (ts, _) = parse_date("1262304000000").unwrap();
        assert_eq!(ts, 1_262_304_000);
    }

    #[test]
    fn parses_iso_date_and_datetime() {
        assert_eq!(parse_date("2019-03-15").unwrap().1, "2019-03-15");
        let (_, iso) = parse_date("2019-03-15T08:30:00Z").unwrap();
        assert_eq!(iso, "2019-03-15T08:30:00Z");
        assert_eq!(parse_date("2019/03/15").unwrap().1, "2019-03-15");
    }

    #[test]
    fn parses_bare_year() {
        assert_eq!(parse_date("1998").unwrap().1, "1998-01-01");
    }

    #[test]
    fn rejects_malformed_time_but_tolerates_offset() {
        // A present-but-unparseable time must be rejected, not coerced to
        // midnight (00:00:00) and silently accepted.
        assert!(parse_date("2019-03-15Tinvalid").is_none());
        assert!(parse_date("2019-03-15T08:bad").is_none()); // garbage minute
        assert!(parse_date("2019-03-15T").is_none()); // empty time part
        // Out-of-range components still reject.
        assert!(parse_date("2019-03-15T25:00:00").is_none());
        // Hour- and minute-only times remain valid (trailing parts default 0).
        assert_eq!(
            parse_date("2019-03-15T08").unwrap().1,
            "2019-03-15T08:00:00Z"
        );
        assert_eq!(
            parse_date("2019-03-15T08:30").unwrap().1,
            "2019-03-15T08:30:00Z"
        );
        // Seconds stay lenient so a timezone offset (split onto the seconds
        // token by ':') doesn't reject an otherwise-valid timestamp.
        let (_, iso) = parse_date("2019-03-15T08:30:00+05:00").unwrap();
        assert_eq!(iso, "2019-03-15T08:30:00Z");
    }

    #[test]
    fn rejects_garbage_and_impossible_dates() {
        assert!(parse_date("not-a-date").is_none());
        assert!(parse_date("").is_none());
        assert!(parse_date("2019-13-01").is_none()); // month 13
        assert!(parse_date("2019-02-30").is_none()); // feb 30
        assert!(parse_date("1850-01-01").is_none()); // out of range year
    }

    #[test]
    fn epoch_roundtrips_through_civil() {
        // A known instant: 2021-06-15 -> seconds -> back to same ISO.
        let (ts, _) = parse_date("2021-06-15").unwrap();
        assert_eq!(from_unix(ts).1, "2021-06-15");
    }

    #[test]
    fn reconstructs_sorted_classified_timeline() {
        let entities = vec![
            entity_with_attrs(
                EntityKind::Email,
                "a@b.com",
                "hibp",
                &[("breach_date", "2019-03-15")],
            ),
            entity_with_attrs(
                EntityKind::Domain,
                "b.com",
                "rdap_domain",
                &[("registered", "2008-06-01"), ("expires", "2026-06-01")],
            ),
        ];
        let tl = reconstruct(&entities);
        assert_eq!(tl.len(), 3);
        // Sorted oldest-first.
        assert_eq!(tl[0].iso, "2008-06-01");
        assert_eq!(tl[0].kind, TimelineEventKind::Registered);
        assert_eq!(tl[1].kind, TimelineEventKind::BreachExposure);
        assert_eq!(tl[2].kind, TimelineEventKind::Expiry);
        assert!(tl.iter().all(|e| e.ts > 0));
    }

    #[test]
    fn ignores_non_date_attributes() {
        let entities = vec![entity_with_attrs(
            EntityKind::Domain,
            "x.com",
            "whois",
            &[("breach_count", "5"), ("registered_address", "1 Main St")],
        )];
        // breach_count is numeric but not a date key; registered_address is text.
        assert!(reconstruct(&entities).is_empty());
    }

    #[test]
    fn dedups_identical_events() {
        let e = entity_with_attrs(
            EntityKind::Email,
            "a@b.com",
            "hibp",
            &[("breach_date", "2019-03-15")],
        );
        // Same entity twice → one event after dedup.
        let tl = reconstruct(&[e.clone(), e]);
        assert_eq!(tl.len(), 1);
    }
}
