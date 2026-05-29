//! `core::temporal` — behavioural & temporal pattern analysis over the corpus.
//!
//! OSINT subjects leave timestamps scattered across the artefacts modules
//! collect: account-creation dates, last-seen markers, commit pushes,
//! certificate validity windows, paste timestamps, breach dates. Taken
//! individually each is noise; aggregated across the entity corpus they
//! describe a *behavioural rhythm* — when the subject is active, in which
//! diurnal band, and therefore (probabilistically) in which timezone.
//!
//! This engine extracts those timestamps, folds them onto a 24-hour /
//! 7-day clock, infers a UTC offset from the diurnal quiet-window, and
//! flags activity bursts. It is the temporal counterpart to the spatial
//! correlation already done in the geo rules: a subject whose activity
//! troughs at 03:00 local but whose timestamps trough at 18:00 UTC is
//! almost certainly living around UTC+9.
//!
//! # Architecture invariants
//! - Pure arithmetic. No `chrono`, no native deps, no I/O, no clock reads
//!   except an injected/`unix_now` reference where decay matters.
//! - Deterministic: identical entity input ⇒ identical profile.
//! - `core` purity: depends only on `core::entity`.

use crate::core::entity::Entity;

// ─── Tunables ────────────────────────────────────────────────────────────────

/// Minimum distinct timestamp samples before an [`ActivityProfile`] is
/// considered meaningful. Below this the diurnal histogram is too sparse to
/// trust a timezone inference.
pub const MIN_SAMPLES: usize = 5;

/// Assumed local hour at the centre of a human's diurnal activity trough
/// (deep sleep). The quiet-window heuristic anchors the inferred offset to
/// this: if activity bottoms out at hour `h` UTC, local 03:00 ≈ `h`.
pub const QUIET_CENTRE_LOCAL_HOUR: i64 = 3;

/// Maximum inter-event gap (seconds) for two timestamps to belong to the
/// same burst. One hour: tighter than a working day, looser than a single
/// automated batch.
pub const BURST_GAP_SECS: u64 = 3_600;

/// Minimum events for a cluster to be reported as a [`Burst`].
pub const BURST_MIN_EVENTS: usize = 3;

/// Attribute keys, across all modules, that carry subject-behavioural
/// datetimes worth folding onto the activity clock. Scan-time bookkeeping
/// (`recorded_at` on [`Evidence`]) is deliberately excluded — it reflects
/// when *we* looked, not when the *subject* acted, and would bias every
/// profile toward the analyst's own timezone.
///
/// [`Evidence`]: crate::core::entity::Evidence
pub const BEHAVIOURAL_KEYS: &[&str] = &[
    "created_at",
    "updated_at",
    "pushed_at",
    "last_seen",
    "first_seen",
    "last_active",
    "last_activity",
    "timestamp",
    "published",
    "published_at",
    "date",
    "breach_date",
    "post_time",
    "commit_date",
    "registered",
    "registration_date",
];

// ─── ActivityProfile ───────────────────────────────────────────────────────

/// Aggregated temporal behaviour distilled from an entity set.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivityProfile {
    /// Number of timestamps that contributed to the histograms.
    pub samples: usize,
    /// Earliest observed behavioural timestamp (Unix seconds).
    pub earliest: u64,
    /// Latest observed behavioural timestamp (Unix seconds).
    pub latest: u64,
    /// Hour-of-day histogram in **UTC**, index = hour (0..24).
    pub hour_histogram: [u32; 24],
    /// Day-of-week histogram, index 0 = Monday … 6 = Sunday (UTC).
    pub weekday_histogram: [u32; 7],
    /// Inferred subject UTC offset in hours, derived from the diurnal
    /// quiet-window. `None` when the signal is too flat to call.
    pub inferred_utc_offset: Option<i64>,
    /// Confidence in `inferred_utc_offset` ∈ [0, 1]: how pronounced the
    /// activity trough is, scaled by sample volume.
    pub offset_confidence: f64,
    /// Activity bursts (chronological), each a dense run of events.
    pub bursts: Vec<Burst>,
    /// Entity UIDs that contributed at least one timestamp, deduplicated and
    /// sorted for determinism.
    pub contributing_uids: Vec<String>,
}

/// A dense run of behavioural events — a sign of campaign activity, bulk
/// account creation, or a single high-tempo session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Burst {
    /// First event in the burst (Unix seconds).
    pub start: u64,
    /// Last event in the burst (Unix seconds).
    pub end: u64,
    /// Number of events in the burst.
    pub count: usize,
}

impl Burst {
    /// Wall-clock span of the burst in seconds.
    #[inline]
    pub fn span_secs(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

impl ActivityProfile {
    /// Local-time equivalent of the UTC hour histogram, rotated by the
    /// inferred offset. Returns the UTC histogram unchanged when no offset
    /// was inferred.
    pub fn local_hour_histogram(&self) -> [u32; 24] {
        match self.inferred_utc_offset {
            Some(off) => rotate_hours(&self.hour_histogram, off),
            None => self.hour_histogram,
        }
    }

    /// Peak activity hour in UTC (the modal hour).
    pub fn peak_hour_utc(&self) -> u8 {
        argmax(&self.hour_histogram) as u8
    }

    /// Human label for the inferred offset, e.g. `"UTC+09"` / `"UTC-05"`.
    pub fn offset_label(&self) -> Option<String> {
        self.inferred_utc_offset.map(|o| {
            if o >= 0 {
                format!("UTC+{o:02}")
            } else {
                format!("UTC-{:02}", -o)
            }
        })
    }
}

// ─── Engine ──────────────────────────────────────────────────────────────────

/// Build an [`ActivityProfile`] from an entity set, or `None` if fewer than
/// [`MIN_SAMPLES`] behavioural timestamps could be extracted.
pub fn analyze(entities: &[Entity]) -> Option<ActivityProfile> {
    let mut stamps: Vec<u64> = Vec::new();
    let mut uids: Vec<String> = Vec::new();

    for e in entities {
        let mut contributed = false;
        for ev in &e.evidence {
            for (key, raw) in &ev.attributes {
                if !is_behavioural_key(key) {
                    continue;
                }
                if let Some(ts) = parse_timestamp(raw) {
                    stamps.push(ts);
                    contributed = true;
                }
            }
        }
        if contributed {
            uids.push(e.uid.clone());
        }
    }

    if stamps.len() < MIN_SAMPLES {
        return None;
    }

    stamps.sort_unstable();
    uids.sort_unstable();
    uids.dedup();

    let earliest = *stamps.first().unwrap();
    let latest = *stamps.last().unwrap();

    let mut hour_histogram = [0u32; 24];
    let mut weekday_histogram = [0u32; 7];
    for &ts in &stamps {
        hour_histogram[hour_of_day(ts) as usize] += 1;
        weekday_histogram[weekday_mon0(ts) as usize] += 1;
    }

    let (inferred_utc_offset, offset_confidence) = infer_offset(&hour_histogram, stamps.len());
    let bursts = detect_bursts(&stamps);

    Some(ActivityProfile {
        samples: stamps.len(),
        earliest,
        latest,
        hour_histogram,
        weekday_histogram,
        inferred_utc_offset,
        offset_confidence,
        bursts,
        contributing_uids: uids,
    })
}

fn is_behavioural_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    BEHAVIOURAL_KEYS.iter().any(|b| k == *b)
}

// ─── Timezone inference ────────────────────────────────────────────────────

/// Infer a UTC offset from the diurnal quiet-window.
///
/// Humans sleep; their online footprint troughs in the small hours. We find
/// the 3-hour UTC window with the least activity, take its centre as local
/// ~03:00, and solve for the offset. Confidence reflects how deep the trough
/// is relative to the mean, damped by sample count so a handful of points
/// can't masquerade as a strong signal.
fn infer_offset(hist: &[u32; 24], samples: usize) -> (Option<i64>, f64) {
    let total: u32 = hist.iter().sum();
    if total == 0 {
        return (None, 0.0);
    }

    // Circular 3-hour window sums; pick the minimum (deepest trough).
    let mut min_sum = u32::MAX;
    let mut min_centre = 0i64;
    for centre in 0..24i64 {
        let s = hist[((centre - 1).rem_euclid(24)) as usize]
            + hist[centre as usize]
            + hist[((centre + 1).rem_euclid(24)) as usize];
        if s < min_sum {
            min_sum = s;
            min_centre = centre;
        }
    }

    // offset solves: local QUIET_CENTRE_LOCAL_HOUR == (min_centre + offset) mod 24
    let mut offset = (QUIET_CENTRE_LOCAL_HOUR - min_centre).rem_euclid(24);
    if offset > 12 {
        offset -= 24; // fold to [-11, 12]
    }

    // Trough depth: how far below the per-window mean the quiet window sits.
    let mean_window = total as f64 * 3.0 / 24.0;
    let depth = if mean_window > 0.0 {
        ((mean_window - min_sum as f64) / mean_window).clamp(0.0, 1.0)
    } else {
        0.0
    };
    // Volume damping: saturates around ~40 samples.
    let volume = (samples as f64 / 40.0).clamp(0.0, 1.0);
    let confidence = (depth * volume).clamp(0.0, 1.0);

    (Some(offset), confidence)
}

// ─── Burst detection ───────────────────────────────────────────────────────

/// Greedily cluster a **sorted** timestamp slice into bursts: runs where each
/// successive event is within [`BURST_GAP_SECS`] of the previous.
fn detect_bursts(sorted: &[u64]) -> Vec<Burst> {
    let mut bursts = Vec::new();
    if sorted.is_empty() {
        return bursts;
    }
    let mut start = sorted[0];
    let mut prev = sorted[0];
    let mut count = 1usize;

    for &ts in &sorted[1..] {
        if ts.saturating_sub(prev) <= BURST_GAP_SECS {
            count += 1;
        } else {
            if count >= BURST_MIN_EVENTS {
                bursts.push(Burst {
                    start,
                    end: prev,
                    count,
                });
            }
            start = ts;
            count = 1;
        }
        prev = ts;
    }
    if count >= BURST_MIN_EVENTS {
        bursts.push(Burst {
            start,
            end: prev,
            count,
        });
    }
    bursts
}

// ─── Civil-time arithmetic (pure, UTC) ───────────────────────────────────────

#[inline]
fn hour_of_day(ts: u64) -> u8 {
    ((ts % 86_400) / 3_600) as u8
}

/// Weekday with Monday = 0. The Unix epoch (1970-01-01) was a Thursday, so
/// `days + 3` shifts Thursday→3 with Monday at 0.
#[inline]
fn weekday_mon0(ts: u64) -> u8 {
    let days = ts / 86_400;
    (((days % 7) + 3) % 7) as u8
}

/// Rotate a 24-bucket hour histogram by `offset` hours (positive = eastward),
/// mapping UTC hours to local hours.
fn rotate_hours(hist: &[u32; 24], offset: i64) -> [u32; 24] {
    let mut out = [0u32; 24];
    for (h, &v) in hist.iter().enumerate() {
        let local = (h as i64 + offset).rem_euclid(24) as usize;
        out[local] = v;
    }
    out
}

fn argmax(hist: &[u32; 24]) -> usize {
    let mut idx = 0;
    let mut best = hist[0];
    for (i, &v) in hist.iter().enumerate() {
        if v > best {
            best = v;
            idx = i;
        }
    }
    idx
}

// ─── Timestamp parsing ───────────────────────────────────────────────────────

/// Parse a heterogeneous timestamp string into Unix seconds (UTC).
///
/// Accepts:
/// - Unix seconds (10 digits) and milliseconds (13 digits)
/// - ISO-8601 / RFC-3339: `2023-04-15T13:45:30Z`, `2023-04-15T13:45:30+00:00`,
///   `2023-04-15 13:45:30`, and date-only `2023-04-15` (assumed 00:00:00Z)
///
/// Returns `None` for anything it can't confidently interpret. Timezone
/// suffixes other than `Z` are parsed for their offset and normalised to UTC.
pub fn parse_timestamp(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Pure-digit epoch forms.
    if s.bytes().all(|b| b.is_ascii_digit()) {
        match s.len() {
            10 => return s.parse::<u64>().ok(),
            13 => return s.parse::<u64>().ok().map(|ms| ms / 1000),
            _ => return None,
        }
    }

    // ISO-8601 / RFC-3339.
    parse_iso8601(s)
}

fn parse_iso8601(s: &str) -> Option<u64> {
    // Split date and the optional time component on 'T' or ' '.
    let (date_part, rest) = match s.find(['T', ' ']) {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };

    let d: Vec<&str> = date_part.split('-').collect();
    if d.len() != 3 {
        return None;
    }
    let year: i64 = d[0].parse().ok()?;
    let month: i64 = d[1].parse().ok()?;
    let day: i64 = d[2].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let mut hour = 0i64;
    let mut min = 0i64;
    let mut sec = 0i64;
    let mut tz_offset_secs = 0i64;

    if !rest.is_empty() {
        // Strip a trailing zone designator and capture its offset.
        let (time_str, tz) = split_zone(rest);
        tz_offset_secs = tz;
        let t: Vec<&str> = time_str.split(':').collect();
        if t.is_empty() {
            return None;
        }
        hour = t[0].parse().ok()?;
        if t.len() > 1 {
            min = t.get(1).and_then(|v| v.parse().ok())?;
        }
        if t.len() > 2 {
            // Seconds may carry fractional digits — keep the integer part.
            let sec_field = t[2].split(['.', ',']).next().unwrap_or("0");
            sec = sec_field.parse().ok()?;
        }
        if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=60).contains(&sec) {
            return None;
        }
    }

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + min * 60 + sec - tz_offset_secs;
    if secs < 0 { None } else { Some(secs as u64) }
}

/// Strip a trailing timezone designator from a time string, returning the
/// bare `HH:MM[:SS]` and the zone's offset from UTC in seconds.
fn split_zone(time: &str) -> (&str, i64) {
    if let Some(stripped) = time.strip_suffix('Z') {
        return (stripped, 0);
    }
    // Look for a +HH:MM / -HH:MM / +HHMM suffix after the time digits.
    // Search from a position past the hour field to avoid eating a leading
    // sign that never occurs in well-formed input.
    for (i, c) in time.char_indices() {
        if (c == '+' || c == '-') && i > 0 {
            let sign = if c == '-' { -1 } else { 1 };
            let off = &time[i + 1..];
            let parts: Vec<&str> = off.split(':').collect();
            let oh: i64 = parts
                .first()
                .and_then(|v| {
                    if v.len() >= 2 {
                        v[..2].parse().ok()
                    } else {
                        v.parse().ok()
                    }
                })
                .unwrap_or(0);
            let om: i64 = if parts.len() > 1 {
                parts[1].parse().unwrap_or(0)
            } else if off.len() == 4 {
                off[2..4].parse().unwrap_or(0)
            } else {
                0
            };
            return (&time[..i], sign * (oh * 3_600 + om * 60));
        }
    }
    (time, 0)
}

/// Days since the Unix epoch for a civil (proleptic Gregorian) date.
/// Howard Hinnant's `days_from_civil` — branch-free, exact, no leap tables.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn entity_with(stamps: &[(&str, &str)]) -> Entity {
        let mut e = Entity::new(EntityKind::Username, "subject", 0.9, "scan-t");
        let mut ev = Evidence::new("test", "temporal");
        for (k, v) in stamps {
            ev = ev.with_attr(*k, *v);
        }
        e.add_evidence(ev);
        e
    }

    // ── Civil-time arithmetic ───────────────────────────────────────────

    #[test]
    fn epoch_is_day_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn known_civil_dates() {
        // 2000-01-01 is 10957 days after the epoch.
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        // 2023-04-15
        assert_eq!(days_from_civil(2023, 4, 15) * 86_400, 1_681_516_800);
    }

    #[test]
    fn weekday_epoch_is_thursday() {
        // 1970-01-01 Thursday → Monday=0 index 3.
        assert_eq!(weekday_mon0(0), 3);
        // 2023-04-15 was a Saturday → index 5.
        assert_eq!(weekday_mon0(1_681_516_800), 5);
    }

    #[test]
    fn hour_of_day_extracts_utc_hour() {
        // 1_681_516_800 = 2023-04-15T00:00:00Z
        assert_eq!(hour_of_day(1_681_516_800), 0);
        assert_eq!(hour_of_day(1_681_516_800 + 13 * 3600 + 45 * 60), 13);
    }

    // ── parse_timestamp ─────────────────────────────────────────────────

    #[test]
    fn parses_unix_seconds() {
        assert_eq!(parse_timestamp("1681516800"), Some(1_681_516_800));
    }

    #[test]
    fn parses_unix_millis() {
        assert_eq!(parse_timestamp("1681516800000"), Some(1_681_516_800));
    }

    #[test]
    fn parses_iso_utc_z() {
        assert_eq!(parse_timestamp("2023-04-15T00:00:00Z"), Some(1_681_516_800));
    }

    #[test]
    fn parses_iso_space_separator() {
        assert_eq!(
            parse_timestamp("2023-04-15 13:45:30"),
            Some(1_681_516_800 + 13 * 3600 + 45 * 60 + 30)
        );
    }

    #[test]
    fn parses_date_only() {
        assert_eq!(parse_timestamp("2023-04-15"), Some(1_681_516_800));
    }

    #[test]
    fn parses_positive_tz_offset() {
        // 09:00 at +09:00 is 00:00Z.
        assert_eq!(
            parse_timestamp("2023-04-15T09:00:00+09:00"),
            Some(1_681_516_800)
        );
    }

    #[test]
    fn parses_negative_tz_offset() {
        // 19:00 on 2023-04-14 at -05:00 is 00:00Z 2023-04-15.
        assert_eq!(
            parse_timestamp("2023-04-14T19:00:00-05:00"),
            Some(1_681_516_800)
        );
    }

    #[test]
    fn parses_fractional_seconds() {
        assert_eq!(
            parse_timestamp("2023-04-15T00:00:00.123Z"),
            Some(1_681_516_800)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_timestamp("not a date"), None);
        assert_eq!(parse_timestamp(""), None);
        assert_eq!(parse_timestamp("2023-13-99"), None);
        assert_eq!(parse_timestamp("12345"), None); // wrong-width epoch
    }

    // ── analyze ─────────────────────────────────────────────────────────

    #[test]
    fn returns_none_below_min_samples() {
        let e = entity_with(&[("created_at", "2023-04-15T10:00:00Z")]);
        assert!(analyze(&[e]).is_none());
    }

    #[test]
    fn ignores_non_behavioural_keys() {
        let e = entity_with(&[
            ("not_a_time_key", "2023-04-15T10:00:00Z"),
            ("random", "2023-04-15T11:00:00Z"),
        ]);
        assert!(analyze(&[e]).is_none());
    }

    #[test]
    fn builds_profile_from_multiple_stamps() {
        // Six events all near 18:00 UTC.
        let base = "2023-04-15T18:";
        let e = entity_with(&[
            ("created_at", "2023-04-10T18:05:00Z"),
            ("updated_at", "2023-04-11T18:10:00Z"),
            ("pushed_at", "2023-04-12T18:15:00Z"),
            ("last_seen", "2023-04-13T18:20:00Z"),
            ("last_active", "2023-04-14T18:25:00Z"),
            ("post_time", &format!("{base}30:00Z")),
        ]);
        let p = analyze(&[e]).expect("profile");
        assert_eq!(p.samples, 6);
        assert_eq!(p.peak_hour_utc(), 18);
        assert_eq!(p.hour_histogram[18], 6);
        assert!(p.inferred_utc_offset.is_some());
        assert_eq!(p.contributing_uids.len(), 1);
    }

    #[test]
    fn infers_offset_from_unique_quiet_window() {
        // Baseline activity everywhere, with a single clear trough centred on
        // 06:00 UTC (hours 5,6,7 dead). Quiet centre 06:00 UTC ⇒ local 03:00
        // ⇒ offset = (3 - 6).rem_euclid(24) = 21 → folds to -3 (i.e. the
        // Americas band).
        let mut hist = [5u32; 24];
        hist[5] = 0;
        hist[6] = 0;
        hist[7] = 0;
        let (off, conf) = infer_offset(&hist, 30);
        assert_eq!(off, Some(-3));
        assert!(conf > 0.0);
    }

    #[test]
    fn flat_distribution_yields_low_confidence() {
        let hist = [5u32; 24];
        let (_, conf) = infer_offset(&hist, 120);
        assert!(
            conf < 0.05,
            "flat signal should be near-zero conf, got {conf}"
        );
    }

    #[test]
    fn offset_label_formats() {
        let mut hist = [1u32; 24];
        hist[18] = 50;
        let p = ActivityProfile {
            samples: 50,
            earliest: 0,
            latest: 0,
            hour_histogram: hist,
            weekday_histogram: [0; 7],
            inferred_utc_offset: Some(9),
            offset_confidence: 0.9,
            bursts: vec![],
            contributing_uids: vec![],
        };
        assert_eq!(p.offset_label(), Some("UTC+09".to_string()));

        let p2 = ActivityProfile {
            inferred_utc_offset: Some(-5),
            ..p.clone()
        };
        assert_eq!(p2.offset_label(), Some("UTC-05".to_string()));
    }

    // ── burst detection ─────────────────────────────────────────────────

    #[test]
    fn detects_single_burst() {
        let stamps = vec![1000, 1500, 2000, 2400]; // all within 1h gaps
        let bursts = detect_bursts(&stamps);
        assert_eq!(bursts.len(), 1);
        assert_eq!(bursts[0].count, 4);
        assert_eq!(bursts[0].start, 1000);
        assert_eq!(bursts[0].end, 2400);
    }

    #[test]
    fn separates_bursts_across_large_gap() {
        let mut stamps = vec![0, 600, 1200]; // burst A
        stamps.extend([100_000, 100_600, 101_200]); // burst B, far away
        let bursts = detect_bursts(&stamps);
        assert_eq!(bursts.len(), 2);
        assert_eq!(bursts[0].count, 3);
        assert_eq!(bursts[1].count, 3);
    }

    #[test]
    fn ignores_sparse_events() {
        let stamps = vec![0, 100_000, 200_000]; // each isolated
        assert!(detect_bursts(&stamps).is_empty());
    }

    #[test]
    fn burst_span_secs() {
        let b = Burst {
            start: 100,
            end: 700,
            count: 3,
        };
        assert_eq!(b.span_secs(), 600);
    }

    // ── local histogram rotation ────────────────────────────────────────

    #[test]
    fn local_histogram_rotates_by_offset() {
        let mut hist = [0u32; 24];
        hist[0] = 7; // 00:00 UTC
        let p = ActivityProfile {
            samples: 7,
            earliest: 0,
            latest: 0,
            hour_histogram: hist,
            weekday_histogram: [0; 7],
            inferred_utc_offset: Some(9),
            offset_confidence: 0.5,
            bursts: vec![],
            contributing_uids: vec![],
        };
        let local = p.local_hour_histogram();
        assert_eq!(local[9], 7); // 00:00 UTC → 09:00 local at +9
    }

    #[test]
    fn local_histogram_identity_without_offset() {
        let mut hist = [0u32; 24];
        hist[3] = 4;
        let p = ActivityProfile {
            samples: 4,
            earliest: 0,
            latest: 0,
            hour_histogram: hist,
            weekday_histogram: [0; 7],
            inferred_utc_offset: None,
            offset_confidence: 0.0,
            bursts: vec![],
            contributing_uids: vec![],
        };
        assert_eq!(p.local_hour_histogram(), hist);
    }
}
