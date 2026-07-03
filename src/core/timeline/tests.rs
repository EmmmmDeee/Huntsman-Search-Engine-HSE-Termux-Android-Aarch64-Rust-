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
    fn pre_1970_dates_are_negative_and_sort_before_epoch() {
        // Regression: a pre-1970 calendar date must yield a *negative* Unix
        // timestamp, not clamp to 0. Otherwise reconstruct()'s oldest-first
        // sort places, e.g., a 1965 date of birth *after* every 1970+ event.
        let (ts, iso) = parse_date("1965-03-10").unwrap();
        assert!(ts < 0, "pre-1970 date must be negative, got {ts}");
        assert_eq!(iso, "1965-03-10");
        // The display string round-trips through the signed inverse too.
        assert_eq!(from_unix(ts).1, "1965-03-10");

        let entities = vec![
            entity_with_attrs(
                EntityKind::Domain,
                "b.com",
                "rdap_domain",
                &[("registered", "2008-06-01")],
            ),
            entity_with_attrs(
                EntityKind::Person,
                "Haigen Bamford",
                "au_people",
                &[("date_of_birth", "1965-03-10")],
            ),
        ];
        let tl = reconstruct(&entities);
        assert_eq!(tl.len(), 2);
        // Oldest-first: the 1965 birth must precede the 2008 registration,
        // even though it was supplied second.
        assert_eq!(tl[0].kind, TimelineEventKind::DateOfBirth);
        assert!(tl[0].ts < 0);
        assert_eq!(tl[1].kind, TimelineEventKind::Registered);
        assert!(tl[1].ts > 0);
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

    // ── classify ──────────────────────────────────────────────────────────────

    #[test]
    fn classify_maps_attr_keys_to_event_kinds() {
        use TimelineEventKind::*;
        assert!(matches!(classify("breach_date"), Some(BreachExposure)));
        assert!(matches!(classify("data_breach"), Some(BreachExposure)));
        assert!(matches!(classify("created_at_unix"), Some(Registered)));
        assert!(matches!(classify("expire_secs"), Some(Expiry)));
        assert!(matches!(classify("date_of_birth"), Some(DateOfBirth)));
        assert!(matches!(classify("timestamp"), Some(Generic)));
    }

    #[test]
    fn classify_is_case_insensitive_and_none_for_unknown() {
        assert!(matches!(
            classify("BREACH_DATE"),
            Some(TimelineEventKind::BreachExposure)
        ));
        assert!(classify("favourite_colour").is_none());
        assert!(classify("").is_none());
    }

    /// PROBLEM_TREE C1 "(c) widen the timeline": 12 real module attribute keys
    /// a source-family audit found already carrying a parseable date under a
    /// spelling `classify` didn't recognise. Each mapping here matches the
    /// module it was found in (`wikidata`/`stackoverflow_user`/
    /// `discord_snowflake`/`structured_id`/`ip_registry`/`crtsh`/`leakix`/
    /// `wigle`/`psbdmp`/`hudsonrock`) — see the `classify` doc comment for the
    /// per-key rationale, including the two keys deliberately left out
    /// (HIBP's catalogue-metadata dates, not the subject's own chronology).
    #[test]
    fn classify_recognises_the_widened_source_family_keys() {
        use TimelineEventKind::*;
        for (key, expected) in [
            ("birth_date", DateOfBirth),
            ("account_created", Registered),
            ("discord_created_date", Registered),
            ("uuid_created_date", Registered),
            ("objectid_created_date", Registered),
            ("ulid_created_date", Registered),
            ("ksuid_created_date", Registered),
            ("allocated", Registered),
            ("not_before", Registered),
            ("not_after", Expiry),
            ("earliest", FirstSeen),
            ("earliest_paste", FirstSeen),
            ("most_recent", LastSeen),
            ("most_recent_observation", LastSeen),
            ("date_uploaded", LastSeen),
            ("date_compromised", BreachExposure),
        ] {
            assert_eq!(
                classify(key),
                Some(expected),
                "{key} should classify as {expected:?}"
            );
        }
        // Deliberately excluded: HIBP's own catalogue record-keeping dates,
        // not an event in the subject's chronology.
        assert!(classify("added_date").is_none());
        assert!(classify("modified_date").is_none());
    }

    #[test]
    fn reconstruct_includes_a_real_crtsh_certificate_validity_window() {
        // End-to-end proof (not just classify()): the exact evidence shape
        // `modules/crtsh` emits — this failed to appear in the timeline at
        // all before `not_before`/`not_after` were recognised.
        let cert = entity_with_attrs(
            EntityKind::Domain,
            "example.com",
            "crtsh",
            &[("not_before", "2024-01-01"), ("not_after", "2024-04-01")],
        );
        let events = reconstruct(&[cert]);
        assert_eq!(events.len(), 2, "both cert dates become timeline events");
        assert_eq!(events[0].kind, TimelineEventKind::Registered);
        assert_eq!(events[0].iso, "2024-01-01");
        assert_eq!(events[1].kind, TimelineEventKind::Expiry);
        assert_eq!(events[1].iso, "2024-04-01");
    }

    #[test]
    fn reconstruct_includes_a_real_hudsonrock_compromise_date() {
        // The exact evidence shape `modules/hudsonrock` emits for a stealer
        // log — the subject's own machine-compromise date, arguably the
        // highest-value single event this widening adds.
        let stealer_log = entity_with_attrs(
            EntityKind::Credential,
            "alice@example.com",
            "hudsonrock",
            &[("date_compromised", "2026-05-01T00:00:00Z")],
        );
        let events = reconstruct(&[stealer_log]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TimelineEventKind::BreachExposure);
        assert_eq!(events[0].iso, "2026-05-01");
    }

    // ── is_leap ───────────────────────────────────────────────────────────────

    #[test]
    fn is_leap_follows_the_gregorian_rule() {
        assert!(is_leap(2024)); // divisible by 4, not by 100
        assert!(!is_leap(1900)); // century not divisible by 400
        assert!(is_leap(2000)); // divisible by 400
        assert!(!is_leap(2023)); // ordinary year
    }

    // ── days_from_civil ───────────────────────────────────────────────────────

    #[test]
    fn days_from_civil_anchors_on_the_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }

    // ── civil_to_unix ─────────────────────────────────────────────────────────

    #[test]
    fn civil_to_unix_renders_date_only_at_midnight() {
        let (ts, iso) = civil_to_unix(1970, 1, 1, 0, 0, 0);
        assert_eq!(ts, 0);
        assert_eq!(iso, "1970-01-01");
    }

    #[test]
    fn civil_to_unix_renders_iso_z_when_time_present() {
        let (ts, iso) = civil_to_unix(1970, 1, 1, 1, 0, 0);
        assert_eq!(ts, 3600);
        assert_eq!(iso, "1970-01-01T01:00:00Z");
    }

    #[test]
    fn civil_to_unix_keeps_pre_epoch_dates_negative() {
        let (ts, iso) = civil_to_unix(1969, 12, 31, 0, 0, 0);
        assert_eq!(ts, -86400);
        assert_eq!(iso, "1969-12-31");
    }

    #[test]
    fn reconstruct_excludes_candidate_quarantined_entities() {
        // Live-scan regression: a name scan's footprint timeline showed only the
        // birth dates of quarantined breach co-occurrence STRANGERS, never the
        // subject. The confirmed subject's DOB is the footprint; a candidate
        // neighbour's must not appear as if it were the subject's life event.
        let subject = entity_with_attrs(
            EntityKind::Person,
            "Matthew Diegmann",
            "oathnet_pro",
            &[("date_of_birth", "1990-05-05")],
        );
        let mut stranger = entity_with_attrs(
            EntityKind::Person,
            "Raymond Perez",
            "oathnet_pro",
            &[("date_of_birth", "1993-01-03")],
        );
        stranger.demote_to_candidate();

        let events = reconstruct(&[subject, stranger]);
        assert_eq!(events.len(), 1, "only the confirmed subject's event survives");
        assert_eq!(events[0].entity_value, "Matthew Diegmann");
        assert_eq!(events[0].iso, "1990-05-05");
    }

    #[test]
    fn online_tenure_spans_the_breach_history() {
        // Two breach exposures 2008 → 2025 reconstruct a 17-year online footprint.
        let a = entity_with_attrs(
            EntityKind::Email,
            "a@x.com",
            "see_know",
            &[("breach_date", "2008-07-01")],
        );
        let b = entity_with_attrs(
            EntityKind::Email,
            "a@x.com",
            "oathnet_pro",
            &[("breach_date", "2025-12-15")],
        );
        let events = reconstruct(&[a, b]);
        let t = online_tenure(&events).expect("a spanning tenure");
        assert!(t.earliest_iso.starts_with("2008"));
        assert!(t.latest_iso.starts_with("2025"));
        assert_eq!(t.span_years, 17, "2008→2025 is a 17-year span");
        assert_eq!(t.breach_count, 2);
        assert_eq!(t.event_count, 2);
    }

    #[test]
    fn online_tenure_excludes_date_of_birth() {
        // A DOB must not stretch tenure back to the birth year; only presence dates it.
        let p = entity_with_attrs(
            EntityKind::Person,
            "Jo Citizen",
            "see_know",
            &[("date_of_birth", "1980-01-01"), ("breach_date", "2015-06-01")],
        );
        let events = reconstruct(&[p]);
        let t = online_tenure(&events).unwrap();
        assert!(
            t.earliest_iso.starts_with("2015"),
            "DOB 1980 excluded; earliest is the 2015 breach"
        );
        assert_eq!(t.span_years, 0, "one presence event → zero span");
        assert_eq!(t.breach_count, 1);
    }

    #[test]
    fn online_tenure_none_for_a_dob_only_footprint() {
        // A DOB alone is not online presence — no tenure rather than a multi-decade lie.
        let p = entity_with_attrs(
            EntityKind::Person,
            "Jo Citizen",
            "see_know",
            &[("date_of_birth", "1980-01-01")],
        );
        let events = reconstruct(&[p]);
        assert!(online_tenure(&events).is_none());
    }

    #[test]
    fn footprint_recency_classifies_by_age() {
        const YEAR: i64 = 31_556_952;
        let now: i64 = 100 * YEAR; // arbitrary "now"
        // Latest activity 0 / 2 / 5 / 10 years ago → Active / Recent / Aging / Dormant.
        assert_eq!(
            footprint_recency(now, now).status,
            FootprintStatus::Active
        );
        assert_eq!(
            footprint_recency(now - 2 * YEAR, now).status,
            FootprintStatus::Recent
        );
        assert_eq!(
            footprint_recency(now - 5 * YEAR, now).status,
            FootprintStatus::Aging
        );
        let dormant = footprint_recency(now - 10 * YEAR, now);
        assert_eq!(dormant.status, FootprintStatus::Dormant);
        assert_eq!(dormant.years_since_latest, 10);
    }

    #[test]
    fn footprint_recency_clamps_a_future_latest_to_active() {
        const YEAR: i64 = 31_556_952;
        let now: i64 = 50 * YEAR;
        let r = footprint_recency(now + 3 * YEAR, now); // latest after now
        assert_eq!(r.years_since_latest, 0);
        assert_eq!(r.status, FootprintStatus::Active);
    }
