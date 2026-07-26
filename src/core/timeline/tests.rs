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
        let (ts, iso) = parse_date("1262304000").expect("should succeed");
        assert_eq!(ts, 1_262_304_000);
        assert_eq!(iso, "2010-01-01");
    }

    #[test]
    fn parses_epoch_millis() {
        let (ts, _) = parse_date("1262304000000").expect("should succeed");
        assert_eq!(ts, 1_262_304_000);
    }

    #[test]
    fn parses_iso_date_and_datetime() {
        assert_eq!(parse_date("2019-03-15").expect("should succeed").1, "2019-03-15");
        let (_, iso) = parse_date("2019-03-15T08:30:00Z").expect("should succeed");
        assert_eq!(iso, "2019-03-15T08:30:00Z");
        assert_eq!(parse_date("2019/03/15").expect("should succeed").1, "2019-03-15");
    }

    #[test]
    fn parses_bare_year() {
        assert_eq!(parse_date("1998").expect("should succeed").1, "1998-01-01");
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
            parse_date("2019-03-15T08").expect("should succeed").1,
            "2019-03-15T08:00:00Z"
        );
        assert_eq!(
            parse_date("2019-03-15T08:30").expect("should succeed").1,
            "2019-03-15T08:30:00Z"
        );
        // Seconds stay lenient so a timezone offset (split onto the seconds
        // token by ':') doesn't reject an otherwise-valid timestamp.
        let (_, iso) = parse_date("2019-03-15T08:30:00+05:00").expect("should succeed");
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
        let (ts, _) = parse_date("2021-06-15").expect("should succeed");
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
        let (ts, iso) = parse_date("1965-03-10").expect("should succeed");
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
    fn classify_maps_every_live_account_created_key_not_leaving_it_dead_code() {
        // `TimelineEventKind::AccountCreated` was defined, documented, and had
        // its own `as_str()` label, but no key in `classify` ever produced it —
        // dead code, and every real module attribute below was silently absent
        // from the timeline. Each key here is a genuine evidence attribute a
        // first-party module stamps today (verified by direct grep, not
        // speculative): `oathnet_pro`/`stackoverflow_user` (`account_created`),
        // `devto` (`joined_at`), `discord_snowflake`'s decoded snowflake
        // timestamp (`discord_created_date`/`discord_created_unix_ms`), and
        // `structured_id`'s decoded UUIDv1 timestamp (`uuid_created_date`).
        // `structured_id`'s three other timestamp-embedding ID decoders
        // (MongoDB ObjectID, ULID, KSUID) stamp the exact same evidence-
        // attribute shape via the same `emit_creation` helper as the UUIDv1
        // case right beside it, but were left out of the original fix.
        use TimelineEventKind::AccountCreated;
        for key in [
            "account_created",
            "joined_at",
            "discord_created_date",
            "discord_created_unix_ms",
            "uuid_created_date",
            "objectid_created_date",
            "ulid_created_date",
            "ksuid_created_date",
        ] {
            assert!(
                matches!(classify(key), Some(AccountCreated)),
                "{key:?} must classify as AccountCreated"
            );
        }
    }

    #[test]
    fn classify_recognises_wikidata_and_mastodon_date_keys() {
        // `wikidata::builder` stamps `birth_date`/`death_date` (distinct from
        // the canonical `date_of_birth` other modules normalise to) and
        // `mastodon_user` stamps `verified_at` on a verified profile field;
        // `ip_reputation` stamps `first_pulse_created` for an OTX pulse's
        // earliest report date. None matched before this fix.
        use TimelineEventKind::*;
        assert!(matches!(classify("birth_date"), Some(DateOfBirth)));
        assert!(matches!(classify("death_date"), Some(Generic)));
        assert!(matches!(classify("verified_at"), Some(Generic)));
        assert!(matches!(classify("first_pulse_created"), Some(FirstSeen)));
    }

    #[test]
    fn reconstruct_surfaces_an_account_created_event_end_to_end() {
        // classify() alone doesn't prove the pipeline: reconstruct must also
        // successfully parse_date the value and emit a real TimelineEvent.
        let e = entity_with_attrs(
            EntityKind::Username,
            "someuser",
            "stackoverflow_user",
            &[("account_created", "2015-06-12")],
        );
        let tl = reconstruct(&[e]);
        assert_eq!(tl.len(), 1);
        assert!(matches!(tl[0].kind, TimelineEventKind::AccountCreated));
        assert_eq!(tl[0].iso, "2015-06-12");
    }

    #[test]
    fn reconstruct_surfaces_a_structured_id_ulid_created_event_end_to_end() {
        // `structured_id::emit_creation` stamps `ulid_created_date` (and its
        // ObjectID/KSUID siblings) in exactly this `YYYY-MM-DD` shape — proves
        // the full pipeline, not just `classify` in isolation, for the three
        // decoders that were missed alongside `uuid_created_date`.
        let e = entity_with_attrs(
            EntityKind::Other("derived-id".into()),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "structured_id",
            &[("ulid_created_date", "2016-07-30")],
        );
        let tl = reconstruct(&[e]);
        assert_eq!(tl.len(), 1);
        assert!(matches!(tl[0].kind, TimelineEventKind::AccountCreated));
        assert_eq!(tl[0].iso, "2016-07-30");
    }

    #[test]
    fn classify_recognises_exif_shot_time_as_location_visited() {
        // `exif_geo` stamps `shot_time` (the EXIF `DateTimeOriginal`/`DateTime`
        // tag) on every entity a photo yields, including its extracted
        // `Coordinates` — the movement/timeline geo signal C5/C1(c) name as
        // remaining. Before this fix, `classify` had no arm for it at all, so
        // the key silently never reached `parse_date`.
        assert!(matches!(
            classify("shot_time"),
            Some(TimelineEventKind::LocationVisited)
        ));
    }

    #[test]
    fn parse_date_accepts_the_real_exif_datetime_format() {
        // The EXIF standard's own separator is `:`, not `-` — `exif_geo::parse::
        // read_str` returns the tag's ASCII value verbatim (e.g.
        // `"2019:03:15 08:30:00"`), so the timeline parser must speak that
        // format directly rather than requiring a pre-normalised one.
        let (ts, iso) = parse_date("2019:03:15 08:30:00").expect("EXIF datetime must parse");
        assert_eq!(iso, "2019-03-15T08:30:00Z");
        assert!(ts > 0);
        // The date-only EXIF form (no time component) is also valid.
        assert_eq!(parse_date("2019:03:15").expect("should succeed").1, "2019-03-15");
    }

    #[test]
    fn reconstruct_surfaces_a_location_visited_event_from_a_real_exif_shot_time() {
        // End-to-end: a `Coordinates` entity carrying `exif_geo`'s real
        // `shot_time` evidence attribute must produce a genuine
        // `LocationVisited` timeline event, not silently vanish. Regression for
        // the dead-key defect: pre-fix, `classify("shot_time")` returned `None`
        // so this reconstruct call yielded zero events.
        let e = entity_with_attrs(
            EntityKind::Coordinates,
            "40.712776,-74.005974",
            "exif_geo",
            &[("shot_time", "2021:06:15 14:22:05"), ("camera_make", "Apple")],
        );
        let tl = reconstruct(&[e]);
        assert_eq!(tl.len(), 1, "camera_make is not a recognised date key");
        assert_eq!(tl[0].kind, TimelineEventKind::LocationVisited);
        assert_eq!(tl[0].iso, "2021-06-15T14:22:05Z");
        assert_eq!(tl[0].entity_value, "40.712776,-74.005974");
        assert_eq!(tl[0].entity_kind, "coordinates");
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
        let t = online_tenure(&events).expect("should succeed");
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

    #[test]
    fn movement_path_none_with_fewer_than_two_fixes() {
        // Zero fixes.
        assert!(movement_path(&[]).is_none());
        // A single dated location isn't a path — it's a point. Fabricating a
        // "movement" out of one photo would misstate what was observed.
        let e = entity_with_attrs(
            EntityKind::Coordinates,
            "40.712776,-74.005974",
            "exif_geo",
            &[("shot_time", "2021-06-15")],
        );
        let events = reconstruct(&[e]);
        assert_eq!(events.len(), 1);
        assert!(movement_path(&events).is_none());
    }

    #[test]
    fn movement_path_walks_real_fixes_chronologically_with_real_distance() {
        // Two real, geotagged photos of the same subject/device: New York on
        // 2021-06-15, then Sydney (CBD, -33.8688,151.2093) a week later. The
        // real-world great-circle distance NYC↔Sydney is ~15,990 km.
        let sydney = entity_with_attrs(
            EntityKind::Coordinates,
            "-33.868800,151.209300",
            "exif_geo",
            &[("shot_time", "2021-06-22")],
        );
        let nyc = entity_with_attrs(
            EntityKind::Coordinates,
            "40.712776,-74.005974",
            "exif_geo",
            &[("shot_time", "2021-06-15")],
        );
        // Deliberately passed out of chronological order — `reconstruct`
        // itself is what guarantees oldest-first, `movement_path` must not
        // silently depend on caller-supplied ordering being lucky.
        let events = reconstruct(&[sydney, nyc]);
        assert_eq!(events[0].entity_value, "40.712776,-74.005974"); // oldest first
        let mv = movement_path(&events).expect("2 real fixes must yield a path");
        assert_eq!(mv.locations_visited, 2);
        assert_eq!(mv.legs.len(), 1);
        let leg = &mv.legs[0];
        assert_eq!(leg.from_coords, "40.712776,-74.005974");
        assert_eq!(leg.to_coords, "-33.868800,151.209300");
        // Real NYC↔Sydney great-circle distance is ~15,990 km — a wide
        // tolerance guards against float-precision nitpicks while still
        // pinning "this is really computing a distance", not a stub.
        assert!(
            (mv.total_km - 15_990.0).abs() < 200.0,
            "expected ~15,990 km, got {}",
            mv.total_km
        );
        assert!((leg.distance_km - mv.total_km).abs() < f64::EPSILON);
    }

    #[test]
    fn movement_path_sums_multiple_legs_and_skips_unparseable_fixes() {
        // Three real fixes plus one `LocationVisited`-classified value that
        // doesn't actually parse as a coordinate — defensive against a future
        // producer stamping `shot_time` onto a non-`Coordinates`-shaped value.
        // It must be skipped, not break the chain into two shorter paths.
        let a = entity_with_attrs(
            EntityKind::Coordinates,
            "-27.470125,153.021072", // Brisbane
            "exif_geo",
            &[("shot_time", "2020-01-01")],
        );
        let junk = entity_with_attrs(
            EntityKind::Coordinates,
            "not-a-coordinate",
            "exif_geo",
            &[("shot_time", "2020-06-01")],
        );
        let b = entity_with_attrs(
            EntityKind::Coordinates,
            "-33.868800,151.209300", // Sydney
            "exif_geo",
            &[("shot_time", "2021-01-01")],
        );
        let events = reconstruct(&[a, junk, b]);
        assert_eq!(events.len(), 3, "the unparseable fix still classifies");
        let mv = movement_path(&events).expect("2 parseable fixes must yield a path");
        assert_eq!(mv.locations_visited, 2, "the junk fix must not count");
        assert_eq!(mv.legs.len(), 1);
        // Real Brisbane↔Sydney great-circle distance is ~730 km.
        assert!(
            (mv.total_km - 730.0).abs() < 50.0,
            "expected ~730 km, got {}",
            mv.total_km
        );
    }
