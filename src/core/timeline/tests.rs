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
