use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn email(v: &str, c: f64) -> Entity {
        Entity::new(EntityKind::Email, v, c, "s")
    }

    #[test]
    fn classifies_added_removed_and_common() {
        let baseline = vec![email("keep@x.com", 0.6), email("gone@x.com", 0.6)];
        let later = vec![email("keep@x.com", 0.6), email("new@x.com", 0.6)];
        let d = diff_entities(&baseline, &later);
        assert_eq!(
            d.added.iter().map(|e| e.value.as_str()).collect::<Vec<_>>(),
            ["new@x.com"]
        );
        assert_eq!(
            d.removed
                .iter()
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>(),
            ["gone@x.com"]
        );
        assert_eq!(d.common, 1);
        assert!(d.confidence_shifts.is_empty());
    }

    #[test]
    fn detects_confidence_shift_on_common_entity() {
        // Same uid (same kind+value), C_eff 0.40 → 0.90 (a candidate confirmed).
        let baseline = vec![email("a@x.com", 0.40)];
        let later = vec![email("a@x.com", 0.90)];
        let d = diff_entities(&baseline, &later);
        assert!(d.added.is_empty() && d.removed.is_empty());
        assert_eq!(d.common, 1);
        assert_eq!(d.confidence_shifts.len(), 1);
        let s = &d.confidence_shifts[0];
        assert!((s.before - 0.40).abs() < 1e-9, "before {s:?}");
        assert!((s.after - 0.90).abs() < 1e-9, "after {s:?}");
    }

    #[test]
    fn sub_eps_jitter_is_not_a_shift() {
        let d = diff_entities(&[email("a@x.com", 0.50)], &[email("a@x.com", 0.52)]);
        assert!(
            d.confidence_shifts.is_empty(),
            "0.02 < SHIFT_EPS must not report"
        );
        assert_eq!(d.common, 1);
    }

    #[test]
    fn identical_scans_diff_empty() {
        let e = vec![Entity::new(EntityKind::Domain, "x.com", 0.7, "s")];
        let d = diff_entities(&e, &e);
        assert!(d.is_empty());
        assert_eq!(d.common, 1);
        assert!(d.summary().starts_with("0 added, 0 removed, 1 common"));
    }

    #[test]
    fn output_is_uid_sorted_deterministic() {
        let later = vec![email("z@x.com", 0.6), email("a@x.com", 0.6)];
        let d = diff_entities(&[], &later);
        // uid-sorted, not insertion-order — deterministic across runs.
        let uids: Vec<&str> = d.added.iter().map(|e| e.uid.as_str()).collect();
        let mut sorted = uids.clone();
        sorted.sort_unstable();
        assert_eq!(uids, sorted);
        assert_eq!(d.added.len(), 2);
    }
