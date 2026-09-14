//! Shared helpers for the free host-recon collectors — `crtsh`, `certspotter`,
//! `anubis`, and any future source that keys on a hostname and emits discovered
//! subdomains/hosts. Consolidating them here keeps the host-keying rule and the
//! deterministic emission order defined ONCE, so they can't drift between
//! collectors as new sources are added.

use crate::core::entity::Entity;
use crate::core::scan::TargetKind;

/// The apex host to query for a host-keyed recon source, or `None` for a kind we
/// can't key on. **Pure**: a `Domain` is normalised verbatim (trimmed, trailing
/// root-dot stripped, lowercased, and required to contain a dot so a bare label
/// like `localhost` is rejected); a `Url` is reduced to its host (also
/// lowercased). Every collector that searches by hostname shares this so the
/// normalisation is identical across sources.
#[must_use]
pub fn host_key(kind: TargetKind, value: &str) -> Option<String> {
    match kind {
        TargetKind::Domain => {
            let host = value.trim().trim_end_matches('.').to_lowercase();
            (!host.is_empty() && host.contains('.')).then_some(host)
        }
        TargetKind::Url => crate::util::url_util::host_from_url(value).map(|h| h.to_lowercase()),
        _ => None,
    }
}

/// Confidence-descending, `uid`-ascending total order — the comparator behind
/// [`sort_by_confidence_desc`], exposed separately for the handful of callers
/// that hold `&Entity` references rather than owned `Entity` values (so they
/// can't call the slice-of-owned-values version directly) but need the exact
/// same tie-break to stay in agreement with it.
///
/// This one comparator now backs every plain confidence-then-uid sort in the
/// tree (Pass 26 consolidation): `app::persist`, `core::engine`'s recall-cap
/// and found-key-flatten passes, and the dossier's finding order all used to
/// carry byte-for-byte independent copies of it — one of them with a doc
/// comment explicitly noting it "mirrors" another's "identical ranking", the
/// exact kind of acknowledged-but-never-closed duplication a future
/// tie-break change (or bug fix) could silently apply to only some of them.
#[must_use]
pub fn confidence_desc_then_uid(a: &Entity, b: &Entity) -> std::cmp::Ordering {
    b.confidence
        .partial_cmp(&a.confidence)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| a.uid.cmp(&b.uid))
}

/// Sort discovered entities confidence-descending with a deterministic
/// `uid`-ascending tie-break — the reproducible emission order every host-recon
/// collector uses (Determinism Requirement: a `HashMap`/`HashSet`-seeded build
/// order must not leak through). No truncation; ordering only.
pub fn sort_by_confidence_desc(entities: &mut [Entity]) {
    entities.sort_by(confidence_desc_then_uid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    #[test]
    fn host_key_normalises_a_domain() {
        assert_eq!(
            host_key(TargetKind::Domain, "Example.COM"),
            Some("example.com".into())
        );
        assert_eq!(
            host_key(TargetKind::Domain, "example.com."),
            Some("example.com".into())
        );
        assert_eq!(
            host_key(TargetKind::Domain, "  sub.example.com  "),
            Some("sub.example.com".into())
        );
    }

    #[test]
    fn host_key_reduces_a_url_to_its_host() {
        assert_eq!(
            host_key(TargetKind::Url, "https://SUB.example.com/path?q=1"),
            Some("sub.example.com".into())
        );
    }

    #[test]
    fn host_key_rejects_non_hosts() {
        assert_eq!(host_key(TargetKind::Domain, "localhost"), None);
        assert_eq!(host_key(TargetKind::Domain, "   "), None);
        assert_eq!(host_key(TargetKind::Email, "a@x.com"), None);
        assert_eq!(host_key(TargetKind::Username, "bob"), None);
    }

    #[test]
    fn sort_is_confidence_desc_then_uid_asc_and_deterministic() {
        let mk = |v: &str, c: f64| Entity::new(EntityKind::Domain, v, c, "scan1");
        let build = || {
            let mut v = vec![
                mk("b.example.com", 0.45),
                mk("a.example.com", 0.75),
                mk("c.example.com", 0.75),
            ];
            sort_by_confidence_desc(&mut v);
            v
        };
        let first = build();
        // 0.75s precede the 0.45; within the tie, uid-ascending is stable.
        let confs: Vec<f64> = first.iter().map(|e| e.confidence).collect();
        assert!(confs.windows(2).all(|w| w[0] >= w[1]), "{confs:?}");
        // Reproducible run-to-run.
        let second = build();
        let order = |v: &[Entity]| v.iter().map(|e| e.uid.clone()).collect::<Vec<_>>();
        assert_eq!(order(&first), order(&second));
    }

    /// A stronger check than mere run-to-run reproducibility: the tie-break
    /// must come from `uid` itself, not from an accident of `sort_by`'s
    /// stability preserving whatever order the caller happened to build the
    /// input in. Feeding the exact same two equal-confidence entities in
    /// forward and reversed order must produce the identical output order —
    /// the property `app::persist`'s `confidence_rank` (now deleted; this
    /// function replaced it, Pass 26) had its own copy of this exact test for.
    #[test]
    fn tie_break_is_uid_not_arrival_order() {
        let a = Entity::new(EntityKind::Email, "a-tie@example.com", 0.5, "s");
        let b = Entity::new(EntityKind::Email, "b-tie@example.com", 0.5, "s");
        let mut expected_uid_order = vec![a.uid.clone(), b.uid.clone()];
        expected_uid_order.sort();

        let mut forward = vec![a.clone(), b.clone()];
        sort_by_confidence_desc(&mut forward);
        let mut reversed = vec![b, a];
        sort_by_confidence_desc(&mut reversed);

        let uids = |v: &[Entity]| v.iter().map(|e| e.uid.clone()).collect::<Vec<_>>();
        assert_eq!(uids(&forward), expected_uid_order);
        assert_eq!(
            uids(&forward),
            uids(&reversed),
            "reversing the input must not change a confidence-tied output order"
        );
    }
}
