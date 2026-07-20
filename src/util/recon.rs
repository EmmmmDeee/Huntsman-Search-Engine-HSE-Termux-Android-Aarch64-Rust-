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

/// Sort discovered entities confidence-descending with a deterministic
/// `uid`-ascending tie-break — the reproducible emission order every host-recon
/// collector uses (Determinism Requirement: a `HashMap`/`HashSet`-seeded build
/// order must not leak through). No truncation; ordering only.
pub fn sort_by_confidence_desc(entities: &mut [Entity]) {
    entities.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.uid.cmp(&b.uid))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    #[test]
    fn host_key_normalises_a_domain() {
        assert_eq!(host_key(TargetKind::Domain, "Example.COM"), Some("example.com".into()));
        assert_eq!(host_key(TargetKind::Domain, "example.com."), Some("example.com".into()));
        assert_eq!(host_key(TargetKind::Domain, "  sub.example.com  "), Some("sub.example.com".into()));
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
}
