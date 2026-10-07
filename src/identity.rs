//! People-centric identity on operator-supplied records.
//! A shared display name is not a link. Email and handle are.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::canonical;

pub use crate::{domains, textnorm, validation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonRecord {
    pub id: String,
    pub name: String,
    pub emails: Vec<String>,
    pub handles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub left: String,
    pub right: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cluster {
    pub members: Vec<String>,
    pub links: Vec<Link>,
}

#[must_use]
pub fn canonical_name(raw: &str) -> String {
    canonical::canonical_name(raw)
}

#[must_use]
pub fn canonical_email(raw: &str) -> Option<String> {
    canonical::canonical_email(raw)
}

#[must_use]
pub fn canonical_domain(raw: &str) -> Option<String> {
    canonical::canonical_domain_host(raw)
}

#[must_use]
pub fn canonical_handle(raw: &str) -> Option<String> {
    canonical::canonical_handle(raw)
}

#[must_use]
pub fn canonical_phone(raw: &str) -> Option<String> {
    canonical::canonical_phone(raw)
}

/// Union by shared canonical email or handle. Names never merge records.
/// Canonical keys are computed once per record.
#[must_use]
pub fn resolve(records: &[PersonRecord]) -> Vec<Cluster> {
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    fn keys(raw: &[String], canon: fn(&str) -> Option<String>) -> HashSet<String> {
        raw.iter().filter_map(|v| canon(v)).collect()
    }
    let n = records.len();
    let emails: Vec<HashSet<String>> = records
        .iter()
        .map(|r| keys(&r.emails, canonical_email))
        .collect();
    let handles: Vec<HashSet<String>> = records
        .iter()
        .map(|r| keys(&r.handles, canonical_handle))
        .collect();
    let mut parent: Vec<usize> = (0..n).collect();
    let mut links = Vec::new();
    for i in 0..n {
        for j in (i + 1)..n {
            let reason = if !emails[i].is_disjoint(&emails[j]) {
                "shared_email"
            } else if !handles[i].is_disjoint(&handles[j]) {
                "shared_handle"
            } else {
                continue;
            };
            let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
            if ri != rj {
                parent[rj] = ri;
            }
            links.push((i, j, reason));
        }
    }
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        let root = find(&mut parent, i);
        buckets[root].push(i);
    }
    let mut cluster_links: Vec<Vec<Link>> = vec![Vec::new(); n];
    for (i, j, reason) in links {
        let root = find(&mut parent, i);
        cluster_links[root].push(Link {
            left: records[i].id.clone(),
            right: records[j].id.clone(),
            reason: reason.to_owned(),
        });
    }
    buckets
        .into_iter()
        .zip(cluster_links)
        .filter(|(b, _)| !b.is_empty())
        .map(|(idxs, links)| Cluster {
            members: idxs.iter().map(|i| records[*i].id.clone()).collect(),
            links,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_name_without_link_stays_split() {
        let records = vec![
            PersonRecord {
                id: "a".into(),
                name: "Jane Doe".into(),
                emails: vec!["a@example.com".into()],
                handles: vec![],
            },
            PersonRecord {
                id: "b".into(),
                name: "jane doe".into(),
                emails: vec!["b@example.com".into()],
                handles: vec![],
            },
        ];
        let clusters = resolve(&records);
        assert_eq!(clusters.len(), 2);
        assert!(clusters.iter().all(|c| c.links.is_empty()));
    }

    #[test]
    fn malformed_email_domain_is_not_a_link() {
        for bad in [
            "x@.",
            "x@a..b",
            "x@.com",
            "x@com.",
            "x@a b.com",
            "x@a_b.com",
        ] {
            assert_eq!(canonical_email(bad), None, "{bad}");
        }
        assert_eq!(
            canonical_email(" X@Mail-1.Example.COM "),
            Some("x@mail-1.example.com".into())
        );
        let records = vec![
            PersonRecord {
                id: "a".into(),
                name: "A".into(),
                emails: vec!["x@.".into()],
                handles: vec![],
            },
            PersonRecord {
                id: "b".into(),
                name: "B".into(),
                emails: vec!["X@.".into()],
                handles: vec![],
            },
        ];
        assert_eq!(resolve(&records).len(), 2);
    }

    #[test]
    fn duplicate_record_ids_keep_links_in_their_own_cluster() {
        // Old filter matched links by id string, so duplicate ids leaked links across clusters.
        let records = vec![
            PersonRecord {
                id: "x".into(),
                name: String::new(),
                emails: vec!["p@ex.com".into()],
                handles: vec![],
            },
            PersonRecord {
                id: "y".into(),
                name: String::new(),
                emails: vec!["p@ex.com".into()],
                handles: vec![],
            },
            PersonRecord {
                id: "x".into(),
                name: String::new(),
                emails: vec![],
                handles: vec!["q".into()],
            },
            PersonRecord {
                id: "y".into(),
                name: String::new(),
                emails: vec![],
                handles: vec!["q".into()],
            },
        ];
        let clusters = resolve(&records);
        assert_eq!(clusters.len(), 2);
        let reasons: Vec<Vec<&str>> = clusters
            .iter()
            .map(|c| c.links.iter().map(|l| l.reason.as_str()).collect())
            .collect();
        assert_eq!(reasons, [vec!["shared_email"], vec!["shared_handle"]]);
    }

    #[test]
    fn transitive_handle_then_email_is_one_cluster() {
        let records = vec![
            PersonRecord {
                id: "a".into(),
                name: String::new(),
                emails: vec![],
                handles: vec!["h".into(), "hh".into()],
            },
            PersonRecord {
                id: "b".into(),
                name: String::new(),
                emails: vec!["m@ex.com".into()],
                handles: vec!["@HH".into()],
            },
            PersonRecord {
                id: "c".into(),
                name: String::new(),
                emails: vec!["M@EX.com".into()],
                handles: vec![],
            },
        ];
        let clusters = resolve(&records);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members, ["a", "b", "c"]);
        let reasons: Vec<&str> = clusters[0]
            .links
            .iter()
            .map(|l| l.reason.as_str())
            .collect();
        assert_eq!(reasons, ["shared_handle", "shared_email"]);
    }

    #[test]
    fn shared_email_merges_case_and_at_handle() {
        let records = vec![
            PersonRecord {
                id: "a".into(),
                name: "Ada".into(),
                emails: vec!["Ada@Example.com".into()],
                handles: vec![],
            },
            PersonRecord {
                id: "b".into(),
                name: "Other".into(),
                emails: vec!["ada@example.com".into()],
                handles: vec!["@Ada".into()],
            },
        ];
        let clusters = resolve(&records);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].links[0].reason, "shared_email");
        assert_eq!(canonical_handle("@Ada"), Some("ada".into()));
    }

    #[test]
    fn canonical_domain_and_phone_merge_here() {
        assert_eq!(
            canonical_domain(" WWW.Example.COM. ").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            canonical_phone("0412 345 678").as_deref(),
            Some("+61412345678")
        );
        assert_eq!(
            canonical_phone("+1 555 123 4567").as_deref(),
            Some("+15551234567")
        );
    }
}
