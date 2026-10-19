//! People-centric identity on operator-supplied records.
//! A shared display name is not a link. Email and handle are.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_email, canonical_handle};

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

/// Union by shared canonical email or handle. Names never merge records.
/// A deterministic inverted index avoids pairwise comparisons between records
/// without shared keys. All directly matching pairs are still emitted, in the
/// original record-pair order, including duplicate public record identifiers.
/// Canonical emails take precedence over handles as the recorded link reason.
#[must_use]
pub fn resolve(records: &[PersonRecord]) -> Vec<Cluster> {
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }

    fn collect_pairs(
        records: &[PersonRecord],
        select: fn(&PersonRecord) -> &[String],
        canonicalize: fn(&str) -> Option<String>,
        reason: &'static str,
        pairs: &mut BTreeMap<(usize, usize), &'static str>,
    ) {
        let mut index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (position, record) in records.iter().enumerate() {
            // Repeated raw values (including different spellings that canonize
            // to one key) must not create duplicate links.
            let keys = select(record)
                .iter()
                .filter_map(|raw| canonicalize(raw))
                .collect::<BTreeSet<_>>();
            for key in keys {
                index.entry(key).or_default().push(position);
            }
        }
        for members in index.values() {
            for (position, &left) in members.iter().enumerate() {
                for &right in &members[position + 1..] {
                    pairs.entry((left, right)).or_insert(reason);
                }
            }
        }
    }

    let count = records.len();
    // Email pairs are inserted first. A handle overlap cannot overwrite the
    // stronger email match, even if the handle appears first in the input.
    let mut pairs = BTreeMap::new();
    collect_pairs(
        records,
        |record| &record.emails,
        canonical_email,
        "shared_email",
        &mut pairs,
    );
    collect_pairs(
        records,
        |record| &record.handles,
        canonical_handle,
        "shared_handle",
        &mut pairs,
    );

    let mut parent: Vec<usize> = (0..count).collect();
    for &(left, right) in pairs.keys() {
        let (a, b) = (find(&mut parent, left), find(&mut parent, right));
        if a != b {
            parent[b] = a;
        }
    }

    let mut buckets = vec![Vec::new(); count];
    for position in 0..count {
        let root = find(&mut parent, position);
        buckets[root].push(position);
    }
    let mut cluster_links = vec![Vec::new(); count];
    for ((left, right), reason) in pairs {
        let root = find(&mut parent, left);
        cluster_links[root].push(Link {
            left: records[left].id.clone(),
            right: records[right].id.clone(),
            reason: reason.to_owned(),
        });
    }
    buckets
        .into_iter()
        .zip(cluster_links)
        .filter(|(indices, _)| !indices.is_empty())
        .map(|(indices, links)| Cluster {
            members: indices
                .iter()
                .map(|&position| records[position].id.clone())
                .collect(),
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
    fn overlapping_email_and_handle_emits_one_email_link() {
        let records = vec![
            PersonRecord {
                id: "a".into(),
                name: "same display name".into(),
                emails: vec!["Ada@Example.com".into(), "ada@example.com".into()],
                handles: vec!["@Ada".into(), "ada".into()],
            },
            PersonRecord {
                id: "b".into(),
                name: "same display name".into(),
                emails: vec!["ada@example.com".into()],
                handles: vec!["ada".into()],
            },
        ];
        let clusters = resolve(&records);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].links.len(), 1);
        assert_eq!(clusters[0].links[0].reason, "shared_email");
    }

    #[test]
    fn indexed_resolution_matches_pairwise_oracle_on_mixed_records() {
        fn oracle(records: &[PersonRecord]) -> Vec<Cluster> {
            fn find(parent: &mut [usize], mut position: usize) -> usize {
                while parent[position] != position {
                    parent[position] = parent[parent[position]];
                    position = parent[position];
                }
                position
            }

            let emails: Vec<BTreeSet<String>> = records
                .iter()
                .map(|record| {
                    record
                        .emails
                        .iter()
                        .filter_map(|raw| canonical_email(raw))
                        .collect()
                })
                .collect();
            let handles: Vec<BTreeSet<String>> = records
                .iter()
                .map(|record| {
                    record
                        .handles
                        .iter()
                        .filter_map(|raw| canonical_handle(raw))
                        .collect()
                })
                .collect();
            let count = records.len();
            let mut parent: Vec<usize> = (0..count).collect();
            let mut links = Vec::new();
            for left in 0..count {
                for right in left + 1..count {
                    let reason = if !emails[left].is_disjoint(&emails[right]) {
                        "shared_email"
                    } else if !handles[left].is_disjoint(&handles[right]) {
                        "shared_handle"
                    } else {
                        continue;
                    };
                    let (a, b) = (find(&mut parent, left), find(&mut parent, right));
                    if a != b {
                        parent[b] = a;
                    }
                    links.push((left, right, reason));
                }
            }
            let mut buckets = vec![Vec::new(); count];
            for position in 0..count {
                let root = find(&mut parent, position);
                buckets[root].push(position);
            }
            let mut cluster_links = vec![Vec::new(); count];
            for (left, right, reason) in links {
                let root = find(&mut parent, left);
                cluster_links[root].push(Link {
                    left: records[left].id.clone(),
                    right: records[right].id.clone(),
                    reason: reason.to_owned(),
                });
            }
            buckets
                .into_iter()
                .zip(cluster_links)
                .filter(|(positions, _)| !positions.is_empty())
                .map(|(positions, links)| Cluster {
                    members: positions
                        .iter()
                        .map(|&position| records[position].id.clone())
                        .collect(),
                    links,
                })
                .collect()
        }

        let records = (0..160)
            .map(|position| PersonRecord {
                id: format!("id-{}", position % 43),
                name: "repeated display name".to_owned(),
                emails: if position % 7 == 0 {
                    Vec::new()
                } else {
                    vec![
                        format!("Person{}@Example.com", position % 29),
                        format!("person{}@EXAMPLE.com", position % 29),
                    ]
                },
                handles: if position % 11 == 0 {
                    Vec::new()
                } else {
                    vec![
                        format!("@account{}", position % 37),
                        format!("ACCOUNT{}", position % 37),
                    ]
                },
            })
            .collect::<Vec<_>>();
        assert_eq!(resolve(&records), oracle(&records));
        assert!(resolve(&[]).is_empty());
    }

    #[test]
    fn thousands_of_disjoint_records_do_not_require_pairwise_comparison() {
        let records = (0..10_000)
            .map(|position| PersonRecord {
                id: format!("person-{position}"),
                name: "same name".to_owned(),
                emails: vec![format!("person-{position}@example.com")],
                handles: Vec::new(),
            })
            .collect::<Vec<_>>();
        let clusters = resolve(&records);
        assert_eq!(clusters.len(), records.len());
        assert!(
            clusters
                .iter()
                .all(|cluster| { cluster.members.len() == 1 && cluster.links.is_empty() })
        );
    }
}
