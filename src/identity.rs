//! People-centric identity on operator-supplied records.
//! A shared display name is not a link. Email and handle are.

use serde::{Deserialize, Serialize};

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
    raw.split_whitespace()
        .map(|w| w.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

#[must_use]
pub fn canonical_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return None;
    }
    if !local.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')) {
        return None;
    }
    Some(format!("{local}@{domain}"))
}

#[must_use]
pub fn canonical_handle(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 40 {
        return None;
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(trimmed)
}

/// Union by shared canonical email or handle. Names never merge records.
#[must_use]
pub fn resolve(records: &[PersonRecord]) -> Vec<Cluster> {
    let n = records.len();
    let mut parent: Vec<usize> = (0..n).collect();
    let mut links = Vec::new();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    fn unite(parent: &mut [usize], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent[rb] = ra;
        }
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if shared_email(&records[i], &records[j]) {
                unite(&mut parent, i, j);
                links.push(Link {
                    left: records[i].id.clone(),
                    right: records[j].id.clone(),
                    reason: "shared_email".to_owned(),
                });
            } else if shared_handle(&records[i], &records[j]) {
                unite(&mut parent, i, j);
                links.push(Link {
                    left: records[i].id.clone(),
                    right: records[j].id.clone(),
                    reason: "shared_handle".to_owned(),
                });
            }
        }
    }
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        buckets[find(&mut parent, i)].push(i);
    }
    buckets
        .into_iter()
        .filter(|b| !b.is_empty())
        .map(|idxs| {
            let members: Vec<String> = idxs.iter().map(|i| records[*i].id.clone()).collect();
            let cluster_links = links
                .iter()
                .filter(|l| members.contains(&l.left) && members.contains(&l.right))
                .cloned()
                .collect();
            Cluster {
                members,
                links: cluster_links,
            }
        })
        .collect()
}

fn shared_email(a: &PersonRecord, b: &PersonRecord) -> bool {
    let left: Vec<String> = a.emails.iter().filter_map(|e| canonical_email(e)).collect();
    b.emails.iter().filter_map(|e| canonical_email(e)).any(|e| left.contains(&e))
}

fn shared_handle(a: &PersonRecord, b: &PersonRecord) -> bool {
    let left: Vec<String> = a.handles.iter().filter_map(|h| canonical_handle(h)).collect();
    b.handles.iter().filter_map(|h| canonical_handle(h)).any(|h| left.contains(&h))
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
}
