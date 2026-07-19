//! Pure entity-building helpers for GitHub code search results.

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    scan::TargetKind,
};
use crate::util::str_util::nonempty;

use super::{CodeItem, CommitsResp, SRC};

/// Build entities from a single search result item. Pure.
pub(super) fn build_repo_entities(
    item: &CodeItem,
    seed: &str,
    seed_kind: TargetKind,
    scan_id: &str,
) -> Vec<Entity> {
    let Some(repo) = &item.repository else {
        return vec![];
    };
    let mut out = Vec::new();

    let full_name = repo.full_name.as_deref().unwrap_or("");
    let description = repo.description.as_deref().unwrap_or("");
    let html_url = match nonempty(&repo.html_url) {
        Some(u) => u,
        None => return vec![],
    };

    // Confidence: higher if owner login matches username seed exactly,
    // or if the repo name/description contain the seed string.
    let owner_login = repo
        .owner
        .as_ref()
        .and_then(|o| o.login.as_deref())
        .unwrap_or("");
    let exact_owner = seed_kind == TargetKind::Username && owner_login.eq_ignore_ascii_case(seed);
    let seed_in_repo = full_name.to_lowercase().contains(&seed.to_lowercase())
        || description.to_lowercase().contains(&seed.to_lowercase());
    let conf = if exact_owner || seed_in_repo {
        0.58
    } else {
        0.38
    };

    // Repo URL entity.
    let mut url_e = Entity::new(EntityKind::Url, html_url, conf, scan_id);
    url_e.tag(SRC);
    url_e.tag("code-repo");
    url_e.tag("github");
    let mut ev = Evidence::new(SRC, format!("GitHub code search hit: {full_name}"))
        .with_attr("repo", full_name)
        .with_attr("seed", seed);
    if let Some(d) = nonempty(&repo.description) {
        ev = ev.with_attr("description", d);
    }
    url_e.add_evidence(ev.clone());
    out.push(url_e);

    // Repo owner → Username pivot.
    if !owner_login.is_empty() {
        let login = owner_login;
        let owner_conf = if exact_owner { confidence::HIGH } else { conf };
        let mut u = Entity::new(EntityKind::Username, login, owner_conf, scan_id);
        u.tag(SRC);
        u.tag("github");
        u.tag("repo-owner");
        let mut uev = Evidence::new(SRC, format!("GitHub repo owner: {login} ({full_name})"))
            .with_attr("repo", full_name)
            .with_attr("owner", login);
        if let Some(profile_url) = repo.owner.as_ref().and_then(|o| nonempty(&o.html_url)) {
            uev = uev.with_attr("profile_url", profile_url);
        }
        u.add_evidence(uev);
        out.push(u);
    }

    out
}

/// Build Email and Person entities from a repository's recent commits. Pure.
pub(super) fn build_commit_emails(
    commits: &CommitsResp,
    repo_name: &str,
    scan_id: &str,
) -> Vec<Entity> {
    let mut seen_emails = std::collections::HashSet::new();
    let mut seen_names = std::collections::HashSet::new();
    let mut out = Vec::new();

    for item in &commits.commits {
        let Some(author) = item.commit.as_ref().and_then(|c| c.author.as_ref()) else {
            continue;
        };
        let Some(email) = nonempty(&author.email) else {
            continue;
        };
        // Skip noreply GitHub emails — not real contact addresses.
        if email.contains("noreply.github.com") || email.contains("users.noreply") {
            continue;
        }
        let email_lc = email.to_lowercase();
        if seen_emails.insert(email_lc.clone()) {
            let mut e = Entity::new(EntityKind::Email, &email_lc, 0.35, scan_id);
            e.tag(SRC);
            e.tag("github");
            e.tag("commit-author");
            let mut ev = Evidence::new(SRC, format!("Commit author email from {repo_name}"))
                .with_attr("repo", repo_name)
                .with_attr("email", &email_lc);
            if let Some(name) = author.name.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("commit_author_name", name);
            }
            e.add_evidence(ev);
            out.push(e);
        }

        // Commit author name → Person entity (low confidence; one of potentially
        // many contributors to the repo).
        if let Some(name) = author.name.as_deref().map(str::trim).filter(|n| {
            n.len() >= 4
                && n.contains(' ')
                && !n.eq_ignore_ascii_case("github actions")
                && !n.to_lowercase().contains("bot")
        }) {
            let name_lc = name.to_lowercase();
            if seen_names.insert(name_lc) {
                let mut pe = Entity::new(EntityKind::Person, name, 0.30, scan_id);
                pe.tag(SRC);
                pe.tag("github");
                pe.tag("commit-author");
                pe.tag("derived");
                pe.add_evidence(
                    Evidence::new(SRC, format!("Commit author name from {repo_name}"))
                        .with_attr("repo", repo_name)
                        .with_attr("author_name", name),
                );
                out.push(pe);
            }
        }
    }

    out
}
