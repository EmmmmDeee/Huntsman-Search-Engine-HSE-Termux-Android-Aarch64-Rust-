//! Parser for the OathNet HTML export import format. Shared helpers (ImportStats,
//! persistence, geo/key construction) live in `super` and are reached via
//! `use super::*`.

use super::*;

/// Parse an OathNet HTML export into entities (domains/subdomains, IPs, emails)
/// by regex over the page text. Pure — the reusable core shared by the CLI
/// (`cmd_import_html`) and the web upload dispatcher, so the two never drift.
pub(super) fn parse_oathnet_html(body: &str, sid: &str) -> Vec<crate::core::entity::Entity> {
    use crate::core::entity::{Entity, EntityKind};
    use regex::Regex;
    use std::collections::HashSet;
    use std::sync::OnceLock;

    // Compile the three extraction patterns once (codebase convention — see
    // `util::html`, `address_au`, `employer_pivot`). Regex compilation is
    // non-trivial and these are otherwise rebuilt on every import call.
    static RES: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (ip_re, email_re, domain_re) = RES.get_or_init(|| {
        (
            Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap(),
            Regex::new(r"(?:https?://)?([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)").unwrap(),
        )
    });

    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let lower = body.to_lowercase();

    for cap in domain_re.captures_iter(&lower) {
        let dom = &cap[1];
        if dom.len() > 4 && seen.insert(format!("d:{dom}")) {
            let is_sub = dom.split('.').count() >= 3;
            let conf = if is_sub { 0.45 } else { 0.50 };
            let mut e = Entity::new(EntityKind::Domain, dom, conf, sid);
            e.tag("import");
            if is_sub {
                e.tag(crate::core::tags::SUBDOMAIN);
            }
            entities.push(e);
        }
    }

    for cap in ip_re.captures_iter(body) {
        let ip = cap[0].to_string();
        if seen.insert(format!("ip:{ip}"))
            && !ip.starts_with("0.")
            && !ip.starts_with("127.")
            && !ip.starts_with("255.")
        {
            let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.55, sid);
            e.tag("import");
            entities.push(e);
        }
    }

    for cap in email_re.captures_iter(body) {
        let em = cap[0].to_lowercase();
        if em.len() >= 5 && seen.insert(format!("em:{em}")) {
            let mut e = Entity::new(EntityKind::Email, &em, 0.50, sid);
            e.tag("import");
            entities.push(e);
        }
    }

    entities
}

pub(super) async fn cmd_import_html(body: &str, output: &str) -> Result<()> {
    use crate::core::entity::EntityKind;

    note(output, "Importing OathNet HTML export...");
    let sid = format!("import-html-{}", crate::core::entity::unix_now());
    let mut entities = parse_oathnet_html(body, &sid);

    deduplicate_by_uid(&mut entities);

    let domains = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .count();
    let ips = entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .count();
    let emails = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .count();

    note(
        output,
        format!(
            "Imported {} entities: {} domains, {} IPs, {} emails",
            entities.len(),
            domains,
            ips,
            emails
        ),
    );

    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
