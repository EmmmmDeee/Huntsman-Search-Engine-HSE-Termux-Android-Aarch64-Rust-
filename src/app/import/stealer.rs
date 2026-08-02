//! Parser for the "Stealerlogs" victim-centric export (`Module: Stealerlogs` /
//! `Victims:` / `[N]` blocks). Each victim carries a `Log Id:`, a `Credentials:`
//! list of `Username:`/`Password:`/`Pwned At:` triples and a `Domains:` list of
//! the sites/IPs found in the victim's saved credentials. This is the
//! stealer/victim data an analyst pivots on: the reused password across victims
//! (AU-047), the corporate domain a credential belongs to, the infrastructure IP.
//! Shared helpers (ImportStats, persistence, push_* extractors) live in `super`.
//!
//! Shape (indentation- and `[N]`-delimited, values on the line *after* each key):
//! ```text
//! Victims:
//!   [1]
//!     Log Id:
//!       <hex log id>
//!     Credentials:
//!       [1]
//!         Username:
//!           alice
//!         Password:
//!           hunter2
//!         Pwned At:
//!           2026-05-20T21:00:00Z
//!     Domains:
//!       [1]
//!         example.com
//!     Credential Count:
//!       15
//! ```

use super::*;

use crate::core::confidence;
use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::core::stealer_row::{StealerRow, StealerRowKind};

/// Detect the Stealerlogs export — by its module banner or by its structural
/// fingerprint (a `Victims:` section of `[N]` blocks each carrying a `Log Id:`
/// and a `Credentials:` list), so a renamed banner still parses.
pub(crate) fn looks_like_stealerlogs(body: &str) -> bool {
    body.contains("Module: Stealerlogs")
        || (body.contains("Victims:") && body.contains("Credentials:") && body.contains("Log Id:"))
}

/// One credential triple lifted from a victim block.
#[derive(Default)]
struct Cred {
    user: Option<String>,
    pass: Option<String>,
    pwned_at: Option<String>,
}

/// One infected machine ("victim") and everything its log yielded.
#[derive(Default)]
struct Victim {
    log_id: Option<String>,
    creds: Vec<Cred>,
    domains: Vec<String>,
    newest: Option<String>,
    oldest: Option<String>,
}

/// Which value the next bare line supplies.
#[derive(PartialEq, Clone, Copy)]
enum Pending {
    None,
    LogId,
    CredUser,
    CredPass,
    CredPwned,
    Domain,
    Newest,
    Oldest,
}

/// Which list the current `[N]` markers belong to.
#[derive(PartialEq, Clone, Copy)]
enum Sect {
    None,
    Creds,
    Domains,
}

/// True for a `[N]` index marker line, e.g. `   [12]`.
fn is_index_marker(trimmed: &str) -> bool {
    trimmed.len() >= 3
        && trimmed.starts_with('[')
        && trimmed.ends_with(']')
        && trimmed[1..trimmed.len() - 1]
            .chars()
            .all(|c| c.is_ascii_digit())
}

/// Split the report body into victim records via the indentation/`[N]` grammar.
/// A `[N]` at (or shallower than) the first victim marker's indent opens a new
/// victim; a deeper `[N]` opens a sub-record in the current section. A `Key:`
/// line sets what the following bare line supplies. Caps guard against a hostile
/// blob: at most 500 victims, 200 creds and 200 domains per victim.
fn split_victims(body: &str) -> Vec<Victim> {
    const MAX_VICTIMS: usize = 500;
    const MAX_PER_LIST: usize = 200;

    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    let mut victims: Vec<Victim> = Vec::new();
    let mut cur: Option<Victim> = None;
    let mut in_victims = false;
    let mut victim_indent: Option<usize> = None;
    let mut sect = Sect::None;
    let mut pending = Pending::None;

    for raw in body.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "Victims:" {
            in_victims = true;
            continue;
        }
        if !in_victims {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();

        // A `[N]` marker is structural — never a field value, so it takes priority
        // over a pending value-expecting state.
        if is_index_marker(trimmed) {
            let is_new_victim = victim_indent.is_none_or(|vi| indent <= vi);
            if is_new_victim {
                victim_indent = Some(victim_indent.map_or(indent, |vi| vi.min(indent)));
                if let Some(v) = cur.take()
                    && victims.len() < MAX_VICTIMS
                {
                    victims.push(v);
                }
                cur = Some(Victim::default());
                sect = Sect::None;
                pending = Pending::None;
            } else if let Some(v) = cur.as_mut() {
                match sect {
                    Sect::Creds if v.creds.len() < MAX_PER_LIST => v.creds.push(Cred::default()),
                    Sect::Domains => pending = Pending::Domain,
                    _ => {}
                }
            }
            continue;
        }

        // A pending value-expecting state consumes this line verbatim — even if it
        // ends with ':' (a password may), so this is checked before key-detection.
        if pending != Pending::None
            && let Some(v) = cur.as_mut()
        {
            match pending {
                Pending::LogId => v.log_id = Some(trimmed.to_string()),
                Pending::CredUser => {
                    if v.creds.is_empty() {
                        v.creds.push(Cred::default());
                    }
                    if let Some(c) = v.creds.last_mut() {
                        c.user = Some(trimmed.to_string());
                    }
                }
                Pending::CredPass => {
                    if let Some(c) = v.creds.last_mut() {
                        c.pass = Some(trimmed.to_string());
                    }
                }
                Pending::CredPwned => {
                    if let Some(c) = v.creds.last_mut() {
                        c.pwned_at = Some(trimmed.to_string());
                    }
                }
                Pending::Domain => {
                    if v.domains.len() < MAX_PER_LIST {
                        v.domains.push(trimmed.to_string());
                    }
                }
                Pending::Newest => v.newest = Some(trimmed.to_string()),
                Pending::Oldest => v.oldest = Some(trimmed.to_string()),
                Pending::None => {}
            }
            pending = Pending::None;
            continue;
        }

        // A `Key:` line transitions section/pending state.
        if let Some(key) = trimmed.strip_suffix(':') {
            match key.trim().to_ascii_lowercase().as_str() {
                "log id" => {
                    sect = Sect::None;
                    pending = Pending::LogId;
                }
                "credentials" => {
                    sect = Sect::Creds;
                    pending = Pending::None;
                }
                "domains" => {
                    sect = Sect::Domains;
                    pending = Pending::None;
                }
                "username" => pending = Pending::CredUser,
                "password" => pending = Pending::CredPass,
                "pwned at" => pending = Pending::CredPwned,
                "newest" => {
                    sect = Sect::None;
                    pending = Pending::Newest;
                }
                "oldest" => {
                    sect = Sect::None;
                    pending = Pending::Oldest;
                }
                "credential count" | "domain count" => {
                    sect = Sect::None;
                    pending = Pending::None;
                }
                _ => pending = Pending::None,
            }
        }
    }
    if let Some(v) = cur.take()
        && victims.len() < MAX_VICTIMS
    {
        victims.push(v);
    }
    victims
}

/// Parse a Stealerlogs export into correlated victim entities. Each victim's
/// `Log Id` becomes a `DeviceId` (the infected-machine pivot), its credentials
/// become `Username` + plaintext `Credential` entities, and its domains become
/// `Domain` / `IpAddress` pivots — every one tagged with this victim's log so
/// the cluster stays correlated. Plaintext passwords are emitted per victim and
/// NOT value-deduped, preserving the cross-victim reuse signal (AU-047) through
/// the uid-merge. Also returns every victim's credentials as paired
/// [`StealerRow`]s — the login/password/machine pairing the entity graph
/// above deliberately loses (each becomes an independent Email/Username/
/// Credential entity) but the Stealer Logs Viewer needs back. This export
/// format has no per-credential site association (`Domains:` is a flat,
/// victim-level list, not paired to any one credential), so every row's
/// `domain` is honestly `None` here — never fabricated from the victim's
/// domain list. Pure (no I/O) so it is unit-testable.
pub(super) fn parse_stealerlogs(
    body: &str,
    sid: &str,
) -> (Vec<Entity>, ImportStats, Vec<StealerRow>) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut stealer_rows = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for victim in split_victims(body) {
        // Skip an empty scaffolding block that yielded nothing.
        if victim.log_id.is_none() && victim.creds.is_empty() && victim.domains.is_empty() {
            continue;
        }
        stats.victim_records += 1;
        stats.stealer_docs += 1;

        // One evidence record describing this victim's log, cloned onto every
        // entity the victim yields so the cluster (machine ⇄ creds ⇄ domains)
        // stays correlated and verifiable. Domains ride along (truncated) so the
        // victim's full site list is preserved even when a domain is too generic
        // to promote to its own pivot.
        let short_id: String = victim
            .log_id
            .as_deref()
            .map_or_else(|| "unknown".to_string(), |h| h.chars().take(12).collect());
        let mut ev = Evidence::new(
            "import:stealer",
            format!(
                "Stealer log {short_id} — {} credential(s), {} domain(s)",
                victim.creds.len(),
                victim.domains.len()
            ),
        )
        .with_attr("importer", "stealerlogs")
        .with_attr("credential_count", victim.creds.len().to_string())
        .with_attr("domain_count", victim.domains.len().to_string());
        if let Some(id) = &victim.log_id {
            ev = ev.with_attr("log_id", id);
        }
        if let Some(n) = &victim.newest {
            ev = ev.with_attr("newest", n);
        }
        if let Some(o) = &victim.oldest {
            ev = ev.with_attr("oldest", o);
        }
        if !victim.domains.is_empty() {
            let joined = victim.domains.join(", ");
            ev = ev.with_attr(
                "domains",
                crate::util::str_util::truncate_safe(&joined, 240),
            );
        }

        let mut push = |mut e: Entity, tag: &str, evidence: Evidence| {
            e.tag("import");
            e.tag("stealer");
            e.tag("stealer-victim");
            e.tag(tag);
            e.add_evidence(evidence);
            entities.push(e);
        };

        // The infected machine's log id — the per-victim pivot that ties this
        // victim's whole cluster together.
        if let Some(id) = &victim.log_id
            && id.len() >= 8
            && seen.insert(format!("lid:{id}"))
        {
            push(
                Entity::new(EntityKind::DeviceId, id, confidence::MEDIUM_HIGH, sid),
                "log-id",
                ev.clone(),
            );
            stats.machines += 1;
        }

        for cred in &victim.creds {
            // `Pwned At:` is this credential's OWN capture date — distinct per
            // credential within a victim (unlike the victim-level `newest`/
            // `oldest` range above), so it rides only on the entities THIS
            // credential yields, not the whole victim's cluster. Previously
            // parsed into `Cred::pwned_at` and then silently dropped (never
            // read again anywhere) despite being a real field the module's own
            // format documents — a full-fidelity-policy gap (`Evidence`'s own
            // doc: "the FULL source record, preserved verbatim... nothing
            // redacted or omitted"), not a timeline classification (that stays
            // scoped to first-party scan MODULES, per the C1(c) precedent —
            // `cli/import` bulk-dump evidence deliberately does not feed
            // `core::timeline::classify`).
            let cred_ev = match &cred.pwned_at {
                Some(p) => ev.clone().with_attr("pwned_at", p),
                None => ev.clone(),
            };
            if let Some(u) = &cred.user
                && u.len() >= 2
            {
                if u.contains('@') {
                    let em = u.to_ascii_lowercase();
                    if !crate::core::validation::is_fragment_value(&EntityKind::Email, &em)
                        && seen.insert(format!("em:{em}"))
                    {
                        push(
                            Entity::new(EntityKind::Email, &em, confidence::MEDIUM_HIGH, sid),
                            "breach",
                            cred_ev.clone(),
                        );
                        stats.emails += 1;
                    }
                } else if seen.insert(format!("un:{}", u.to_lowercase())) {
                    push(
                        Entity::new(EntityKind::Username, u, confidence::MEDIUM, sid),
                        "breach",
                        cred_ev.clone(),
                    );
                    stats.usernames += 1;
                }
            }
            // Plaintext password — a first-class cross-correlation join-key
            // (AU-047). Emitted per victim, never value-deduped here, so a reused
            // password across victims survives to the uid-merge that gathers every
            // victim onto the one secret. The entropy gate downstream decides
            // linkability; a weak/common password is recorded but links nobody.
            if let Some(p) = &cred.pass
                && p.chars().count() >= 4
            {
                if seen.insert(format!("cr:{p}")) {
                    stats.credentials += 1;
                }
                push(
                    Entity::new(EntityKind::Credential, p, confidence::MEDIUM_HIGH, sid),
                    "plaintext-credential",
                    cred_ev.clone(),
                );
            }

            // The paired row the entity graph above can't represent: login +
            // password + capture date, exactly as this one credential record
            // held them, for the dedicated Stealer Logs Viewer. Deliberately
            // NOT gated by the same admission thresholds as the entities
            // above (`u.len() >= 2`, `p.chars().count() >= 4`) — this is a
            // full-fidelity record store, so a short/weak value that doesn't
            // earn its own graph pivot is still preserved here verbatim.
            let row = StealerRow {
                log_id: victim.log_id.clone(),
                domain: None,
                login: cred.user.clone(),
                password: cred.pass.clone(),
                pwned_at: cred.pwned_at.clone(),
                kind: StealerRowKind::Combo,
            };
            if !row.is_empty() {
                stealer_rows.push(row);
            }
        }

        for dom in &victim.domains {
            // A `Domains:` item is either an infrastructure IP the victim
            // connected to (a geolocatable pivot) or a site the victim had an
            // account on. Classify by shape; gate freemail/mega/placeholder
            // domains out of the pivot set exactly as the engine's expansion does
            // (deep-expanding gmail.com maps a platform, not the subject).
            if let Ok(ip) = dom.parse::<std::net::IpAddr>() {
                let ip = ip.to_string();
                if !crate::core::validation::is_bogus_ip(&ip) && seen.insert(format!("ip:{ip}")) {
                    push(
                        Entity::new(EntityKind::IpAddress, &ip, confidence::MEDIUM_HIGH, sid),
                        "breach",
                        ev.clone(),
                    );
                    stats.ips += 1;
                }
            } else {
                let d = dom.to_ascii_lowercase();
                if d.contains('.')
                    && !crate::util::domains::is_freemail(&d)
                    && !crate::core::scan::is_mega_domain(&d)
                    && !crate::core::validation::is_placeholder_domain(&d)
                    && !crate::core::validation::is_fragment_value(&EntityKind::Domain, &d)
                    && seen.insert(format!("dom:{d}"))
                {
                    push(
                        Entity::new(EntityKind::Domain, &d, confidence::MEDIUM, sid),
                        "breach",
                        ev.clone(),
                    );
                    stats.domains += 1;
                }
            }
        }
    }

    // A stealer log routinely carries a router BSSID, a crypto wallet, a leaked
    // API key, a bank IBAN, a WiFi SSID — mine them straight out of the body as
    // the other importers do, for geolocation / chain / key-pool / financial seeds.
    push_macs(body, sid, "stealer", &mut entities);
    push_crypto(body, sid, "stealer", &mut entities);
    push_api_keys(body, sid, "stealer", &mut entities);
    push_ibans(body, sid, "stealer", &mut entities);
    push_ssids(body, sid, "stealer", &mut entities);
    (entities, stats, stealer_rows)
}

/// CLI entry: parse a Stealerlogs export and persist it as a completed scan.
pub(super) async fn cmd_import_stealerlogs(body: &str, output: &str) -> Result<()> {
    note(output, "Importing Stealerlogs export...");
    let sid = format!("import-stealer-{}", crate::core::entity::unix_now());
    let (mut entities, stats, stealer_rows) = parse_stealerlogs(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    if stats.api_keys > 0 {
        crate::util::key_pool::save_pool_best_effort(&crate::util::key_pool::global_pool());
    }
    persist_and_report(&sid, &entities, output).await;
    persist_stealer_rows_best_effort(&sid, &stealer_rows, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
