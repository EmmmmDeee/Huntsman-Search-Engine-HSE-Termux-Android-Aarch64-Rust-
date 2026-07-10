//! AU correlation rules — org family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_012_identity_linked_domain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let username_uids: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|u| u.uid.clone())
        .collect();
    if username_uids.is_empty() {
        return Vec::new();
    }
    entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Url | EntityKind::Domain) && e.has_tag("personal-site")
        })
        .map(|d| {
            let mut uids = Vec::with_capacity(1 + username_uids.len());
            uids.push(d.uid.clone());
            uids.extend(username_uids.iter().cloned());
            Correlation {
                rule_id: "AU-012".into(),
                rule_name: "Identity-linked site".into(),
                severity: Severity::Medium,
                description: format!(
                    "Personal site '{}' co-occurs with {} username(s) in scan",
                    d.value,
                    username_uids.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
                techniques: Vec::new(),
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_022_organisation_with_breach(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.confidence >= 0.60)
        .collect();
    if orgs.is_empty() {
        return Vec::new();
    }
    let breach_entities: Vec<&Entity> = entities.iter().filter(|e| e.has_tag("breach")).collect();
    if breach_entities.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|e| e.uid.clone()).collect();
    // Full member set (no `take` cap): the live and finalise passes must yield the
    // same uid SET so storage's containment-dedup folds them. A `take(5)` of the
    // HashMap-ordered breach list gave disjoint 5-samples across passes that
    // persisted as duplicate AU-022 rows — the same defect (and fix) as AU-018.
    uids.extend(breach_entities.iter().map(|e| e.uid.clone()));
    vec![Correlation::new(
        "AU-022",
        "Organisation linked to breach data",
        Severity::High,
        format!(
            "{} organisation(s) co-located with {} breach entities",
            orgs.len(),
            breach_entities.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(in crate::core::correlator) fn rule_au_024_email_fraud_signal(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .filter_map(|e| {
            // Classify each tag class once, then reuse the booleans for the
            // ≥2-signal gate, the signal labels and (implicitly) the count —
            // instead of re-scanning the tag list up to seven times per email.
            let fraud = e.has_tag("suspicious") || e.has_tag("high-risk");
            let breach = e.has_tag("breach");
            let disposable = e.has_tag("disposable");
            if u32::from(fraud) + u32::from(breach) + u32::from(disposable) < 2 {
                return None;
            }
            let mut signals: Vec<&str> = Vec::new();
            if fraud {
                signals.push("fraud-flagged");
            }
            if breach {
                signals.push("breach-exposed");
            }
            if disposable {
                signals.push("disposable");
            }
            Some(Correlation::new(
                "AU-024",
                "Multi-signal email fraud indicator",
                Severity::High,
                format!(
                    "Email '{}' has converging risk signals: {}",
                    e.value,
                    signals.join(" + ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ))
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_025_corporate_identity_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.has_tag("opencorporates"))
        .collect();
    if orgs.is_empty() {
        return Vec::new();
    }
    let persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.confidence >= 0.60)
        .collect();
    if persons.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = orgs.iter().map(|o| o.uid.clone()).collect();
    // Full member set (no `take` cap) so the live/finalise uid SETs match and
    // containment-dedup folds them, as in AU-018/AU-022 — a HashMap-ordered
    // `take(5)` sample otherwise persists as duplicate AU-025 rows.
    uids.extend(persons.iter().map(|p| p.uid.clone()));
    vec![Correlation::new(
        "AU-025",
        "Corporate registry linked to identity",
        Severity::Medium,
        format!(
            "{} registered company/ies co-located with {} person entities",
            orgs.len(),
            persons.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-033 — Australian business identity. Links an ABN/ACN registration to the
/// registered organisation(s) it belongs to when both are present from an
/// Australian registry (`abn_lookup` → `abr`, `opencorporates`, `acnc_charities`
/// → `acnc`, `gleif_lei` → `gleif`). Surfaces the
/// ABN/ACN ↔ Organisation chain those modules produce but no prior rule joined
/// (AU-025 covers Organisation ↔ Person). Organisations are gated on a registry
/// tag so unrelated `Organisation` names (e.g. from search_engines) don't link.
pub(in crate::core::correlator) fn rule_au_033_abn_organisation_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let abns: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::AbnAcn)
        .collect();
    if abns.is_empty() {
        return Vec::new();
    }
    let orgs: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Organisation
                && (e.has_tag("abr")
                    || e.has_tag("opencorporates")
                    || e.has_tag("acnc")
                    || e.has_tag("gleif"))
        })
        .collect();
    if orgs.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = abns.iter().map(|a| a.uid.clone()).collect();
    uids.extend(orgs.iter().map(|o| o.uid.clone()));
    vec![Correlation::new(
        "AU-033",
        "Australian business identity (ABN/ACN \u{2194} organisation)",
        Severity::Medium,
        format!(
            "{} ABN/ACN registration(s) linked to {} registered organisation(s) \
             via the Australian Business Register / corporate registries",
            abns.len(),
            orgs.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// Delegates to [`crate::util::domains::is_proxy_registrant`] — single source
/// of truth for the privacy-proxy / WHOIS-redaction exclusion used by both
/// AU-109 and `core::relation::builders::derive_co_ownership`.
fn is_proxy_registrant(value: &str, is_email: bool) -> bool {
    crate::util::domains::is_proxy_registrant(value, is_email)
}

/// AU-109 — Shared-registrant domain co-ownership.
///
/// Groups the `RegisteredBy` edges (Domain → registrant Organisation/Email,
/// derived from WHOIS/RDAP by `relation::builders::derive_registration`) by
/// registrant. When ≥2 DISTINCT domains share one genuine registrant they are
/// very likely controlled by a single operator — the canonical WHOIS pivot for
/// mapping an actor's domain estate.
///
/// This is the ownership counterpart to AU-044 (shared web-analytics id): both
/// assert "different web properties, one operator". Unlike a shared hosting IP
/// (millions of unrelated sites behind one CDN edge — AU-031 treats that as
/// noise to *suppress*), a shared registrant is a strong ownership signal
/// because the registrant is the party that contractually holds the domains.
///
/// False-positive guard: privacy-proxy / redacted registrants (see
/// [`is_proxy_registrant`]) are shared across millions of domains and are
/// EXCLUDED — only a real registrant identity links the estate. Severity High,
/// matching AU-044's shared-ownership tier. Deterministic: registrants iterated
/// in uid order, member domains sorted by uid.
pub(in crate::core::correlator) fn rule_au_109_shared_registrant(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // uid → entity, for endpoint lookup.
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // registrant uid → distinct domain uids registered by it (insertion order
    // preserved for determinism; sorted before emission).
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations
        .iter()
        .filter(|r| r.kind == RelationKind::RegisteredBy)
    {
        let (Some(dom), Some(reg)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        // `RegisteredBy` is Domain → Organisation/Email by construction; assert
        // the endpoint kinds so a malformed edge can't group non-domains.
        if dom.kind != EntityKind::Domain
            || !matches!(reg.kind, EntityKind::Organisation | EntityKind::Email)
        {
            continue;
        }
        if is_proxy_registrant(&reg.value, reg.kind == EntityKind::Email) {
            continue;
        }
        let members = groups.entry(r.to_uid.as_str()).or_default();
        if !members.contains(&r.from_uid.as_str()) {
            members.push(r.from_uid.as_str());
        }
    }

    // Stable iteration order: registrants by uid.
    let mut registrant_uids: Vec<&str> = groups.keys().copied().collect();
    registrant_uids.sort_unstable();

    let mut out = Vec::new();
    for reg_uid in registrant_uids {
        let Some(mut domains) = groups.remove(reg_uid) else {
            continue;
        };
        if domains.len() < 2 {
            continue;
        }
        domains.sort_unstable();
        let reg = by_uid.get(reg_uid).copied();
        let reg_label = reg.map_or("registrant", |e| e.value.as_str());
        let reg_kind = match reg.map(|e| &e.kind) {
            Some(EntityKind::Email) => "registrant email",
            _ => "registrant organisation",
        };
        let domain_values: Vec<&str> = domains
            .iter()
            .filter_map(|u| by_uid.get(u).map(|e| e.value.as_str()))
            .collect();

        let mut uids: Vec<String> = Vec::with_capacity(domains.len() + 1);
        uids.push(reg_uid.to_string());
        uids.extend(domains.iter().map(|u| (*u).to_string()));

        out.push(Correlation::new(
            "AU-109",
            "Shared registrant (domain co-ownership)",
            Severity::High,
            format!(
                "{} domains share the {} '{}' — a common WHOIS registrant indicates \
                 the domains are controlled by one operator: {}",
                domains.len(),
                reg_kind,
                reg_label,
                domain_values.join(", ")
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

/// Upper bound on DISTINCT registrable domains sharing one dedicated IP for
/// AU-110 to read the co-tenancy as probable co-ownership rather than shared
/// hosting. A real operator estate is a handful of sites; a single IP serving
/// many *distinct* sites is a reseller / shared-hosting box — the high-fan-out
/// shared-infra case AU-031 already aggregates as noise.
const MAX_CO_HOSTED_REGISTRABLE: usize = 5;

/// AU-110 — Shared dedicated-IP domain co-hosting (probable co-ownership).
///
/// Groups the `ResolvesTo` edges (Domain → IpAddress, from DNS) by IP. When a
/// SMALL set of ≥2 DISTINCT registrable domains resolve to one DEDICATED IP they
/// are probably co-owned — the reverse-IP clustering pivot for an actor's estate.
///
/// This is the IP counterpart to AU-109 (shared registrant) at LOWER severity
/// (Medium vs High): a dedicated IP can still host a few unrelated small sites,
/// whereas a registrant contractually holds the domains. The finding is framed
/// as a lead to verify (against registrant / page content), not a conclusion.
///
/// Three false-positive guards, each removing a distinct noise class:
/// 1. **CDN / anycast edges** (`is_cdn_edge_ip`) and **non-routable** IPs
///    (`is_non_routable_ip`) are excluded — a Cloudflare edge fronting millions
///    of unrelated sites is co-tenancy, not co-ownership (the class AU-031
///    suppresses).
/// 2. **Distinct registrable domains** (`registrable_domain`) — the membership
///    must span ≥2 different eTLD+1s, so a single site's own subdomains
///    (`www`/`api`/`blog.example.com` all on its origin IP) is co-*residence*,
///    not co-ownership, and does NOT fire.
/// 3. **Fan-out cap** (`MAX_CO_HOSTED_REGISTRABLE`) — many distinct sites on one
///    IP reads as shared hosting and is skipped.
///
/// Severity Medium. Deterministic: IPs iterated in uid order, member domains and
/// the named registrable set sorted.
pub(in crate::core::correlator) fn rule_au_110_shared_hosting_ip(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // IP uid → distinct domain uids resolving to it (insertion order preserved).
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations
        .iter()
        .filter(|r| r.kind == RelationKind::ResolvesTo)
    {
        let (Some(dom), Some(ip)) = (
            by_uid.get(r.from_uid.as_str()),
            by_uid.get(r.to_uid.as_str()),
        ) else {
            continue;
        };
        if dom.kind != EntityKind::Domain || ip.kind != EntityKind::IpAddress {
            continue;
        }
        // Guard 1: exclude CDN/anycast edges and non-routable IPs.
        if crate::core::validation::is_cdn_edge_ip(&ip.value)
            || crate::core::validation::is_non_routable_ip(&ip.value)
        {
            continue;
        }
        let members = groups.entry(r.to_uid.as_str()).or_default();
        if !members.contains(&r.from_uid.as_str()) {
            members.push(r.from_uid.as_str());
        }
    }

    let mut ip_uids: Vec<&str> = groups.keys().copied().collect();
    ip_uids.sort_unstable();

    let mut out = Vec::new();
    for ip_uid in ip_uids {
        let Some(mut domains) = groups.remove(ip_uid) else {
            continue;
        };
        domains.sort_unstable();

        // Guard 2: count DISTINCT registrable domains; a single site's own
        // subdomains collapse to one eTLD+1 and must not fire.
        let mut registrables: Vec<String> = domains
            .iter()
            .filter_map(|u| by_uid.get(u))
            .filter_map(|e| crate::util::domains::registrable_domain(&e.value))
            .collect();
        registrables.sort_unstable();
        registrables.dedup();

        // Guard 3: ≥2 distinct sites, but skip shared-hosting fan-out.
        if registrables.len() < 2 || registrables.len() > MAX_CO_HOSTED_REGISTRABLE {
            continue;
        }

        let ip_label = by_uid.get(ip_uid).map_or("ip", |e| e.value.as_str());
        let mut uids: Vec<String> = Vec::with_capacity(domains.len() + 1);
        uids.push(ip_uid.to_string());
        uids.extend(domains.iter().map(|u| (*u).to_string()));

        out.push(Correlation::new(
            "AU-110",
            "Co-hosted on dedicated IP (probable co-ownership)",
            Severity::Medium,
            format!(
                "{} distinct sites resolve to the same dedicated IP {} — small-set \
                 co-hosting on a non-CDN address is a lead that the domains share an \
                 operator (verify against registrant / content): {}",
                registrables.len(),
                ip_label,
                registrables.join(", ")
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-087 — Shared organisational email domain (institutional / professional affiliation).
///
/// Groups confirmed `Email` entities by their domain and fires when two or more
/// DISTINCT addresses share one SPECIFIC organisational domain — a company, a
/// university (`*.edu.au`), or a government agency (`*.gov.au`). Freemail and ISP
/// webmail (gmail / bigpond / …) and mega / shared infrastructure are excluded via
/// [`crate::core::scan::is_noncentral_domain`], so the domain that survives is an
/// actual organisation: the addresses on it are an employer / institution
/// affiliation surface, and the people whose names derive those local-parts are
/// professionally or institutionally linked.
///
/// This is the email-domain analogue of AU-049 (shared address) and AU-050 (shared
/// phone): a different seam onto the subject's network — colleagues and
/// co-affiliates the residence / phone rules never reach, and one that applies to
/// the average employed or studying Australian. Medium severity, because a shared
/// org domain is an *affiliation surface*, not a confirmed person-to-person tie:
/// the two addresses may be one person's work aliases or two colleagues', and
/// either reading is useful intelligence about where the subject is affiliated.
///
/// Precision: the domain must be specific (`!is_noncentral_domain`, contains a
/// dot) and the cluster must hold ≥2 distinct addresses. Confirmed entities only
/// (the caller quarantines `candidate`s), so a broad name search's namesake
/// emails can't manufacture a false affiliation. Deterministic: domains and the
/// displayed addresses are iterated in sorted (`BTreeMap`/`BTreeSet`) order.
pub(in crate::core::correlator) fn rule_au_087_shared_org_email_domain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};
    // Cheap precondition: a cluster needs ≥2 emails, so fewer than two Email
    // entities anywhere means no shared domain can form.
    if entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .count()
        < 2
    {
        return Vec::new();
    }
    // domain → (distinct addresses, uids to link).
    let mut by_domain: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::Email) {
        let val = e.value.trim().to_ascii_lowercase();
        let Some((local, domain)) = val.split_once('@') else {
            continue;
        };
        // A real address needs a local-part and a dotted domain; the domain must
        // be a specific organisation, not freemail / ISP webmail / shared infra.
        if local.is_empty()
            || !domain.contains('.')
            || crate::core::scan::is_noncentral_domain(domain)
        {
            continue;
        }
        let entry = by_domain.entry(domain.to_string()).or_default();
        entry.0.insert(val.clone());
        entry.1.insert(e.uid.clone());
    }

    let mut out = Vec::new();
    for (domain, (addresses, mut uids)) in by_domain {
        if addresses.len() < 2 {
            continue;
        }
        // Ride-along: link any Person whose name derives one of the local-parts —
        // the actual people affiliated at this organisation (same dictionary-free
        // identity overlap the engine's wrong-identity gate uses), so the firing
        // names people, not just addresses.
        for p in entities.iter().filter(|e| e.kind == EntityKind::Person) {
            let matches = addresses.iter().any(|addr| {
                let local = addr.split('@').next().unwrap_or(addr);
                crate::core::scan::identity_overlaps(&p.value, local)
            });
            if matches {
                uids.insert(p.uid.clone());
            }
        }
        // Show a bounded, sorted sample so a company-wide breach dump doesn't emit
        // a multi-kilobyte description; the link set still carries every uid.
        let shown: Vec<&str> = addresses.iter().map(String::as_str).take(6).collect();
        let more = addresses.len().saturating_sub(shown.len());
        let suffix = if more > 0 {
            format!(" (+{more} more)")
        } else {
            String::new()
        };
        out.push(Correlation::new(
            "AU-087",
            "Shared organisational email domain",
            Severity::Medium,
            format!(
                "{} addresses share the organisational domain '{}': {}{} — an employer / \
                 institution affiliation surface linking the people behind them",
                addresses.len(),
                domain,
                shown.join(", "),
                suffix
            ),
            uids.into_iter().collect(),
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-089 — Australian corporate network (multiple registered companies).
///
/// Counts the **distinct registered companies** the subject's graph touches,
/// where a company is evidenced by a checksum-valid company identifier: a bare
/// nine-digit ACN, or an eleven-digit ABN whose trailing nine digits are
/// themselves a valid ACN (the ASIC company-ABN form, decoded by
/// [`crate::util::abn::derive_acn`]). An ABN and the ACN embedded in it collapse
/// to **one** company — dedup is by the canonical ACN — so a single company, or
/// a company seen as both its ABN and its derived ACN, never fires this rule
/// (that single link is already covered by AU-033/AU-088).
///
/// Two or more *distinct* companies is the signal worth surfacing: a person tied
/// to a web of registered companies — an officeholder / controller footprint
/// that matters for asset tracing and corporate-structure (shell) mapping,
/// beyond any single ABN↔organisation link. Severity escalates at three.
///
/// Non-company ABNs (sole traders, trusts, partnerships, super funds) are
/// deliberately excluded: they carry no ACN and are not the controllable
/// corporate vehicles this rule is about. Pure over the confirmed entity set.
pub(in crate::core::correlator) fn rule_au_089_corporate_network(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeMap;

    // canonical ACN → contributing entity uids (one company per distinct ACN).
    let mut companies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::AbnAcn) {
        let canonical = crate::util::abn::derive_acn(&e.value).or_else(|| {
            let digits: String = e.value.chars().filter(char::is_ascii_digit).collect();
            (digits.len() == 9 && crate::util::abn::is_valid_acn(&digits)).then_some(digits)
        });
        if let Some(acn) = canonical {
            companies.entry(acn).or_default().push(e.uid.clone());
        }
    }

    if companies.len() < 2 {
        return Vec::new();
    }

    let n = companies.len();
    let acn_list = companies
        .keys()
        .map(|a| format!("{} {} {}", &a[0..3], &a[3..6], &a[6..9]))
        .collect::<Vec<_>>()
        .join(", ");
    let mut uids: Vec<String> = companies.into_values().flatten().collect();
    uids.sort_unstable();
    uids.dedup();

    let severity = if n >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };
    vec![Correlation::new(
        "AU-089",
        "Australian corporate network (multiple registered companies)",
        severity,
        format!(
            "Subject's graph touches {n} distinct registered Australian companies \
             (checksum-valid ACN/company-ABN): {acn_list} — an officeholder / controller \
             footprint for asset tracing and corporate-structure mapping"
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-094 — Australian sole-trader / individual ABN holder (non-company).
///
/// The people-centric complement to AU-089. AU-089 surfaces *companies* — the
/// ACN-bearing registrations. But the majority of Australian ABN holders are
/// **not** companies: sole traders, trusts, partnerships and super funds, whose
/// 11-digit ABN carries no embedded ACN (its trailing nine digits fail the ASIC
/// company check — [`crate::util::abn::derive_acn`] returns `None`). This rule
/// surfaces those non-company ABNs, which AU-089 deliberately excludes.
///
/// A non-company ABN tied to the subject is a direct natural-person ↔ operating-
/// business link: a sole trader (a contractor, tradesperson, freelancer — the
/// single most common ABN class) *is* an individual trading under that number.
/// Severity Medium — a solid identity/livelihood tie and a lead into the ABR /
/// the GST and business-name registers, short of the asset-mapping weight of a
/// multi-company controller footprint. Pure over the confirmed entity set.
pub(in crate::core::correlator) fn rule_au_094_sole_trader_abn(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::BTreeSet;

    // Group as `NN NNN NNN NNN` for display; passthrough if not 11 digits. Pure.
    fn fmt_abn(a: &str) -> String {
        if a.len() == 11 {
            format!("{} {} {} {}", &a[0..2], &a[2..5], &a[5..8], &a[8..11])
        } else {
            a.to_string()
        }
    }

    // Distinct non-company ABNs (canonical bare-digit form) and their entities.
    let mut abns: BTreeSet<String> = BTreeSet::new();
    let mut uids: BTreeSet<String> = BTreeSet::new();
    for e in entities.iter().filter(|e| e.kind == EntityKind::AbnAcn) {
        let digits: String = e.value.chars().filter(char::is_ascii_digit).collect();
        if digits.len() == 11
            && crate::util::abn::is_valid_abn(&digits)
            && crate::util::abn::derive_acn(&digits).is_none()
        {
            abns.insert(digits);
            uids.insert(e.uid.clone());
        }
    }

    if abns.is_empty() {
        return Vec::new();
    }

    let n = abns.len();
    let list = abns
        .iter()
        .map(|a| fmt_abn(a))
        .collect::<Vec<_>>()
        .join(", ");
    vec![Correlation::new(
        "AU-094",
        "Australian sole-trader / individual ABN holder",
        Severity::Medium,
        format!(
            "Subject linked to {n} non-company Australian business number(s) ({list}) — an \
             individual/sole-trader, trust or partnership registration (no embedded ACN, so not \
             an incorporated company); a sole-trader ABN ties a natural person directly to an \
             operating business"
        ),
        uids.into_iter().collect(),
        scan_id,
        ts,
    )]
}

/// AU-100 — Australian employer / organisational affiliation (from work email).
///
/// A person's own non-freemail email domain is one of the strongest people-centric
/// pivots there is: where they work or study. This surfaces the subject's
/// Australian organisational email domains — a `.com.au`/`.net.au` (a commercial
/// entity that must hold an ABN), `.gov.au` (a public servant), `.edu.au` (a
/// student / academic), `.org.au` (a non-profit) or `.asn.au` (an association) —
/// classified by registrant type via [`crate::util::address_au::au_domain_registrant`].
///
/// Freemail (`gmail`/`outlook`/…) is excluded ([`crate::util::domains::is_freemail`]),
/// as is a personal `.id.au` domain (not an employer). The affiliation is both an
/// identity anchor (which org) and a pivot — to colleagues (AU-087 finds others on
/// the same domain) and to the registered AU entity behind the domain. Severity
/// Medium; one finding per distinct organisational domain. Pure over the set.
pub(in crate::core::correlator) fn rule_au_100_au_employer_affiliation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    // domain -> (registrant category, contributing uids, distinct emails).
    let mut by_domain: BTreeMap<String, (&'static str, BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email && e.confidence >= 0.50)
    {
        let Some(domain) = e.value.rsplit('@').next() else {
            continue;
        };
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() || crate::util::domains::is_freemail(&domain) {
            continue;
        }
        // AU organisational domain only; `.id.au` is a personal domain, not an
        // employer, so it is excluded.
        let Some((category, _)) = crate::util::address_au::au_domain_registrant(&domain) else {
            continue;
        };
        if category == "individual" {
            continue;
        }
        let entry = by_domain
            .entry(domain)
            .or_insert_with(|| (category, BTreeSet::new(), BTreeSet::new()));
        entry.1.insert(e.uid.clone());
        entry.2.insert(e.value.clone());
    }

    by_domain
        .into_iter()
        .map(|(domain, (category, uids, emails))| {
            let abn_note = if category == "commercial" {
                " (a com.au/net.au registrant holds an Australian ABN/ACN)"
            } else {
                ""
            };
            Correlation::new(
                "AU-100",
                "Australian employer / organisational affiliation",
                Severity::Medium,
                format!(
                    "Subject uses {} email(s) on the Australian organisational domain '{domain}' \
                     (a {category} registrant){abn_note} — a likely employer / institutional \
                     affiliation, and a pivot to colleagues and the registered AU entity",
                    emails.len()
                ),
                uids.into_iter().collect(),
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-107 — Subject's breach-stated employer / affiliation.
///
/// A breach/stealer record frequently names the subject's EMPLOYER or affiliated
/// organisation (a `company` / `employer` field), which the rich-detail extractor
/// (`breach_rich`) surfaces as a `breach`-tagged `Organisation` at modest
/// confidence (0.50) — BELOW [`rule_au_022_organisation_with_breach`]'s 0.60
/// co-location gate, so that rule (which only COUNTS co-located orgs anyway) never
/// names it. This rule does: it reports each distinct breach-stated organisation
/// as the subject's affiliation, with the breach source(s) that assert it — the
/// people-centric, stated-relationship complement to the registry-based corporate
/// links (AU-033/089/100). One source is a lead (Medium); two or more INDEPENDENT
/// sources naming the same employer is corroborated affiliation (High).
///
/// Precision: keys on the `breach` tag (a breach-sourced org, not a registry one),
/// requires a real name (≥2 alphabetic chars — rejects codes/IDs), de-dupes by
/// lowercase canonical name, and runs on the confirmed (candidate-filtered) view
/// so a co-occurrence stranger's employer never leaks in. Deterministic
/// (`BTreeMap` by name, sorted sources/uids).
pub(in crate::core::correlator) fn rule_au_107_breach_employer_affiliation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};
    // canonical lowercase name -> (display name, distinct breach sources, uids).
    let mut by_name: BTreeMap<String, (String, BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    for e in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation && e.has_tag("breach"))
    {
        let name = e.value.trim();
        if name.chars().filter(|c| c.is_alphabetic()).count() < 2 {
            continue; // a code / id, not a real organisation name
        }
        let entry = by_name
            .entry(name.to_lowercase())
            .or_insert_with(|| (name.to_string(), BTreeSet::new(), BTreeSet::new()));
        for s in e.corroborating_sources() {
            entry.1.insert(s.to_string());
        }
        entry.2.insert(e.uid.clone());
    }

    by_name
        .into_values()
        .map(|(name, sources, uids)| {
            let n = sources.len();
            let severity = if n >= 2 {
                Severity::High
            } else {
                Severity::Medium
            };
            let src_list = sources.into_iter().collect::<Vec<_>>().join(", ");
            Correlation::new(
                "AU-107",
                "Subject's breach-stated employer/affiliation",
                severity,
                format!(
                    "Breach data names '{name}' as the subject's employer/affiliation \
                     ({n} source(s): {src_list}) — a stated business relationship, the \
                     people-centric complement to the registry-based corporate links",
                ),
                uids.into_iter().collect(),
                scan_id,
                ts,
            )
        })
        .collect()
}
