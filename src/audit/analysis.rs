//! Core analysis logic: helpers and the main `audit` function.

use std::collections::BTreeMap;

use super::types::{AuditEntity, AuditReport, Finding, GeoSummary, LogSignals, Severity};

/// Coordinates within this radius (km) are treated as the same locality/metro —
/// independent geocoders rarely agree tighter than a city.
const GEO_CONSENSUS_KM: f64 = 50.0;
/// A coordinate farther than this (km) from the consensus is a divergent fix —
/// almost certainly a different place (a datacenter, a mis-geocode, a homograph
/// city) rather than the subject's true location.
const GEO_OUTLIER_KM: f64 = 150.0;

const MAX_EXAMPLES: usize = 8;

/// Cap an example list and de-duplicate while preserving order.
pub(super) fn examples(mut vals: Vec<String>) -> Vec<String> {
    vals.dedup();
    vals.truncate(MAX_EXAMPLES);
    vals
}

/// True if a value looks truncated or fragmentary rather than a complete,
/// verifiable datum — the documented "@gmail" / partial-reference case.
pub(super) fn is_fragment(kind: &str, value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    if v.ends_with('…') || v.ends_with("...") || v.ends_with('@') || v.starts_with('@') {
        return true;
    }
    match kind {
        "email" => {
            // Must be local@domain.tld — reject "@gmail", "matthew@", "a@b".
            match v.split_once('@') {
                Some((local, domain)) => {
                    local.is_empty() || !domain.contains('.') || domain.starts_with('.')
                }
                None => true,
            }
        }
        // A bare freemail PROVIDER as a "domain" finding (gmail.com) is the
        // "@gmail"-style incomplete reference in domain form.
        "domain" => v.len() < 4 || !v.contains('.'),
        "url" => !v.contains("://") || v.ends_with("://"),
        _ => false,
    }
}

/// Cross-validate the scan's coordinates: find the consensus locality (the point
/// with the most neighbours within [`GEO_CONSENSUS_KM`]) and flag any fix farther
/// than [`GEO_OUTLIER_KM`] from it as divergent. Returns the summary plus an
/// optional finding. Pure; uses the same haversine the correlator does.
fn geo_consistency(entities: &[AuditEntity]) -> (GeoSummary, Option<Finding>) {
    // Parse distinct coordinate points, keeping each one's source labels.
    let mut pts: Vec<(f64, f64, String, Vec<String>)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut srcs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for e in entities.iter().filter(|e| e.kind == "coordinates") {
        // The `hse radar` / `POST /api/v1/radar` sweep seeds every run with a
        // sentinel coordinate (0,0 — "null island") purely so the local-sensor
        // modules, which gate on target KIND and ignore the value, dispatch. It
        // is never a real claimed location. Without this guard, every radar
        // sweep's genuine GPS/Wi-Fi fix was compared against this placeholder
        // and reported as diverging by thousands of km from "the subject's
        // location" — a spurious [MEDIUM/HIGH] geo-divergence finding on every
        // single sweep, dinging the self-audit score for a fixed artifact of
        // how the sweep is seeded rather than a real source disagreement.
        if crate::core::scan::is_radar_sentinel(crate::core::scan::TargetKind::Coordinates, &e.value)
        {
            continue;
        }
        if let Some((lat, lon)) = crate::util::geohash::parse_coords(&e.value) {
            srcs.extend(e.sources.iter().cloned());
            if seen.insert(e.value.clone()) {
                pts.push((lat, lon, e.value.clone(), e.sources.clone()));
            }
        }
    }
    let mut summary = GeoSummary {
        coord_count: pts.len(),
        source_count: srcs.len(),
        ..Default::default()
    };
    if pts.len() < 2 {
        return (summary, None);
    }

    let dist = |a: &(f64, f64, String, Vec<String>), b: &(f64, f64, String, Vec<String>)| {
        crate::util::geohash::haversine_km(a.0, a.1, b.0, b.1)
    };
    // Max pairwise spread.
    for i in 0..pts.len() {
        for j in (i + 1)..pts.len() {
            summary.max_spread_km = summary.max_spread_km.max(dist(&pts[i], &pts[j]));
        }
    }
    // Consensus medoid: the point with the most neighbours within GEO_CONSENSUS_KM.
    let (mut best_idx, mut best_neighbours) = (0usize, 0usize);
    for i in 0..pts.len() {
        let n = (0..pts.len())
            .filter(|&j| j != i && dist(&pts[i], &pts[j]) <= GEO_CONSENSUS_KM)
            .count();
        if n > best_neighbours {
            best_neighbours = n;
            best_idx = i;
        }
    }
    summary.has_consensus = best_neighbours >= 1;

    // Everything spread tightly already → consensus, no finding.
    if summary.max_spread_km <= GEO_OUTLIER_KM {
        return (summary, None);
    }

    let medoid = &pts[best_idx];
    let mut outlier_examples: Vec<String> = Vec::new();
    for (i, p) in pts.iter().enumerate() {
        if i == best_idx {
            continue;
        }
        let d = dist(medoid, p);
        if d > GEO_OUTLIER_KM {
            summary.outliers += 1;
            let who = if p.3.is_empty() {
                String::new()
            } else {
                format!(" [{}]", p.3.join(","))
            };
            outlier_examples.push(format!("{}{who} — {:.0} km from consensus", p.2, d));
        }
    }
    if summary.outliers == 0 {
        return (summary, None);
    }

    // If there is a real consensus cluster, the outliers are noise to drop
    // (MEDIUM). If coordinates are scattered with no agreement, geolocation is
    // unreliable for this subject (HIGH).
    let severity = if summary.has_consensus {
        Severity::Medium
    } else {
        Severity::High
    };
    let finding = Finding {
        severity,
        category: "geo-divergence",
        message: format!(
            "{} geolocation fix(es) disagree by up to {:.0} km — sources do not agree on the \
             subject's location",
            summary.outliers + 1,
            summary.max_spread_km
        ),
        examples: examples(outlier_examples),
        recommendation: "Cross-validate geocoders: drop datacenter/CDN-IP fixes, prefer \
            multi-source consensus (WiGLE/EXIF over coarse IP-geo), and down-rank coordinates \
            that no other source corroborates. Investigate the divergent source above."
            .into(),
    };
    (summary, Some(finding))
}

/// Build the scored report from normalised entities and (optional) log signals.
/// Pure: every input is owned/borrowed data, no IO, fully unit-testable.
#[must_use]
pub fn audit(all_entities: &[AuditEntity], log: LogSignals) -> AuditReport {
    // Grade the operator's ACTIONABLE result. Breach co-occurrence that the
    // breach modules deliberately quarantined (tagged `candidate` — a record that
    // did not match the subject identity) is already excluded from the scan view,
    // the JSON/CSV export, and the correlator. Exclude it from the grade too, and
    // report it separately, so a thorough breach search is not perversely scored
    // as "noise" for raw material it correctly set aside — the audit was the one
    // consumer still counting quarantined rows against the result.
    let is_quarantined = |e: &AuditEntity| e.tags.iter().any(|t| t == crate::core::tags::CANDIDATE);
    let quarantined = all_entities.iter().filter(|e| is_quarantined(e)).count();
    let entities: Vec<AuditEntity> = all_entities
        .iter()
        .filter(|e| !is_quarantined(e))
        .cloned()
        .collect();
    let entities = entities.as_slice();
    let entity_total = entities.len();

    // ── Tiers + kind histogram ──────────────────────────────────────────────
    let mut by_kind_map: BTreeMap<String, usize> = BTreeMap::new();
    let (mut verified, mut probable, mut candidate) = (0usize, 0usize, 0usize);
    for e in entities {
        *by_kind_map.entry(e.kind.clone()).or_default() += 1;
        if e.c_effective >= 0.75 {
            verified += 1;
        } else if e.c_effective >= 0.40 {
            probable += 1;
        } else {
            candidate += 1;
        }
    }
    let mut by_kind: Vec<(String, usize)> = by_kind_map.into_iter().collect();
    by_kind.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let noise_ratio = if entity_total > 0 {
        candidate as f64 / entity_total as f64
    } else {
        0.0
    };

    let mut findings: Vec<Finding> = Vec::new();

    // An empty result is the single most important thing to surface. With no
    // entities there is no quality to grade, so the bare penalty model would score
    // it a misleading 100/100 "clean, well-sourced". Flag it: the cause is either
    // total source failure (connectivity / missing keys → see source-health) or a
    // target with no discoverable footprint for this seed.
    if entity_total == 0 {
        findings.push(Finding {
            severity: Severity::High,
            category: "empty-result",
            message: "scan produced 0 entities — no intelligence was gathered".into(),
            examples: Vec::new(),
            recommendation: "Check source health (modules that errored or were \
                blocked, missing API keys) and connectivity. If every source ran \
                cleanly, the target likely has no discoverable footprint for this seed."
                .into(),
        });
    }
    let count = |k: &str| entities.iter().filter(|e| e.kind == k).count();

    // ── 1. Infrastructure pollution ──────────────────────────────────────────
    let mut infra: Vec<String> = Vec::new();
    for e in entities {
        let hit = match e.kind.as_str() {
            "ip_address" => crate::core::validation::is_cdn_edge_ip(&e.value),
            "domain" => crate::core::scan::is_noncentral_domain(&e.value),
            "email" => crate::util::domains::is_infrastructure_email(&e.value),
            _ => false,
        } || e.tags.iter().any(|t| {
            let t = t.to_ascii_lowercase();
            t == "cloudflare" || t == "hosting" || t == "shodan:cdn"
        }) && matches!(e.kind.as_str(), "ip_address" | "domain");
        if hit {
            infra.push(format!("{}={}", e.kind, e.value));
        }
    }
    if !infra.is_empty() {
        let n = infra.len();
        findings.push(Finding {
            severity: if n >= 5 {
                Severity::Critical
            } else {
                Severity::High
            },
            category: "infrastructure-pollution",
            message: format!(
                "{n} CDN/registrar/provider infrastructure entit{} are present — these map a \
                 provider's estate, not the subject, and inflate correlations",
                if n == 1 { "y" } else { "ies" }
            ),
            examples: examples(infra),
            recommendation: "Exclude these from expansion and correlation \
                (is_cdn_edge_ip / is_noncentral_domain / is_infrastructure_email already gate \
                them in the engine — investigate the module that emitted each one)."
                .into(),
        });
    }

    // ── 2. Generic / non-individualised domains ──────────────────────────────
    let generic: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == "domain")
        .filter(|e| {
            e.c_effective < 0.55
                && !crate::core::scan::is_noncentral_domain(&e.value) // counted above
                && !e.tags.iter().any(|t| t == "subdomain")
        })
        .map(|e| e.value.clone())
        .collect();
    if generic.len() >= 3 {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "generic-domain-noise",
            message: format!(
                "{} low-confidence bare external domains — likely SERP-result hosts that are \
                 not the subject's own assets",
                generic.len()
            ),
            examples: examples(generic),
            recommendation: "For person/email/username seeds, bare external SERP hosts should \
                be suppressed (kept only as Url entities). Verify search_engines build.rs gating."
                .into(),
        });
    }

    // ── 3. Truncated / fragment values ───────────────────────────────────────
    let fragments: Vec<String> = entities
        .iter()
        .filter(|e| is_fragment(&e.kind, &e.value))
        .map(|e| format!("{}={}", e.kind, e.value))
        .collect();
    if !fragments.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            category: "fragment-values",
            message: format!(
                "{} truncated / incomplete values (e.g. '@gmail', a domain-less email, a bare \
                 host) that can't be verified without reconstruction",
                fragments.len()
            ),
            examples: examples(fragments),
            recommendation: "Reject partial parses at the source; every finding must be a \
                complete, verifiable datum (full email local@domain.tld, full URL with scheme)."
                .into(),
        });
    }

    // ── 4. Role/infra emails surfaced as PII ─────────────────────────────────
    let role_emails: Vec<String> = entities
        .iter()
        .filter(|e| e.kind == "email" && crate::util::domains::is_infrastructure_email(&e.value))
        .map(|e| e.value.clone())
        .collect();
    if !role_emails.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            category: "role-mailbox-as-pii",
            message: format!(
                "{} role/provider mailboxes (abuse@, dns@, …) treated as the subject's email",
                role_emails.len()
            ),
            examples: examples(role_emails),
            recommendation: "These are registrar/provider desks; suppress at the WHOIS/RIPE \
                emitter and never breach-check or identity-cluster them."
                .into(),
        });
    }

    // ── 5. Missed-PII / weak enrichment ──────────────────────────────────────
    let (emails, persons, phones, addrs, usernames, urls) = (
        count("email"),
        count("person"),
        count("phone"),
        count("address") + count("coordinates"),
        count("username"),
        count("url"),
    );
    let mut missed: Vec<String> = Vec::new();
    if emails > 0 && persons == 0 {
        missed.push("has email(s) but no Person — name enrichment likely missed".into());
    }
    if emails + usernames > 0 && phones == 0 && addrs == 0 {
        missed
            .push("identity present but no phone or location — geo/contact enrichment thin".into());
    }
    if usernames > 0 && urls == 0 {
        missed.push("username(s) present but no profile URLs — social enumeration missed".into());
    }
    if !missed.is_empty() {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "missed-pii",
            message: format!("{} enrichment gap(s) detected", missed.len()),
            examples: missed,
            recommendation: "Strengthen recursion/enrichment on confirmed seeds (name→person, \
                username→social profiles, email/handle→phone/address)."
                .into(),
        });
    }

    // ── 6. Single-source dominance (weak corroboration) ──────────────────────
    if entity_total >= 10 {
        let single = entities.iter().filter(|e| e.corroboration <= 1).count();
        let share = single as f64 / entity_total as f64;
        if share >= 0.6 {
            findings.push(Finding {
                severity: Severity::Low,
                category: "weak-corroboration",
                message: format!(
                    "{:.0}% of entities have a single source — most findings are uncorroborated",
                    share * 100.0
                ),
                examples: Vec::new(),
                recommendation: "Add independent sources / cross-checks; rank corroborated \
                    findings ahead of single-source ones."
                    .into(),
            });
        }
    }

    // ── 7. Source health (from logs) ─────────────────────────────────────────
    if !log.engine_parser_defects.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            category: "engine-parser-defect",
            message: format!(
                "{} search engine(s) returned pages that parsed to zero results — a parser \
                 defect, not a block",
                log.engine_parser_defects.len()
            ),
            examples: examples(log.engine_parser_defects.clone()),
            recommendation: "Fix the per-engine result parser (markup likely changed). Run \
                `hse engines` for the per-engine diagnosis."
                .into(),
        });
    }
    let dead_engines = log.engines_down.len() + log.engines_blocked.len();
    if dead_engines >= 3 {
        let mut ex = log.engines_down.clone();
        ex.extend(log.engines_blocked.clone());
        findings.push(Finding {
            severity: Severity::Medium,
            category: "search-coverage",
            message: format!(
                "{dead_engines} search engine(s) down or blocked — reduced discovery coverage"
            ),
            examples: examples(ex),
            recommendation: "Blocks are often datacenter-IP only (work on residential/Termux); \
                set HUNTSMAN_SEARCH_PROXY or run from the target device. `down` needs an endpoint \
                fix."
                .into(),
        });
    }
    if !log.module_errors.is_empty() {
        let total: u32 = log.module_errors.values().sum();
        let ex: Vec<String> = log
            .module_errors
            .iter()
            .map(|(m, n)| format!("{m} ×{n}"))
            .collect();
        findings.push(Finding {
            severity: if total >= 10 {
                Severity::Medium
            } else {
                Severity::Low
            },
            category: "module-errors",
            message: format!(
                "{total} module error(s) across {} module(s)",
                log.module_errors.len()
            ),
            examples: examples(ex),
            recommendation: "Inspect each erroring module — API change, rate limit, or missing \
                key. Errors silently shrink coverage."
                .into(),
        });
    }

    // ── 7b. Expansion exclusions — recall risk made visible ──────────────────
    // The wrong-identity gate keeps a focused scan on-subject, but it can also
    // suppress genuine aliases. When it fires a lot relative to the entities we
    // actually kept, the operator should know there's a recall/coverage trade-off
    // in play (and that `--expand-all-identities` lifts it).
    if let Some(&mismatch) = log.excluded_reasons.get("identity_mismatch")
        && mismatch > 0
    {
        // Scale severity by how much the gate dominated the result: many
        // suppressed identities against a small kept graph is a real blind spot.
        let denom = entity_total.max(1) as f64;
        let ratio = mismatch as f64 / denom;
        let severity = if mismatch >= 10 && ratio >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        };
        findings.push(Finding {
            severity,
            category: "recursion-recall",
            message: format!(
                "{mismatch} username/person pivot(s) suppressed by the wrong-identity gate \
                 ({entity_total} entities kept) — possible missed aliases"
            ),
            examples: vec![format!("identity_mismatch ×{mismatch}")],
            recommendation: "If aliases were missed, re-run with `--expand-all-identities` \
                (or `--full`) to lift the gate, then prune unrelated footprints by hand. \
                Every suppressed alias is logged as `identity_mismatch`."
                .into(),
        });
    }
    // A large number of already-dispatched / non-pivotable exclusions is normal
    // (dedup + terminal kinds), so it is surfaced only as INFO context — never a
    // penalty — keeping the exclusion ledger visible without distorting the score.
    let other_excluded: u32 = log
        .excluded_reasons
        .iter()
        .filter(|(r, _)| r.as_str() != "identity_mismatch")
        .map(|(_, n)| *n)
        .sum();
    if other_excluded > 0 {
        let ex: Vec<String> = log
            .excluded_reasons
            .iter()
            .filter(|(r, _)| r.as_str() != "identity_mismatch")
            .map(|(r, n)| format!("{r} ×{n}"))
            .collect();
        findings.push(Finding {
            severity: Severity::Info,
            category: "expansion-ledger",
            message: format!("{other_excluded} pivot(s) excluded for non-recall reasons"),
            examples: examples(ex),
            recommendation: "Informational: dedup (`already_dispatched_this_scan`), terminal \
                kinds (`non_pivotable_kind`), saturation, infra gating, uncorroborated \
                search-snippet leads (`uncorroborated_recycled`) and unconfirmed \
                name-permutation guesses (`uncorroborated_speculative`) are expected. \
                Review only if a specific expected pivot is missing (raise recall with \
                `--expand-all-identities`)."
                .into(),
        });
    }

    // ── 8. Geolocation cross-source consistency ──────────────────────────────
    let (geo, geo_finding) = geo_consistency(entities);
    if let Some(f) = geo_finding {
        findings.push(f);
    }

    // ── Score ────────────────────────────────────────────────────────────────
    let penalty: u32 = findings.iter().map(|f| f.severity.penalty()).sum();
    let score = 100u32.saturating_sub(penalty);

    // Most-severe findings first, then by category for stable output.
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.category.cmp(b.category))
    });

    AuditReport {
        entity_total,
        by_kind,
        tiers: (verified, probable, candidate),
        noise_ratio,
        quarantined,
        findings,
        score,
        log,
        geo,
    }
}
