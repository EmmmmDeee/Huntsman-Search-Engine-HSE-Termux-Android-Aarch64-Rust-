//! Scored self-audit of a scan's output.
//!
//! Distils a scan — from a CSV export, the live SQLite store, or a debug-log /
//! scan-event stream — into a **quality scorecard**: noise ratio, infrastructure
//! pollution, false-positive flags, truncated/fragment values, missed-PII
//! signals, and source health, each with concrete examples and an actionable
//! recommendation. It is the manifesto's "the platform should constantly evaluate
//! itself, identify weaknesses, expose blind spots … and generate actionable
//! recommendations" as a first-class, reusable capability.
//!
//! The analysis is **pure** (no IO) and reuses the *same* authoritative
//! classifiers the engine uses to make its filtering decisions
//! ([`crate::core::scan::is_noncentral_domain`],
//! [`crate::core::validation::is_cdn_edge_ip`],
//! [`crate::util::domains::is_infrastructure_email`]), so the audit flags exactly
//! the categories the engine is supposed to suppress — turning it into a living
//! regression guard. Lives at the crate root (not under `core`) so it may use
//! both `core` and `util` without violating the core→util boundary.

use std::collections::BTreeMap;

/// One entity, normalised to the common shape shared by every input source.
#[derive(Debug, Clone)]
pub struct AuditEntity {
    pub kind: String,
    pub value: String,
    pub confidence: f64,
    pub c_effective: f64,
    pub corroboration: u32,
    pub sources: Vec<String>,
    pub tags: Vec<String>,
}

impl AuditEntity {
    /// Normalise a stored [`Entity`](crate::core::entity::Entity) for auditing —
    /// the shared mapping used by both the `--scan-id` CLI path and the web API
    /// so the two can never drift. `sources` is the de-duplicated set of evidence
    /// source names.
    #[must_use]
    pub fn from_entity(e: &crate::core::entity::Entity) -> Self {
        let sources: Vec<String> = e
            .evidence
            .iter()
            .map(|ev| ev.source.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            kind: e.kind.to_string(),
            value: e.value.clone(),
            confidence: e.confidence,
            c_effective: e.c_effective(),
            corroboration: e.corroboration,
            sources,
            tags: e.tags.clone(),
        }
    }
}

/// Signals distilled from a debug-log / scan-event stream. All optional — a CSV
/// or DB audit simply leaves these empty.
#[derive(Debug, Default, Clone)]
pub struct LogSignals {
    /// module name → error count.
    pub module_errors: BTreeMap<String, u32>,
    /// module name → timeout count.
    pub module_timeouts: BTreeMap<String, u32>,
    /// Search engines reporting blocked / down / a parser defect.
    pub engines_blocked: Vec<String>,
    pub engines_down: Vec<String>,
    pub engine_parser_defects: Vec<String>,
    /// HTTP / fetch failures observed across all components.
    pub http_failures: u32,
    /// Reasons recorded for expansion stopping early.
    pub expansion_stops: Vec<String>,
    /// Per-reason count of entities excluded from expansion (an `EntityExcluded`
    /// event's `reason` → how many times it fired). Surfaces *why* pivots were
    /// pruned — e.g. a high `identity_mismatch` count means the wrong-identity
    /// gate suppressed many aliases (a recall risk the operator can lift with
    /// `--expand-all-identities`).
    pub excluded_reasons: BTreeMap<String, u32>,
    /// Total log lines consumed (so an empty/garbage log is obvious).
    pub lines_parsed: usize,
}

/// Severity of an audit finding, ordered most-severe first for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
    /// Score penalty per finding of this severity (subtracted from 100).
    fn penalty(self) -> u32 {
        match self {
            Self::Critical => 25,
            Self::High => 15,
            Self::Medium => 8,
            Self::Low => 3,
            Self::Info => 0,
        }
    }
}

/// A single audit observation: a category, a human explanation, concrete
/// offending examples, and the recommended action.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: &'static str,
    pub message: String,
    pub examples: Vec<String>,
    pub recommendation: String,
}

/// Cross-source geolocation consistency summary — validates that the scan's
/// geocoders agree, and quantifies disagreement when they don't.
#[derive(Debug, Clone, Default)]
pub struct GeoSummary {
    /// Distinct coordinate points parsed.
    pub coord_count: usize,
    /// Distinct geo source modules contributing coordinates.
    pub source_count: usize,
    /// Largest pairwise great-circle distance between any two coordinates (km).
    pub max_spread_km: f64,
    /// Coordinates lying farther than the outlier threshold from the consensus.
    pub outliers: usize,
    /// True if a consensus cluster (≥2 nearby coordinates) was found.
    pub has_consensus: bool,
}

/// The full scored audit.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub entity_total: usize,
    pub by_kind: Vec<(String, usize)>,
    /// (verified ≥0.75, probable ≥0.40, candidate <0.40) by c_effective.
    pub tiers: (usize, usize, usize),
    /// Share of entities in the candidate (low-confidence) tier, 0.0–1.0.
    pub noise_ratio: f64,
    pub findings: Vec<Finding>,
    /// 0–100 — 100 is a clean, individualised, well-sourced scan.
    pub score: u32,
    pub log: LogSignals,
    /// Cross-source geolocation consistency.
    pub geo: GeoSummary,
}

/// Coordinates within this radius (km) are treated as the same locality/metro —
/// independent geocoders rarely agree tighter than a city.
const GEO_CONSENSUS_KM: f64 = 50.0;
/// A coordinate farther than this (km) from the consensus is a divergent fix —
/// almost certainly a different place (a datacenter, a mis-geocode, a homograph
/// city) rather than the subject's true location.
const GEO_OUTLIER_KM: f64 = 150.0;

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

impl AuditReport {
    /// Letter grade + one-line characterisation derived from the score. Shared by
    /// the CLI scorecard and the web panel so both speak the same language.
    #[must_use]
    pub fn grade(&self) -> &'static str {
        match self.score {
            90..=100 => "A — clean, individualised, well-sourced",
            75..=89 => "B — solid, minor weaknesses",
            60..=74 => "C — usable but noisy",
            40..=59 => "D — significant weaknesses",
            _ => "F — dominated by noise / false positives",
        }
    }

    /// Canonical JSON form — the single serialization used by `hse audit --json`
    /// and `GET /api/v1/scans/{id}/audit`, so the CLI and web UI never diverge.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let findings: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "severity": f.severity.as_str(),
                    "category": f.category,
                    "message": f.message,
                    "examples": f.examples,
                    "recommendation": f.recommendation,
                })
            })
            .collect();
        let by_kind: BTreeMap<&str, usize> =
            self.by_kind.iter().map(|(k, n)| (k.as_str(), *n)).collect();
        serde_json::json!({
            "score": self.score,
            "grade": self.grade(),
            "entity_total": self.entity_total,
            "tiers": {
                "verified": self.tiers.0,
                "probable": self.tiers.1,
                "candidate": self.tiers.2,
            },
            "noise_ratio": self.noise_ratio,
            "by_kind": by_kind,
            "findings": findings,
            "source_health": {
                "engines_down": self.log.engines_down,
                "engines_blocked": self.log.engines_blocked,
                "engine_parser_defects": self.log.engine_parser_defects,
                "module_errors": self.log.module_errors,
                "http_failures": self.log.http_failures,
                "log_lines_parsed": self.log.lines_parsed,
            },
            "expansion": {
                "stops": self.log.expansion_stops,
                "excluded_reasons": self.log.excluded_reasons,
            },
            "geo": {
                "coord_count": self.geo.coord_count,
                "source_count": self.geo.source_count,
                "max_spread_km": self.geo.max_spread_km,
                "outliers": self.geo.outliers,
                "has_consensus": self.geo.has_consensus,
            },
        })
    }
}

const MAX_EXAMPLES: usize = 8;

/// Cap an example list and de-duplicate while preserving order.
fn examples(mut vals: Vec<String>) -> Vec<String> {
    vals.dedup();
    vals.truncate(MAX_EXAMPLES);
    vals
}

/// True if a value looks truncated or fragmentary rather than a complete,
/// verifiable datum — the manifesto's explicit "@gmail" / partial-reference case.
fn is_fragment(kind: &str, value: &str) -> bool {
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

/// Fold a stored scan's events into auditor [`LogSignals`]: every
/// `ExpansionStop` reason and every `EntityExcluded` reason (counted), so the
/// recursion/admission ledger is available to the audit without a debug-log
/// upload. Shared by the web audit endpoint and the CLI debug bundle so the two
/// can never diverge.
pub fn fold_events(sig: &mut LogSignals, events: &[crate::core::event::Event]) {
    use crate::core::event::EventKind;
    for ev in events {
        match &ev.kind {
            EventKind::ExpansionStop { reason } => sig.expansion_stops.push(reason.clone()),
            EventKind::EntityExcluded { reason, .. } => {
                *sig.excluded_reasons.entry(reason.clone()).or_default() += 1;
            }
            EventKind::ModuleError { module, .. } => {
                *sig.module_errors.entry(module.clone()).or_default() += 1;
            }
            _ => {}
        }
    }
}

/// Build the scored report from normalised entities and (optional) log signals.
/// Pure: every input is owned/borrowed data, no IO, fully unit-testable.
#[must_use]
pub fn audit(entities: &[AuditEntity], log: LogSignals) -> AuditReport {
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
                kinds (`non_pivotable_kind`), saturation and infra gating are expected. \
                Review only if a specific expected pivot is missing."
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
        findings,
        score,
        log,
        geo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(kind: &str, value: &str, c: f64, corr: u32, tags: &[&str]) -> AuditEntity {
        AuditEntity {
            kind: kind.into(),
            value: value.into(),
            confidence: c,
            c_effective: c,
            corroboration: corr,
            sources: vec!["test".into()],
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn clean_individualised_scan_scores_high() {
        let ents = vec![
            ent("email", "matthewdiegmann@gmail.com", 1.0, 4, &[]),
            ent("username", "matthewdiegmann", 1.0, 3, &[]),
            ent("person", "Matthew Diegmann", 0.8, 2, &[]),
            ent("address", "Ellington, Connecticut", 0.7, 2, &[]),
            ent("url", "https://gravatar.com/matthewdiegmann", 0.6, 1, &[]),
        ];
        let r = audit(&ents, LogSignals::default());
        assert!(
            r.score >= 90,
            "clean scan should score high, got {}",
            r.score
        );
        assert!(
            !r.findings
                .iter()
                .any(|f| f.category == "infrastructure-pollution"),
            "no infra in a clean scan"
        );
    }

    #[test]
    fn infrastructure_pollution_is_flagged_critical() {
        // The exact failure from the real screenshots.
        let ents = vec![
            ent(
                "ip_address",
                "172.66.147.185",
                1.0,
                258,
                &["cloudflare", "hosting"],
            ),
            ent("ip_address", "104.20.37.187", 1.0, 268, &["cloudflare"]),
            ent("email", "dns@cloudflare.com", 1.0, 2, &[]),
            ent("email", "abuse@cloudflare.com", 1.0, 1, &[]),
            ent("domain", "cloudflare.com", 1.0, 5, &[]),
        ];
        let r = audit(&ents, LogSignals::default());
        let f = r
            .findings
            .iter()
            .find(|f| f.category == "infrastructure-pollution")
            .expect("must flag infra pollution");
        assert_eq!(f.severity, Severity::Critical);
        assert!(
            r.score < 80,
            "infra pollution must hurt the score, got {}",
            r.score
        );
    }

    #[test]
    fn fragment_values_are_detected() {
        assert!(is_fragment("email", "@gmail"));
        assert!(is_fragment("email", "matthew@"));
        assert!(is_fragment("email", "a@b")); // no dot in domain
        assert!(is_fragment("url", "example.com/path")); // no scheme
        assert!(is_fragment("domain", "ab")); // too short / no dot
        assert!(!is_fragment("email", "real.person@onet.eu"));
        assert!(!is_fragment("url", "https://x.com/u"));
        assert!(!is_fragment("domain", "example.com"));

        let ents = vec![ent("email", "@gmail", 0.5, 1, &[])];
        let r = audit(&ents, LogSignals::default());
        assert!(r.findings.iter().any(|f| f.category == "fragment-values"));
    }

    #[test]
    fn log_parser_defect_is_surfaced() {
        let mut log = LogSignals::default();
        log.engine_parser_defects.push("brave".into());
        log.lines_parsed = 100;
        let r = audit(&[], log);
        assert!(
            r.findings
                .iter()
                .any(|f| f.category == "engine-parser-defect" && f.severity == Severity::High)
        );
    }

    #[test]
    fn heavy_identity_gating_surfaces_recall_risk() {
        // Few entities kept, many username/person pivots suppressed → the
        // wrong-identity gate dominated the result. That is a recall blind spot
        // and must be surfaced (MEDIUM) with the --expand-all-identities tip.
        let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
        let mut log = LogSignals::default();
        log.excluded_reasons.insert("identity_mismatch".into(), 12);
        let r = audit(&ents, log);
        let f = r
            .findings
            .iter()
            .find(|f| f.category == "recursion-recall")
            .expect("recall finding");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.recommendation.contains("--expand-all-identities"));
    }

    #[test]
    fn non_recall_exclusions_are_info_only() {
        // Dedup / terminal-kind exclusions are expected; they must appear as
        // INFO context (zero score penalty), never as a recall finding.
        let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
        let mut log = LogSignals::default();
        log.excluded_reasons
            .insert("already_dispatched_this_scan".into(), 40);
        log.excluded_reasons.insert("non_pivotable_kind".into(), 5);
        let r = audit(&ents, log);
        let f = r
            .findings
            .iter()
            .find(|f| f.category == "expansion-ledger")
            .expect("ledger finding");
        assert_eq!(f.severity, Severity::Info);
        assert!(!r.findings.iter().any(|f| f.category == "recursion-recall"));
    }

    #[test]
    fn missed_pii_when_email_but_no_person() {
        let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
        let r = audit(&ents, LogSignals::default());
        assert!(r.findings.iter().any(|f| f.category == "missed-pii"));
    }

    #[test]
    fn to_json_is_stable_and_complete() {
        let ents = vec![ent("email", "dns@cloudflare.com", 1.0, 1, &[])];
        let j = audit(&ents, LogSignals::default()).to_json();
        assert!(j["score"].as_u64().is_some());
        assert!(
            j["grade"]
                .as_str()
                .unwrap()
                .starts_with(|c: char| c.is_ascii_uppercase())
        );
        assert!(
            j["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| { f["category"] == "role-mailbox-as-pii" })
        );
        assert!(j["source_health"]["engines_down"].is_array());
    }

    #[test]
    fn grade_bands_are_monotonic() {
        let mk = |score: u32| AuditReport {
            entity_total: 0,
            by_kind: vec![],
            tiers: (0, 0, 0),
            noise_ratio: 0.0,
            findings: vec![],
            score,
            log: LogSignals::default(),
            geo: GeoSummary::default(),
        };
        assert!(mk(95).grade().starts_with("A"));
        assert!(mk(80).grade().starts_with("B"));
        assert!(mk(50).grade().starts_with("D"));
        assert!(mk(10).grade().starts_with("F"));
    }

    #[test]
    fn geo_divergence_flags_an_outlier_against_consensus() {
        // Three nearby fixes (a real metro) + one ~3800 km outlier (a datacenter
        // or mis-geocode). The outlier must be flagged, consensus recognised.
        let ents = vec![
            ent("coordinates", "35.4137,-114.1762", 0.6, 1, &[]), // Bullhead City, AZ
            ent("coordinates", "35.4200,-114.1800", 0.6, 1, &[]),
            ent("coordinates", "35.4000,-114.2000", 0.6, 1, &[]),
            ent("coordinates", "45.5019,-73.5674", 0.4, 1, &[]), // Montreal — outlier
        ];
        let r = audit(&ents, LogSignals::default());
        let f = r
            .findings
            .iter()
            .find(|f| f.category == "geo-divergence")
            .expect("must flag geo divergence");
        assert_eq!(f.severity, Severity::Medium, "consensus exists → medium");
        assert!(r.geo.has_consensus);
        assert_eq!(r.geo.outliers, 1);
        assert!(r.geo.max_spread_km > 1000.0);
        assert!(f.examples.iter().any(|e| e.contains("45.5019")));
    }

    #[test]
    fn geo_consensus_produces_no_finding() {
        let ents = vec![
            ent("coordinates", "35.4137,-114.1762", 0.6, 1, &[]),
            ent("coordinates", "35.4200,-114.1800", 0.6, 2, &[]),
        ];
        let r = audit(&ents, LogSignals::default());
        assert!(!r.findings.iter().any(|f| f.category == "geo-divergence"));
        assert_eq!(r.geo.coord_count, 2);
        assert!(r.geo.max_spread_km < 50.0);
    }

    #[test]
    fn noise_ratio_and_tiers_are_computed() {
        let ents = vec![
            ent("username", "real", 1.0, 2, &[]),
            ent("username", "junk1", 0.3, 1, &[]),
            ent("username", "junk2", 0.3, 1, &[]),
        ];
        let r = audit(&ents, LogSignals::default());
        assert_eq!(r.tiers, (1, 0, 2));
        assert!((r.noise_ratio - 2.0 / 3.0).abs() < 1e-9);
    }
}
