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
            severity: if n >= 5 { Severity::Critical } else { Severity::High },
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
        missed.push("identity present but no phone or location — geo/contact enrichment thin".into());
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
            severity: if total >= 10 { Severity::Medium } else { Severity::Low },
            category: "module-errors",
            message: format!("{total} module error(s) across {} module(s)", log.module_errors.len()),
            examples: examples(ex),
            recommendation: "Inspect each erroring module — API change, rate limit, or missing \
                key. Errors silently shrink coverage."
                .into(),
        });
    }

    // ── Score ────────────────────────────────────────────────────────────────
    let penalty: u32 = findings.iter().map(|f| f.severity.penalty()).sum();
    let score = 100u32.saturating_sub(penalty);

    // Most-severe findings first, then by category for stable output.
    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.category.cmp(b.category)));

    AuditReport {
        entity_total,
        by_kind,
        tiers: (verified, probable, candidate),
        noise_ratio,
        findings,
        score,
        log,
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
        assert!(r.score >= 90, "clean scan should score high, got {}", r.score);
        assert!(
            !r.findings.iter().any(|f| f.category == "infrastructure-pollution"),
            "no infra in a clean scan"
        );
    }

    #[test]
    fn infrastructure_pollution_is_flagged_critical() {
        // The exact failure from the real screenshots.
        let ents = vec![
            ent("ip_address", "172.66.147.185", 1.0, 258, &["cloudflare", "hosting"]),
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
        assert!(r.score < 80, "infra pollution must hurt the score, got {}", r.score);
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
    fn missed_pii_when_email_but_no_person() {
        let ents = vec![ent("email", "x@y.com", 1.0, 2, &[])];
        let r = audit(&ents, LogSignals::default());
        assert!(r.findings.iter().any(|f| f.category == "missed-pii"));
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
