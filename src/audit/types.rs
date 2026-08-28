//! Core types for the audit module.

use std::collections::BTreeMap;

/// One entity, normalised to the common shape shared by every input source.
#[derive(Debug, Clone)]
pub struct AuditEntity {
    pub kind: String,
    pub value: String,
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
    pub(super) fn penalty(self) -> u32 {
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
    /// Share of *actionable* entities that are either low-confidence candidates
    /// or provider/CDN infrastructure, 0.0–1.0. High-confidence infrastructure
    /// counts as noise too — it maps a provider's estate, not the subject — so
    /// this can never read 0% while the report also raises
    /// `infrastructure-pollution`. Deliberately-quarantined breach
    /// co-occurrence stays excluded from both numerator and denominator.
    pub noise_ratio: f64,
    /// Breach co-occurrence rows the breach modules deliberately quarantined
    /// (excluded from the scan view, the correlator/grade, and the default
    /// structured exports — report/json/csv/gexf; present only in the
    /// nothing-hidden `full`/`debug` bundle). Reported for visibility; NOT
    /// counted in `entity_total`, `tiers`, or `noise_ratio`.
    pub quarantined: usize,
    pub findings: Vec<Finding>,
    /// 0–100 — 100 is a clean, individualised, well-sourced scan.
    pub score: u32,
    pub log: LogSignals,
    /// Cross-source geolocation consistency.
    pub geo: GeoSummary,
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
            "quarantined": self.quarantined,
            "by_kind": by_kind,
            "findings": findings,
            "source_health": {
                "engines_down": self.log.engines_down,
                "engines_blocked": self.log.engines_blocked,
                "engine_parser_defects": self.log.engine_parser_defects,
                "module_errors": self.log.module_errors,
                "module_timeouts": self.log.module_timeouts,
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
