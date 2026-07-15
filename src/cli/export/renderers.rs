//! Format renderers — JSON, CSV, GEXF, report, full dossier, debug bundle.

use crate::core::error::{Error, Result};
use crate::storage::Store;

/// A scan's entities with the quarantined `candidate` rows removed — the
/// subject's confirmed footprint. The breach co-occurrence "strangers" carry
/// the `candidate` tag and are non-subject PII; the structured exports
/// (`json`/`csv`/`gexf`) drop them by default so they match `report.json` and
/// the `/entities` API instead of leaking a foreign breach victim list under
/// the subject's scan. The COMPLETE, nothing-hidden set is still available via
/// `--format full` / `--format debug`.
fn confirmed_entities(store: &Store, sid: &str) -> Result<Vec<crate::core::entity::Entity>> {
    let mut entities = store.entities_for_scan(sid)?;
    entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    Ok(entities)
}

pub(super) fn render_json(store: &Store, sid: &str) -> Result<String> {
    let entities = confirmed_entities(store, sid)?;
    serde_json::to_string_pretty(&entities)
        .map_err(|e| Error::Other(format!("json serialise: {e}")))
}

pub(super) fn render_csv(store: &Store, sid: &str) -> Result<String> {
    let entities = confirmed_entities(store, sid)?;
    Ok(crate::api::scan_export::entities_to_csv(&entities))
}

pub(super) fn render_gexf(store: &Store, sid: &str) -> Result<String> {
    let entities = confirmed_entities(store, sid)?;
    let relations = store.relations_for_scan(sid)?;
    Ok(crate::core::gexf::entities_to_gexf(
        &entities, &relations, sid,
    ))
}

/// The **full dossier** — Huntsman's standard of maximum output detail. Emits
/// EVERY entity (including quarantined `candidate` rows — nothing is hidden),
/// each with its confidence/corroboration/tags and its COMPLETE evidence chain:
/// every attribute verbatim — the full raw source record, the provenance
/// (`provider`, `api_key_origin`, `via_endpoint`), and the source website/db —
/// nothing hashed, masked, truncated, or omitted. A leading provenance summary
/// lists every provider, API-key origin, and source seen. This is the on-disk
/// counterpart to the live dossier and the raw archive: the contract is total
/// transparency for a professional interpreter.
pub(crate) fn render_full(store: &dyn crate::core::port::StoragePort, sid: &str) -> Result<String> {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    let scan = store
        .get_scan(sid)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    let mut entities = store.entities_for_scan(sid)?;
    let relations = store.relations_for_scan(sid)?;
    let correlations = store.correlations_for_scan(sid)?;
    // Stable, readable grouping: by kind, then value.
    entities.sort_by(|a, b| {
        a.kind
            .to_string()
            .cmp(&b.kind.to_string())
            .then_with(|| a.value.cmp(&b.value))
    });

    // Provenance roll-up across every evidence record.
    let mut providers: BTreeSet<String> = BTreeSet::new();
    let mut key_origins: BTreeSet<String> = BTreeSet::new();
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for e in &entities {
        for ev in &e.evidence {
            if let Some(p) = ev.attributes.get("provider") {
                providers.insert(p.clone());
            }
            if let Some(k) = ev.attributes.get("api_key_origin") {
                key_origins.insert(k.clone());
            }
            for sk in ["source", "source_db", "dbname"] {
                if let Some(v) = ev.attributes.get(sk).filter(|v| !v.is_empty()) {
                    sources.insert(v.clone());
                }
            }
        }
    }

    let mut s = String::new();
    let _ = writeln!(s, "═══════════════════════════════════════════════════════");
    let _ = writeln!(s, "HUNTSMAN FULL DOSSIER — complete, unredacted");
    let _ = writeln!(s, "═══════════════════════════════════════════════════════");
    let _ = writeln!(s, "scan id    : {}", scan.id);
    let _ = writeln!(
        s,
        "target     : {} = {}",
        scan.target.kind.canonical_str(),
        scan.target.value
    );
    let _ = writeln!(s, "status     : {:?}", scan.status);
    let _ = writeln!(s, "entities   : {}", entities.len());
    let _ = writeln!(s, "relations  : {}", relations.len());

    // Exposure Index — the calibrated 0–100 headline with its transparent
    // per-signal breakdown, mirroring the live dossier (`print_dossier`) so the
    // on-disk/debug artifact opens with the same operator-facing verdict. Note
    // `assess` excludes candidate rows and sub-floor speculation internally, so
    // this matches what the operator saw live even though the dossier below lists
    // every (incl. candidate) entity unredacted.
    let exposure = crate::core::exposure::assess(&entities, &correlations);
    let _ = writeln!(s, "\n── EXPOSURE INDEX ──");
    let _ = writeln!(s, "  {}", exposure.summary_line());
    for c in &exposure.components {
        let _ = writeln!(
            s,
            "    · {:<22} {:>2}/{:<2}  {}",
            c.name, c.score, c.max, c.detail
        );
    }

    let _ = writeln!(s, "\n── PROVENANCE ──");
    let _ = writeln!(
        s,
        "providers      : {}",
        super::dossier::join_or_dash(providers.iter())
    );
    let _ = writeln!(
        s,
        "api key origins: {}",
        super::dossier::join_or_dash(key_origins.iter())
    );
    let _ = writeln!(
        s,
        "sources/sites  : {}",
        super::dossier::join_or_dash(sources.iter())
    );

    // Foreign API keys retrieved from endpoint data — surfaced up front because
    // a leaked third-party credential is the highest-signal finding in a scan.
    // These are ApiKey entities tagged `foreign-key`: recognised VENDOR keys
    // (Stripe, AWS, GitHub, PEM blocks, …) identified in any module's response,
    // with our own auth keys excluded. Bare breach password hashes are NOT here
    // (they appear as their own entities below). Full evidence is in ENTITIES.
    let foreign: Vec<&crate::core::entity::Entity> = entities
        .iter()
        .filter(|e| e.has_tag("foreign-key"))
        .collect();
    let _ = writeln!(s, "\n── FOREIGN API KEYS RETRIEVED ({}) ──", foreign.len());
    if foreign.is_empty() {
        let _ = writeln!(s, "  (none identified in this scan's responses)");
    }
    for e in &foreign {
        let attr = |k: &str| {
            e.evidence
                .iter()
                .find_map(|ev| ev.attributes.get(k).cloned())
                .unwrap_or_default()
        };
        let _ = writeln!(
            s,
            "  • [{}] {}  (from {} · query={} · seen {}×)",
            attr("service"),
            e.value,
            attr("source_provider"),
            attr("source_query"),
            attr("occurrences"),
        );
    }

    let _ = writeln!(s, "\n── ENTITIES (every field, fully unredacted) ──");
    for (i, e) in entities.iter().enumerate() {
        let _ = writeln!(s, "\n[{}] {} = {}", i + 1, e.kind, e.value);
        // "Nothing omitted" (see the module doc): the entity's own top-level
        // fields — the SHA-256 uid, the pre-normalisation raw_value, and the
        // decay timestamp — that `render_json`/CSV already carry but a human
        // reading the full dossier previously never saw. `raw_value` genuinely
        // diverges from `value` for Email/Username/Domain (case-folding, sigil
        // stripping, …), so it is real provenance, not noise.
        let _ = writeln!(
            s,
            "    uid={}  raw_value={}  observed_at={} ({})",
            e.uid,
            e.raw_value,
            e.observed_at,
            crate::util::timefmt::compact_utc(e.observed_at)
        );
        let _ = writeln!(
            s,
            "    confidence={:.2}  c_eff={:.2}  corroboration={}  source_count={}  class={}",
            e.confidence,
            e.c_effective(),
            e.corroboration,
            e.source_count(),
            e.classify()
        );
        // `corroboration` is a raw per-module observation magnitude (seeded by
        // the emitting module, summed on every merge, never deduplicated) — it
        // is NOT the count `c_eff` is actually computed from. The two often
        // read as the same kind of number side by side, which is exactly what
        // makes a merged multi-source entity's confidence look unexplained
        // without reading the source. Spell out the divergence here instead of
        // leaving the reader to reconcile it by hand — see the per-evidence
        // `(non-corroborating)` markers below for which sources counted.
        if e.corroboration != e.source_count() {
            let _ = writeln!(
                s,
                "    note: c_eff is driven by source_count={} (distinct \
                 corroborating sources), not corroboration={} (a separate raw \
                 per-module magnitude — does not by itself mean {} independent \
                 confirmations)",
                e.source_count(),
                e.corroboration,
                e.corroboration,
            );
        }
        if !e.tags.is_empty() {
            let _ = writeln!(s, "    tags: {}", e.tags.join(", "));
        }
        // The inline `attack:<ID>` provenance tags, resolved to their MITRE
        // ATT&CK Reconnaissance technique names — the technique(s) that collected
        // this finding, carried in the data itself (not a separate report).
        let mitre: Vec<String> = e
            .tags
            .iter()
            .filter_map(|t| t.strip_prefix("attack:"))
            .map(|id| {
                crate::core::attack::technique(id)
                    .map_or_else(|| id.to_string(), |t| format!("{} {}", t.id, t.name))
            })
            .collect();
        if !mitre.is_empty() {
            let _ = writeln!(s, "    MITRE ATT&CK: {}", mitre.join("; "));
        }
        for ev in &e.evidence {
            let marker = if crate::core::entity::is_non_corroborating_source(&ev.source) {
                "  (non-corroborating: enrichment/recall/cross-scan — doesn't count toward source_count)"
            } else {
                ""
            };
            let _ = writeln!(s, "    ├─ [{}] {}{marker}", ev.source, ev.summary);
            for (k, v) in &ev.attributes {
                if !v.is_empty() {
                    let _ = writeln!(s, "    │    {k} = {v}");
                }
            }
        }
    }

    if !relations.is_empty() {
        let _ = writeln!(s, "\n── RELATIONS ──");
        for r in &relations {
            let _ = writeln!(
                s,
                "  {} ──{}──▶ {}  (conf={:.2})",
                r.from_uid, r.kind, r.to_uid, r.confidence
            );
        }
    }

    // ── RAW SOURCE RECORDS ──────────────────────────────────────────────────
    // Embed every paid API response this scan fetched, verbatim, recovered from
    // the on-disk archive. This guarantees the dossier leaves NOTHING out — even
    // thin records that produced no entity (e.g. a breach hit with only a
    // `source`, or a paste listing hundreds of unrelated addresses) appear here
    // in full. The archive files remain saved separately; this is an embedded
    // copy for a self-contained dossier.
    //
    // Responses are tied to THIS scan precisely: the time window [started_at,
    // finished_at] excludes earlier runs of the same target, and the query-set
    // (target value + every entity value) excludes a neighbouring back-to-back
    // scan whose second-granular window touches this one. (A loose ±margin window
    // bled adjacent scans together — unix timestamps are per-second.)
    let start = scan.started_at;
    let end = scan.finished_at.unwrap_or(u64::MAX);
    let mut queries: std::collections::HashSet<String> = std::collections::HashSet::new();
    queries.insert(scan.target.value.to_lowercase());
    for e in &entities {
        queries.insert(e.value.to_lowercase());
    }
    let raws = crate::util::raw_archive::records_for_queries(&queries, start, end);
    let _ = writeln!(
        s,
        "\n── RAW SOURCE RECORDS ({} response{}, verbatim) ──",
        raws.len(),
        if raws.len() == 1 { "" } else { "s" }
    );
    if raws.is_empty() {
        let _ = writeln!(
            s,
            "  (raw archive empty for this window — disabled, or run predates archiving)"
        );
    }
    for resp in &raws {
        let _ = writeln!(
            s,
            "\n  ▼ {} · endpoint={} · query={} · file={}",
            resp.provider, resp.endpoint, resp.query, resp.filename
        );
        for line in render_raw_response_body(&resp.raw).lines() {
            let _ = writeln!(s, "    {line}");
        }
    }

    Ok(s)
}

/// Pretty-print one archived raw response for embedding in the dossier, with
/// any of the operator's OWN configured secret values masked (the same
/// `redact_credentials` pass module errors already run upstream echoes
/// through). The on-disk archive file itself (`raw/*.json`) is never touched —
/// per that module's own doc comment, retention there is a deliberate,
/// verbatim, never-redacted operator policy — this only guards the COPY
/// embedded here. That distinction matters because the auto-written dossier
/// is 0600, but an explicit `hse export -o <path>` is deliberately left to the
/// user's umask (see `PROBLEM_TREE` S3's own note), so an upstream provider
/// that happens to echo our request's `api_key=…` back in its response body
/// could otherwise ride an exported/shared dossier out to a world-readable
/// file.
fn render_raw_response_body(raw: &serde_json::Value) -> String {
    let pretty = serde_json::to_string_pretty(raw).unwrap_or_else(|_| raw.to_string());
    crate::util::http::redact_credentials(&pretty)
}

/// The **one-file debug bundle** — everything needed to understand and improve a
/// scan from a single artifact, with no black boxes. It concatenates:
///   0. the environment fingerprint ([`render_environment`](super::environment::render_environment)) — build/host, module
///      set, and key-PRESENCE (names only) the scan ran under;
///   1. the full dossier ([`render_full`]) — every entity, every evidence field,
///      provenance, foreign keys, and the verbatim raw source records;
///   2. the typed relation graph and correlator hits;
///   3. the COMPLETE scan sequence — every event (module start/done/error,
///      entity found, every admission/expansion exclusion with its reason,
///      expansion ticks/stops) as loss-less JSONL plus a per-type histogram, so
///      the exact order of operations and every decision is reconstructable;
///   4. the scored self-audit — score, every weakness finding with its
///      recommendation, the exclusion ledger, and the geo-consistency summary.
///
/// One `hse export <id> --format debug` (or the web "Debug bundle" button) yields
/// a single text file from which the whole run — sequence, results, and every
/// flaw — is understandable via logs alone.
pub(crate) fn render_debug_bundle(
    store: &dyn crate::core::port::StoragePort,
    sid: &str,
) -> Result<String> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let mut s = String::new();
    let _ = writeln!(
        s,
        "╔═══════════════════════════════════════════════════════╗"
    );
    let _ = writeln!(
        s,
        "║  HUNTSMAN DEBUG BUNDLE — complete scan snapshot         ║"
    );
    let _ = writeln!(
        s,
        "║  Self-contained: results, sequence, and every flaw.    ║"
    );
    let _ = writeln!(
        s,
        "╚═══════════════════════════════════════════════════════╝"
    );
    // DETERMINISM: the bundle body deliberately carries NO wall-clock generation
    // timestamp. For an immutable (completed) scan, two exports must be
    // byte-identical so the artifact can be `diff`ed across runs/tools/time —
    // the reproducibility the bundle exists to serve. The scan's own immutable
    // timestamps (event `ts`, entity `observed_at`) are already inside, and a
    // caller that needs the generation time can take it out-of-band (HTTP
    // `Date` header / shell). Guarded by `debug_bundle_is_deterministic`.

    // ── 0. Environment fingerprint (reconstructable scan context) ──
    s.push_str(&super::environment::render_environment(
        super::environment::curl_present(),
    ));

    // ── 1. Full dossier (entities/evidence/provenance/raw records) ──
    s.push_str(&render_full(store, sid)?);

    // ── 2. Correlator hits ──
    let correlations = store.correlations_for_scan(sid)?;
    let _ = writeln!(s, "\n── CORRELATIONS ({}) ──", correlations.len());
    if correlations.is_empty() {
        let _ = writeln!(s, "  (no correlator rules fired)");
    }
    // Rule histogram (rule_id × count, sorted by frequency) — surfaces, at a
    // glance, a single rule dominating the output (the permutation-flood failure
    // mode: a name seed firing one identity-bridge per email×username pair). It is
    // the fastest anomaly signal for a diagnosing tool (human or Claude): a rule
    // at a large share of the total is the first thing to investigate when a
    // dossier reads noisy. Deterministic (count desc, then rule_id asc).
    if !correlations.is_empty() {
        let mut by_rule: BTreeMap<String, (usize, String)> = BTreeMap::new();
        for c in &correlations {
            let e = by_rule
                .entry(c.rule_id.clone())
                .or_insert((0, c.rule_name.clone()));
            e.0 += 1;
        }
        let mut ranked: Vec<(String, usize, String)> = by_rule
            .into_iter()
            .map(|(id, (n, name))| (id, n, name))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let total = correlations.len().max(1);
        let _ = writeln!(
            s,
            "  rule histogram (rule_id  count  share — investigate any rule with an outsized share):"
        );
        for (id, n, name) in &ranked {
            let pct = (*n as f64) * 100.0 / (total as f64);
            let _ = writeln!(s, "    {id:10} {n:>5}  {pct:>5.1}%  {name}");
        }
    }
    for c in &correlations {
        let _ = writeln!(
            s,
            "  • [{}] {} ({}) — {}  · entities: {}",
            c.rule_id,
            c.rule_name,
            c.severity,
            c.description,
            c.entity_uids.len()
        );
    }

    // Best AU geolocation fix, if one fired. `extract_au_location_fix` returns
    // one of two shapes: a true AU-059 cross-seed synergy fix (has
    // `synergy_confidence`) or a coarser single-signal fallback (has `confidence`
    // / `basis` instead) — see `dossier.rs`'s matching dual-branch render for the
    // reference pattern this mirrors. Branching on which shape actually fired
    // (rather than unconditionally labelling every fix "(AU-059)") matters
    // because the fallback can be a single hardcoded landline-area-code anchor,
    // not a corroborated synergy — mislabelling it AU-059 overstates its rigour.
    // Recomputed structurally from the scan's confirmed entities (the set the
    // rule ran on — candidates quarantined), not parsed from the finding prose.
    let mut fix_entities = store.entities_for_scan(sid)?;
    fix_entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    let fix = crate::api::scan_export::extract_au_location_fix(&correlations, &fix_entities);
    if fix != serde_json::Value::Null {
        let lat = fix["lat"].as_f64().unwrap_or(0.0);
        let lon = fix["lon"].as_f64().unwrap_or(0.0);
        let radius = fix["radius_km"].as_f64().unwrap_or(0.0);
        let gh = fix["geohash"].as_str().unwrap_or("");
        let state = fix["state"].as_str().unwrap_or("");
        if let Some(sc) = fix["synergy_confidence"].as_f64() {
            let sev = fix["severity"].as_str().unwrap_or("");
            let _ = writeln!(
                s,
                "\n── BEST AU LOCATION FIX (AU-059) ──\n  {lat:.4},{lon:.4} ± {radius:.1} km · geohash={gh} · state={state} · synergy_conf={sc:.2} · severity={sev}"
            );
        } else {
            let confidence = fix["confidence"].as_f64().unwrap_or(0.0);
            let basis = fix["basis"].as_str().unwrap_or("");
            let _ = writeln!(
                s,
                "\n── BEST AU LOCATION FIX (single-signal) ──\n  {lat:.4},{lon:.4} ± {radius:.1} km · geohash={gh} · state={state} · basis={basis} · confidence={confidence:.2}"
            );
        }
    }

    // ── 3. Complete scan sequence (every event) ──
    let events = store.events_for_scan(sid)?;
    let mut histo: BTreeMap<String, usize> = BTreeMap::new();
    for ev in &events {
        *histo
            .entry(ev.kind.event_type_str().to_string())
            .or_default() += 1;
    }
    let _ = writeln!(s, "\n── SCAN SEQUENCE ({} events) ──", events.len());
    let _ = writeln!(s, "  event histogram:");
    for (typ, n) in &histo {
        let _ = writeln!(s, "    {typ:30} {n}");
    }
    let _ = writeln!(
        s,
        "\n  full timeline (JSONL — one loss-less event per line, in order):"
    );
    if events.is_empty() {
        let _ = writeln!(
            s,
            "  (no events recorded — event persistence disabled, or an import not a live scan)"
        );
    }
    for ev in &events {
        // Loss-less, greppable: timestamp + the entire serialised event.
        let json = serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
        let _ = writeln!(s, "  {} {}", ev.ts, json);
    }

    // ── 4. Scored self-audit (every weakness + recommendation) ──
    let entities = store.entities_for_scan(sid)?;
    let normalised: Vec<crate::audit::AuditEntity> = entities
        .iter()
        .map(crate::audit::AuditEntity::from_entity)
        .collect();
    let mut signals = crate::audit::LogSignals::default();
    crate::audit::fold_events(&mut signals, &events);
    let report = crate::audit::audit(&normalised, signals);

    let _ = writeln!(s, "\n── SELF-AUDIT ──");
    let _ = writeln!(
        s,
        "  score      : {}/100 ({})",
        report.score,
        report.grade()
    );
    let _ = writeln!(
        s,
        "  tiers      : {} verified · {} probable · {} candidate · {:.0}% noise",
        report.tiers.0,
        report.tiers.1,
        report.tiers.2,
        report.noise_ratio * 100.0
    );
    if report.quarantined > 0 {
        let _ = writeln!(
            s,
            "  quarantined: {} breach co-occurrence row(s) — non-subject, excluded from \
             the correlator, the grade, and the default views/exports (report, json, \
             csv, gexf); retained in this full bundle for transparency",
            report.quarantined
        );
    }
    if report.geo.coord_count > 0 {
        let _ = writeln!(
            s,
            "  geo        : {} fix(es) / {} source(s) · spread {:.0} km · {}{}",
            report.geo.coord_count,
            report.geo.source_count,
            report.geo.max_spread_km,
            if report.geo.has_consensus {
                "consensus"
            } else {
                "NO consensus"
            },
            if report.geo.outliers > 0 {
                format!(" · {} outlier(s)", report.geo.outliers)
            } else {
                String::new()
            },
        );
    }
    if !report.log.excluded_reasons.is_empty() {
        let ledger: Vec<String> = report
            .log
            .excluded_reasons
            .iter()
            .map(|(r, n)| format!("{r}×{n}"))
            .collect();
        let _ = writeln!(s, "  exclusions : {}", ledger.join(", "));
    }
    let _ = writeln!(s, "\n  FINDINGS ({}):", report.findings.len());
    if report.findings.is_empty() {
        let _ = writeln!(s, "    ✓ no weaknesses detected");
    }
    for f in &report.findings {
        let _ = writeln!(
            s,
            "\n    [{}] {} — {}",
            f.severity.as_str(),
            f.category,
            f.message
        );
        for ex in &f.examples {
            let _ = writeln!(s, "        • {ex}");
        }
        let _ = writeln!(s, "        → {}", f.recommendation);
    }

    // ── 5. Source-file manifest (every file the binary was built from) ──
    // Incorporates ALL files, not just runtime modules: a build fingerprint that
    // makes the codebase the binary carries fully accountable from the artifact.
    // Deterministic (build.rs emits it sorted by path).
    let _ = writeln!(
        s,
        "\n── SOURCE FILES ({} files, {} LOC) ──",
        crate::source_manifest::SOURCE_FILES.len(),
        crate::source_manifest::SOURCE_TOTAL_LINES,
    );
    for (path, lines) in crate::source_manifest::SOURCE_FILES {
        let _ = writeln!(s, "  {lines:>6}  {path}");
    }

    Ok(s)
}

// ═══════════════════════════════════════════════════════════════════════════
// System self-diagnosis bundle — the whole engine's health in ONE artifact.
//
// The per-scan `render_debug_bundle` above answers "what happened in THIS
// scan?". This answers the orthogonal, engine-level question the operator (or
// Claude Code) actually asks when HSE itself misbehaves: "what is wrong with
// the install, right now, and where do I look?" — by joining every otherwise-
// fragmented diagnostic surface (the scattered `/health`, `/selftest`,
// `/modules/health`, `/engines/health`, `/health/scrapers`, `/logs` endpoints)
// into one downloadable, self-diagnosing file, led by an auto-computed
// DETECTED ISSUES verdict.
// ═══════════════════════════════════════════════════════════════════════════

/// A single automatically-detected problem for the bundle's headline DETECTED
/// ISSUES section — what makes the artifact *self*-diagnosing rather than a raw
/// dump. Ordered CRITICAL-first when rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetectedIssue {
    /// [`SEV_CRITICAL`] (a hard failure that stops real work) or
    /// [`SEV_WARNING`] (a degradation worth investigating).
    pub severity: &'static str,
    pub category: &'static str,
    pub detail: String,
}

/// `"CRITICAL"` — a hard failure: a failed core self-test check, or missing
/// `curl` (which silently disables `search_engines`/`social_probe`/`oathnet`).
pub(crate) const SEV_CRITICAL: &str = "CRITICAL";
/// `"WARNING"` — a live degradation (a module/engine/scraper failing streak, a
/// silently-zero-yield source, a stored failed scan) that still leaves the
/// engine running.
pub(crate) const SEV_WARNING: &str = "WARNING";

/// Primitive-only inputs to [`detect_issues`], deliberately free of domain
/// structs so the "what counts as a problem" policy is unit-testable from
/// literals. The renderer does the trivial extraction from the live `Report`
/// and health snapshots.
pub(crate) struct IssueInputs<'a> {
    pub selftest_ok: bool,
    /// `(check name, detail)` for every self-test check that FAILED.
    pub selftest_failures: Vec<(&'a str, &'a str)>,
    pub curl_present: bool,
    /// `(module, consecutive_failures)` — live per-process failure streaks.
    pub unhealthy_modules: Vec<(&'a str, u32)>,
    pub engines_down: Vec<&'a str>,
    pub engines_blocked: Vec<&'a str>,
    /// `(module, consecutive_failures)` — cross-scan persisted hard-failure drift.
    pub scrapers_drifted: Vec<(&'a str, u32)>,
    /// modules whose recent completions all silently returned zero results.
    pub scrapers_yield_drifted: Vec<&'a str>,
    /// count of stored scans whose status is `failed`.
    pub failed_scans: usize,
    /// keyed-provider budgets whose daily/session quota is exhausted right now —
    /// the reason a keyed module returns nothing until the quota resets.
    pub quota_exhausted_providers: Vec<&'a str>,
}

/// Join every health signal into one worst-first problem list. **Pure** (no
/// I/O), so the classification policy is unit-testable off fixtures; a fully
/// healthy engine yields an empty vec (rendered as an explicit "no issues
/// auto-detected"). Deterministic ordering (severity, then category, then
/// detail) so two bundles over identical state produce an identical verdict.
pub(crate) fn detect_issues(inp: &IssueInputs) -> Vec<DetectedIssue> {
    let mut issues: Vec<DetectedIssue> = Vec::new();
    // A failed self-test check is the strongest signal — a fundamental
    // subsystem (registry / dispatch / core math / storage) is broken.
    if !inp.selftest_ok {
        for (name, detail) in &inp.selftest_failures {
            issues.push(DetectedIssue {
                severity: SEV_CRITICAL,
                category: "self-test",
                detail: format!("check `{name}` FAILED: {detail}"),
            });
        }
    }
    if !inp.curl_present {
        issues.push(DetectedIssue {
            severity: SEV_CRITICAL,
            category: "environment",
            detail: "curl is MISSING — search_engines/social_probe/oathnet return \
                     nothing; install with `pkg install curl`"
                .to_string(),
        });
    }
    for (name, streak) in &inp.unhealthy_modules {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "module-health",
            detail: format!(
                "module `{name}` has failed its last {streak} dispatch(es) this process"
            ),
        });
    }
    for name in &inp.engines_down {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "search-engine",
            detail: format!("search engine `{name}` is DOWN (unreachable)"),
        });
    }
    for name in &inp.engines_blocked {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "search-engine",
            detail: format!(
                "search engine `{name}` is BLOCKED (captcha / rate-limit / parser defect)"
            ),
        });
    }
    for (name, streak) in &inp.scrapers_drifted {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "scraper-drift",
            detail: format!(
                "source `{name}` has failed its last {streak} completion(s) across scans"
            ),
        });
    }
    for name in &inp.scrapers_yield_drifted {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "scraper-yield-drift",
            detail: format!(
                "source `{name}` completes without error but has silently stopped finding anything"
            ),
        });
    }
    if inp.failed_scans > 0 {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "scans",
            detail: format!(
                "{} stored scan(s) ended in `failed` — see the RECENT SCANS section for each error",
                inp.failed_scans
            ),
        });
    }
    for name in &inp.quota_exhausted_providers {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "provider-quota",
            detail: format!(
                "provider `{name}` quota is exhausted — its keyed modules return nothing until it resets"
            ),
        });
    }
    issues.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.category.cmp(b.category))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    issues
}

/// CRITICAL sorts before WARNING; any unknown label sorts last.
fn severity_rank(sev: &str) -> u8 {
    match sev {
        SEV_CRITICAL => 0,
        SEV_WARNING => 1,
        _ => 2,
    }
}

/// The gathered-off-reactor inputs for [`render_system_debug_bundle`]. The
/// async / store-bound parts (the self-test, the recent-scan list, the
/// cross-scan scraper-outcome events, and the in-memory log ring) are fetched
/// by the caller — the HTTP handler or a CLI command — and handed in; the
/// renderer reads only cheap, synchronous process-global state (version,
/// registry, live health snapshots, source manifest) inline.
pub(crate) struct SystemDebugInputs {
    pub selftest: crate::selftest::Report,
    pub scans: Vec<crate::core::scan::Scan>,
    pub scraper_health: Vec<crate::util::scraper_health::SourceHealth>,
    pub scraper_events_checked: usize,
    pub log_dump: String,
    pub log_lines: usize,
}

/// Render the consolidated **system self-diagnosis bundle**: one artifact that
/// encompasses the whole engine's diagnostic + validation state — a headline
/// auto-computed DETECTED ISSUES verdict, the environment fingerprint, the full
/// self-test (validation), live + cross-scan module / engine / scraper health,
/// the recent-scan index (each failed scan's error inline), the recent verbose
/// log ring, and the source-file manifest — organised so the engine can be
/// repaired from this one file.
///
/// Unlike the per-scan [`render_debug_bundle`], this is a LIVE snapshot: it
/// carries logs and a headline health read that change moment to moment, so it
/// is deliberately NOT byte-deterministic across time (the [`detect_issues`]
/// ordering and every section's internal ordering ARE deterministic, so two
/// bundles taken in the same instant diff cleanly). Secret-free by construction
/// — the environment section prints key NAMES only, never values — but the
/// caller still gates it to loopback because the log ring can contain scan
/// targets / discovered PII.
pub(crate) fn render_system_debug_bundle(inp: &SystemDebugInputs) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "╔═══════════════════════════════════════════════════════╗"
    );
    let _ = writeln!(
        s,
        "║  HUNTSMAN SYSTEM DEBUG BUNDLE — full engine self-diag   ║"
    );
    let _ = writeln!(
        s,
        "║  One file: what's wrong, the proof, and every module.  ║"
    );
    let _ = writeln!(
        s,
        "╚═══════════════════════════════════════════════════════╝"
    );

    // Live snapshots — cheap synchronous process-global reads.
    let module_health = crate::core::engine::module_health_report();
    let engines = crate::modules::search_engines::health::cached_or_empty();
    use crate::modules::search_engines::health::EngineStatus;
    let engines_down: Vec<&str> = engines
        .engines
        .iter()
        .filter(|h| h.status == EngineStatus::Down)
        .map(|h| h.name)
        .collect();
    let engines_blocked: Vec<&str> = engines
        .engines
        .iter()
        .filter(|h| h.status == EngineStatus::Blocked)
        .map(|h| h.name)
        .collect();
    let curl_present = super::environment::curl_present();
    let failed_scans = inp
        .scans
        .iter()
        .filter(|sc| sc.status.as_str() == "failed")
        .count();
    // Keyed-provider quota budgets (the same snapshots `/stats` serves). WiGLE
    // splits into four independent sub-budgets. A `quota_exhausted` flag is why
    // that provider's keyed modules currently return nothing.
    let provider_budgets: Vec<(&str, crate::util::budget::BudgetSnapshot)> = {
        let w = crate::modules::wigle::budget_snapshot();
        vec![
            ("seeknow", crate::util::see_know::budget_snapshot()),
            ("oathnet", crate::util::oathnet::budget_snapshot()),
            ("wigle:geo", w.geo),
            ("wigle:bssid", w.bssid),
            ("wigle:cell", w.cell),
            ("wigle:bluetooth", w.bluetooth),
        ]
    };
    let quota_exhausted: Vec<&str> = provider_budgets
        .iter()
        .filter(|(_, b)| b.quota_exhausted)
        .map(|(n, _)| *n)
        .collect();

    // ── 0. DETECTED ISSUES — the self-diagnosing verdict, read first ──
    let issues = detect_issues(&IssueInputs {
        selftest_ok: inp.selftest.ok,
        selftest_failures: inp
            .selftest
            .checks
            .iter()
            .filter(|c| c.status == crate::selftest::Status::Fail)
            .map(|c| (c.name.as_str(), c.detail.as_str()))
            .collect(),
        curl_present,
        unhealthy_modules: module_health
            .iter()
            .map(|h| (h.name, h.consecutive_failures))
            .collect(),
        engines_down: engines_down.clone(),
        engines_blocked: engines_blocked.clone(),
        scrapers_drifted: inp
            .scraper_health
            .iter()
            .filter(|h| h.is_drifted())
            .map(|h| (h.module.as_str(), h.consecutive_failures))
            .collect(),
        scrapers_yield_drifted: inp
            .scraper_health
            .iter()
            .filter(|h| h.is_yield_drifted())
            .map(|h| h.module.as_str())
            .collect(),
        failed_scans,
        quota_exhausted_providers: quota_exhausted.clone(),
    });
    let (crit, warn) = issues.iter().fold((0usize, 0usize), |(c, w), i| {
        if i.severity == SEV_CRITICAL {
            (c + 1, w)
        } else {
            (c, w + 1)
        }
    });
    let _ = writeln!(
        s,
        "\n── DETECTED ISSUES ({crit} critical, {warn} warning) ──"
    );
    if issues.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no issues auto-detected — self-test OK, no module/engine/scraper drift, \
             no failed scans"
        );
    }
    for i in &issues {
        let _ = writeln!(s, "  [{}] {}: {}", i.severity, i.category, i.detail);
    }

    // ── 1. Environment fingerprint (build / host / module set / key presence) ──
    // Reuse the `curl_present` already computed for the verdict — one spawn, not two.
    s.push_str(&super::environment::render_environment(curl_present));

    // ── 1b. Disabled capabilities (operator toggles) — the single most direct
    //        answer to "why didn't module/feature X run?" that isn't a bug: an
    //        operator turned it off in `~/.huntsman/settings.json`. ──
    let disabled_modules: Vec<&'static str> = {
        let reg = crate::modules::registry();
        let mut v: Vec<&'static str> = reg
            .iter()
            .map(|m| m.name())
            .filter(|n| !crate::util::settings::get_bool(&format!("module.{n}"), true))
            .collect();
        v.sort_unstable();
        v
    };
    let disabled_features: Vec<String> = crate::util::settings::feature_toggles()
        .into_iter()
        .filter(|(_, on)| !on)
        .map(|(k, _)| k)
        .collect();
    // Search-engine toggles too — a disabled engine silently never dispatches,
    // exactly the "why did search find nothing?" question. Keys are already
    // `engine.<name>`; strip the prefix for a clean roster.
    let mut disabled_engines: Vec<String> = crate::modules::search_engines::engine_toggles()
        .into_iter()
        .filter(|(_, on)| !on)
        .map(|(k, _)| k.strip_prefix("engine.").map_or(k.clone(), str::to_string))
        .collect();
    disabled_engines.sort_unstable();
    let _ = writeln!(
        s,
        "\n── DISABLED CAPABILITIES ({} module(s), {} engine(s), {} feature(s) turned OFF) ──",
        disabled_modules.len(),
        disabled_engines.len(),
        disabled_features.len()
    );
    if disabled_modules.is_empty() && disabled_engines.is_empty() && disabled_features.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ nothing disabled — every module, engine, and feature is enabled"
        );
    }
    if !disabled_modules.is_empty() {
        let _ = writeln!(s, "  modules OFF : {}", disabled_modules.join(", "));
    }
    if !disabled_engines.is_empty() {
        let _ = writeln!(s, "  engines OFF : {}", disabled_engines.join(", "));
    }
    if !disabled_features.is_empty() {
        let _ = writeln!(s, "  features OFF: {}", disabled_features.join(", "));
    }

    // ── 2. Validation — the full self-test suite (`hse selftest`) ──
    let _ = writeln!(s, "\n── VALIDATION (SELF-TEST) ──");
    let _ = writeln!(s, "  {}", inp.selftest.summary());
    s.push_str(&inp.selftest.render());
    s.push('\n');

    // ── 3. Live per-process module health (failure streaks) ──
    let _ = writeln!(
        s,
        "\n── MODULE HEALTH (live, this process — {} with a failure streak) ──",
        module_health.len()
    );
    if module_health.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no module is currently showing a dispatch-failure streak"
        );
    }
    for h in &module_health {
        let last = h
            .last_success_at
            .map_or_else(|| "never this process".to_string(), |t| t.to_string());
        let _ = writeln!(
            s,
            "  {:<28} {} consecutive failure(s) · last success: {}",
            h.name, h.consecutive_failures, last
        );
    }

    // ── 4a. Search-engine liveness (latest cached sweep) ──
    let _ = writeln!(
        s,
        "\n── SEARCH-ENGINE LIVENESS (checked_at={}, {} engines: {} down, {} blocked) ──",
        engines.checked_at,
        engines.engines.len(),
        engines_down.len(),
        engines_blocked.len()
    );
    if engines.engines.is_empty() {
        let _ = writeln!(
            s,
            "  (no sweep cached yet — start `hse serve`/`hse engines` to populate)"
        );
    }
    for h in &engines.engines {
        let _ = writeln!(
            s,
            "  {:<14} {:<8} {:>5} ms · {} result(s) · {}",
            h.name,
            h.status.as_str(),
            h.latency_ms,
            h.results,
            h.detail
        );
    }

    // ── 4b. Cross-scan scraper health (persisted drift) ──
    let drifted: Vec<_> = inp
        .scraper_health
        .iter()
        .filter(|h| h.is_drifted())
        .collect();
    let yield_drifted: Vec<_> = inp
        .scraper_health
        .iter()
        .filter(|h| h.is_yield_drifted())
        .collect();
    let _ = writeln!(
        s,
        "\n── SCRAPER HEALTH (cross-scan, {} tracked over {} events — {} drifted, {} yield-drifted) ──",
        inp.scraper_health.len(),
        inp.scraper_events_checked,
        drifted.len(),
        yield_drifted.len()
    );
    if drifted.is_empty() && yield_drifted.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no source is drifting (no hard-failure streaks, no silent zero-yield)"
        );
    }
    for h in &drifted {
        let err = h.last_error.as_deref().unwrap_or("(no message)");
        let _ = writeln!(
            s,
            "  [FAIL-DRIFT] {:<24} {} consecutive failure(s) · last error: {}",
            h.module, h.consecutive_failures, err
        );
    }
    for h in &yield_drifted {
        let _ = writeln!(
            s,
            "  [YIELD-DRIFT] {:<24} {} consecutive zero-yield completion(s)",
            h.module, h.consecutive_zero_yield
        );
    }

    // ── 4c. Keyed-provider quota budgets (why a keyed module returns nothing) ──
    let _ = writeln!(
        s,
        "\n── PROVIDER QUOTAS ({} exhausted) ──",
        quota_exhausted.len()
    );
    for (name, b) in &provider_budgets {
        let flag = if b.quota_exhausted {
            " · EXHAUSTED"
        } else {
            ""
        };
        let _ = writeln!(
            s,
            "  {:<16} scan {}/{} · session {}/{}{}",
            name, b.scan_used, b.scan_cap, b.session_used, b.session_cap, flag
        );
    }

    // ── 5. Recent scans (with each failed scan's error inline) ──
    let _ = writeln!(
        s,
        "\n── RECENT SCANS ({}, newest-first; pull /api/v1/scans/<id>/debug.txt for per-scan depth) ──",
        inp.scans.len()
    );
    if inp.scans.is_empty() {
        let _ = writeln!(s, "  (no scans stored yet)");
    }
    for sc in &inp.scans {
        let _ = writeln!(
            s,
            "  {}  {:<9} ents={} run={} err={} timeout={} cached={}  {:?}:{}",
            sc.id,
            sc.status.as_str(),
            sc.entity_count,
            sc.modules_run,
            sc.modules_errored,
            sc.modules_timed_out,
            sc.modules_cached,
            sc.target.kind,
            sc.target.value,
        );
        if let Some(err) = sc.error.as_deref().filter(|e| !e.is_empty()) {
            let _ = writeln!(s, "        error: {err}");
        }
    }

    // ── 6. Recent verbose logs (the in-memory TRACE ring) ──
    let _ = writeln!(
        s,
        "\n── RECENT LOGS ({} line(s) in the ring buffer) ──",
        inp.log_lines
    );
    if inp.log_dump.trim().is_empty() {
        let _ = writeln!(
            s,
            "  (log ring empty — capture installs with the server; a bare CLI run buffers little)"
        );
    } else {
        s.push_str(&inp.log_dump);
        if !inp.log_dump.ends_with('\n') {
            s.push('\n');
        }
    }

    // ── 7. Source-file manifest (build fingerprint — every file the binary carries) ──
    let _ = writeln!(
        s,
        "\n── SOURCE FILES ({} files, {} LOC) ──",
        crate::source_manifest::SOURCE_FILES.len(),
        crate::source_manifest::SOURCE_TOTAL_LINES,
    );
    for (path, lines) in crate::source_manifest::SOURCE_FILES {
        let _ = writeln!(s, "  {lines:>6}  {path}");
    }

    s
}

pub(super) fn render_report(store: &Store, sid: &str, include_infra: bool) -> Result<String> {
    // Default dossier hides quarantined `candidate` entities (non-target
    // breach-dump rows) — the confirmed-footprint view. They remain available
    // over HTTP via `report.json?include_candidates=1`.
    let report = crate::api::scan_export::build_scan_report(store as _, sid, false, include_infra)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    serde_json::to_string_pretty(&report)
        .map_err(|e| Error::Other(format!("report serialise: {e}")))
}

#[cfg(test)]
mod tests {
    use super::render_raw_response_body;

    #[test]
    fn raw_response_body_masks_an_echoed_api_key_but_keeps_the_rest() {
        // Regression: a raw archived response embedded verbatim in the
        // dossier could carry an upstream echo of our own request URL
        // (`api_key=…`) straight into an exported/shared file — the
        // auto-written dossier is 0600, but an explicit `hse export -o` is
        // deliberately left to the user's umask (PROBLEM_TREE S3), so this
        // was a real path for an operator's key to leave the device.
        let raw = serde_json::json!({
            "echo_request_url": "https://api.example.org/v1/x?api_key=SECRET123456&q=1",
            "result": "ok",
        });
        let rendered = render_raw_response_body(&raw);
        assert!(
            !rendered.contains("SECRET123456"),
            "the echoed key must be masked: {rendered}"
        );
        assert!(
            rendered.contains("api_key=***"),
            "masking must preserve the surrounding shape: {rendered}"
        );
        assert!(
            rendered.contains("\"result\": \"ok\""),
            "unrelated fields must survive untouched: {rendered}"
        );
    }
}
