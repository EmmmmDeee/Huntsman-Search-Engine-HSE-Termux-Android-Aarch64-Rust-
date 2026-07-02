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
            "    confidence={:.2}  c_eff={:.2}  corroboration={}  class={}",
            e.confidence,
            e.c_effective(),
            e.corroboration,
            e.classify()
        );
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
            let _ = writeln!(s, "    ├─ [{}] {}", ev.source, ev.summary);
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
        // Pretty-print the verbatim body, indented, so the whole response —
        // every record, every field — is in the dossier with nothing elided.
        let pretty =
            serde_json::to_string_pretty(&resp.raw).unwrap_or_else(|_| resp.raw.to_string());
        for line in pretty.lines() {
            let _ = writeln!(s, "    {line}");
        }
    }

    Ok(s)
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
    s.push_str(&super::environment::render_environment());

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

    // Best AU geolocation fix (AU-059 cross-seed synergy), if one fired.
    // Recomputed structurally from the scan's confirmed entities (the set the
    // rule ran on — candidates quarantined), not parsed from the finding prose.
    let mut fix_entities = store.entities_for_scan(sid)?;
    fix_entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    let fix = crate::api::scan_export::extract_au_location_fix(&correlations, &fix_entities);
    if fix != serde_json::Value::Null {
        let lat = fix["lat"].as_f64().unwrap_or(0.0);
        let lon = fix["lon"].as_f64().unwrap_or(0.0);
        let gh = fix["geohash"].as_str().unwrap_or("");
        let state = fix["state"].as_str().unwrap_or("");
        let sc = fix["synergy_confidence"].as_f64().unwrap_or(0.0);
        let sev = fix["severity"].as_str().unwrap_or("");
        let _ = writeln!(
            s,
            "\n── BEST AU LOCATION FIX (AU-059) ──\n  {lat:.4},{lon:.4} · geohash={gh} · state={state} · synergy_conf={sc:.2} · severity={sev}"
        );
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

pub(super) fn render_report(store: &Store, sid: &str, include_infra: bool) -> Result<String> {
    // Default dossier hides quarantined `candidate` entities (non-target
    // breach-dump rows) — the confirmed-footprint view. They remain available
    // over HTTP via `report.json?include_candidates=1`.
    let report = crate::api::scan_export::build_scan_report(store as _, sid, false, include_infra)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    serde_json::to_string_pretty(&report)
        .map_err(|e| Error::Other(format!("report serialise: {e}")))
}
