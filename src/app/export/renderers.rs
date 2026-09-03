//! Format renderers — JSON, CSV, GEXF, report, full dossier, debug bundle.

use crate::core::error::{Error, Result};
use crate::core::scan::Scan;
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

/// Why an export of this scan is only a PARTIAL view, or `None` when the scan
/// genuinely ran to completion.
///
/// Single source of truth for the completeness decision, so the dossier header
/// and the debug-bundle header can never disagree about whether an artifact is
/// whole (they phrase it differently, but they classify identically). An
/// export of an aborted / failed / still-running scan carries only the findings
/// produced before the stop, so branding it "complete" tells the operator the
/// absence of a finding is a real negative when it may just be work that never
/// happened — the one claim an evidentiary artifact must never make falsely.
///
/// A budget-truncated scan is exactly that case, and used to slip through: it
/// reaches [`ScanStatus::Complete`](crate::core::scan::ScanStatus::Complete) like any other, so classifying on status
/// alone branded it "complete" while its expansion had stopped with candidates
/// still queued. Taking the whole [`Scan`] closes that hole — see
/// [`StopReason`](crate::core::scan::StopReason).
///
/// Determinism: every input here is immutable once the scan is terminal
/// (`status` and `stop_reason` are both written once, at finalise), so this
/// keeps the debug bundle's byte-identical-across-exports contract.
fn partial_export_reason(scan: &Scan) -> Option<&'static str> {
    use crate::core::scan::ScanStatus;
    match scan.status {
        ScanStatus::Complete => scan
            .stop_reason
            .is_some_and(|r| r.truncated())
            .then_some("budget-truncated"),
        ScanStatus::Aborted => Some("aborted"),
        ScanStatus::Failed => Some("failed"),
        // A snapshot taken mid-flight is partial by construction: more findings
        // may still land after this byte was written.
        ScanStatus::Pending | ScanStatus::Running => Some("live"),
    }
}

pub(super) fn render_json(store: &Store, sid: &str, redact: bool) -> Result<String> {
    let mut entities = confirmed_entities(store, sid)?;
    if redact {
        crate::util::redact::redact_entities(&mut entities);
    }
    // Augment each entity object with its derived metrics so JSON consumers
    // don't have to re-implement the noisy-OR c_effective / source_count /
    // classification formulas themselves. The raw `confidence` and
    // `corroboration` fields are kept for backwards compatibility.
    let augmented: Vec<serde_json::Value> = entities
        .iter()
        .map(|e| {
            let mut v = serde_json::to_value(e)
                .map_err(|err| Error::Other(format!("entity serialise: {err}")))?;
            if let serde_json::Value::Object(ref mut m) = v {
                // Normalise `kind` to a plain string. serde's default
                // externally-tagged representation renders EntityKind's unit
                // variants as a bare string ("email") but the Other(String)
                // catch-all as {"other":"iban"} -- a JSON TYPE that silently
                // depends on which kind the entity happens to be. Other is
                // the real representation for IBANs, DIDs, nostr keys, and
                // more, so this is not an edge case. `to_string()` (the
                // Display impl) always yields a plain string ("other:iban")
                // and matches what CSV/GEXF already emit for the same field.
                m.insert("kind".into(), serde_json::json!(e.kind.to_string()));
                m.insert("c_effective".into(), serde_json::json!(e.c_effective()));
                m.insert("source_count".into(), serde_json::json!(e.source_count()));
                m.insert(
                    "classification".into(),
                    serde_json::json!(e.classify().as_str()),
                );
            }
            Ok(v)
        })
        .collect::<Result<Vec<_>>>()?;
    serde_json::to_string_pretty(&augmented)
        .map_err(|e| Error::Other(format!("json serialise: {e}")))
}

pub(super) fn render_csv(store: &Store, sid: &str, redact: bool) -> Result<String> {
    let mut entities = confirmed_entities(store, sid)?;
    if redact {
        crate::util::redact::redact_entities(&mut entities);
    }
    Ok(entities_to_csv(&entities))
}

/// Canonical CSV rendering for a scan's entities. Shared by the HTTP
/// endpoint `/api/v1/scans/{id}/entities.csv` and the `hse export
/// --format csv` CLI subcommand so both produce byte-identical
/// output — operators piping the two interchangeably can rely on
/// the column shape staying in sync.
pub(crate) fn entities_to_csv(entities: &[crate::core::entity::Entity]) -> String {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(192 + entities.len() * 192);
    // `evidence_urls` + `evidence` make every row self-verifiable: the operator
    // can follow the source links and read each module's finding without
    // reconstructing anything from the value alone. `source_count` +
    // `corroborating_sources` sit next to `corroboration` + `sources` for the
    // same reason: `corroboration` is a raw per-module observation magnitude
    // (summed on merge, never deduplicated) that does NOT drive `c_effective`
    // — `source_count` (distinct corroborating sources) does. Without both
    // numbers side by side, a reader has no way to tell from the CSV alone
    // whether a high `corroboration` reflects genuine independent agreement.
    // `uid` and `generation` are APPENDED (never inserted) so the header still
    // begins with the exact prefix `looks_like_hse_csv` sniffs for and every
    // by-name column lookup — the import and audit parsers both resolve columns
    // by header name — keeps working on older and newer files alike.
    // `uid` is the join key: it is what the JSON export, the debug bundle, the
    // Browse pane and the /entities/{uid} pivot endpoint all identify a finding
    // by, so without it a CSV row could only be matched back to the other
    // artifacts by string-matching kind+value. `generation` (hops from the seed)
    // travels with it for the same reason it was added to the bundle — it
    // separates a seed-adjacent finding from one three pivots out.
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,source_count,classification,observed_at,sources,corroborating_sources,evidence_urls,evidence,tags,uid,generation\n");
    for e in entities {
        let eff = e.c_effective();
        let source_count = e.source_count();
        let tier = e.classify().to_string();
        let mut sources: Vec<&str> = e.evidence_sources().into_iter().collect();
        sources.sort_unstable();
        let sources = sources.join("|");
        let mut corroborating: Vec<&str> = e.corroborating_sources().into_iter().collect();
        corroborating.sort_unstable();
        let corroborating_sources = corroborating.join("|");
        let tags = e.tags.join("|");

        // Distinct full URLs across all evidence (the verifiable links), and a
        // per-source summary trail of what each module actually found.
        let mut urls: Vec<&str> = Vec::new();
        for ev in &e.evidence {
            for key in ["url", "source_url", "profile_url", "permalink"] {
                if let Some(u) = ev.attributes.get(key)
                    && !u.is_empty()
                    && !urls.contains(&u.as_str())
                {
                    urls.push(u.as_str());
                }
            }
        }
        let evidence_urls = urls.join(" | ");
        // Append each evidence's full attribute record (the same `k = v` detail
        // the dossier renderer prints per evidence row) after its summary, so
        // the CSV's own self-verifiable promise holds for hard evidentiary
        // fields (a leaked DOB, a password hash, …) that a module recorded as
        // structured `attributes` rather than folding into prose. `BTreeMap`
        // iteration is already key-sorted, so output stays deterministic
        // without an extra sort.
        let evidence = e
            .evidence
            .iter()
            .map(|ev| {
                let attrs: Vec<String> = ev
                    .attributes
                    .iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                if attrs.is_empty() {
                    format!("[{}] {}", ev.source, ev.summary)
                } else {
                    format!("[{}] {} ({})", ev.source, ev.summary, attrs.join("; "))
                }
            })
            .collect::<Vec<_>>()
            .join(" || ");

        let _ = writeln!(
            body,
            "{},{},{},{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&e.kind.to_string()),
            csv_escape(&e.value),
            csv_escape(&e.raw_value),
            e.confidence,
            eff,
            e.corroboration,
            source_count,
            tier,
            e.observed_at,
            csv_escape(&sources),
            csv_escape(&corroborating_sources),
            csv_escape(&evidence_urls),
            csv_escape(&evidence),
            csv_escape(&tags),
            csv_escape(&e.uid),
            e.generation,
        );
    }
    body
}

/// RFC-4180 CSV field escaping with **formula-injection defanging**: a field
/// whose first byte is `= + - @ TAB CR` — or `'` itself, which is guarded too so
/// the escape stays invertible, see [`formula_guard`] — is prefixed with a `'`
/// so Excel / LibreOffice don't execute it as a formula on open (OWASP
/// CSV-injection), then any field containing `, " \n \r` is double-quoted with
/// embedded quotes doubled. Every cell in an exported scan CSV passes through
/// this.
pub(crate) fn csv_escape(s: &str) -> String {
    let body = formula_guard(s);
    if body.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body.into_owned()
    }
}

/// Neutralise a spreadsheet formula trigger at the start of a CSV field,
/// **without** applying RFC-4180 quoting.
///
/// A leading `=`/`+`/`-`/`@`/CR/TAB causes Excel and LibreOffice to interpret
/// the cell as a formula on file open — a hostile API response with
/// `first_name = "=cmd|'/c calc'!A1"` could otherwise turn an exported CSV into
/// RCE on the operator's workstation. Prepend a single quote to defang, per
/// OWASP guidance.
///
/// A leading apostrophe is ALSO guarded (doubled). Without that the escape
/// isn't invertible: a genuine value like `'=hunter` would export unchanged as
/// `'=hunter`, indistinguishable from a guarded `=hunter`, and the import
/// reverse (`app::import::csv`'s `strip_csv_formula_guard`) would strip
/// its real apostrophe. By escaping any leading `'` too, this is a clean
/// bijection — export prepends `'` iff the first byte is a trigger OR `'`, and
/// import strips exactly one leading `'` — so every value round-trips
/// byte-for-byte at any nesting.
///
/// Split out of [`csv_escape`] so the two CSV writers in this crate can share
/// **one** guard while differing on who does the quoting. [`csv_escape`] quotes
/// by hand for the scan export; `cli::ingest` hands its fields to `csv::Writer`,
/// which RFC-4180-quotes them itself — passing them through `csv_escape` first
/// would double-quote. Returns [`std::borrow::Cow::Borrowed`] when no guard is
/// needed, which is the overwhelmingly common case (emails, IPs, domains,
/// hashes), so the shared guard costs no allocation on the hot path.
pub(crate) fn formula_guard(s: &str) -> std::borrow::Cow<'_, str> {
    let needs_guard = s
        .as_bytes()
        .first()
        .is_some_and(|b| matches!(*b, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' | b'\''));
    if needs_guard {
        std::borrow::Cow::Owned(format!("'{s}"))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

pub(super) fn render_gexf(store: &Store, sid: &str, redact: bool) -> Result<String> {
    let mut entities = confirmed_entities(store, sid)?;
    if redact {
        crate::util::redact::redact_entities(&mut entities);
    }
    let relations = store.relations_for_scan(sid)?;
    Ok(crate::core::gexf::entities_to_gexf(
        &entities, &relations, sid,
    ))
}

/// The **full dossier** — Huntsman's standard of maximum output detail. Emits
/// EVERY entity (including quarantined `candidate` rows — nothing is hidden),
/// each with its confidence/corroboration/tags, its `generation` (how many
/// pivots out from the seed it was found), and its COMPLETE evidence chain:
/// every attribute verbatim — the full raw source record, the provenance
/// (`provider`, `api_key_origin`, `via_endpoint`), and the source website/db —
/// nothing hashed, masked, truncated, or omitted. Each evidence record also
/// carries its own `recorded_at`, and the two qualifiers that decide how much
/// weight it deserves: `(inferred)` when it is a derivation rather than an
/// observation, and `verification` when it establishes account ownership. A
/// leading provenance summary lists every provider, API-key origin, and source
/// seen. This is the on-disk counterpart to the live dossier and the raw
/// archive: the contract is total transparency for a professional interpreter.
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
            let mut named_a_site = false;
            for sk in ["source", "source_db", "dbname"] {
                if let Some(v) = ev.attributes.get(sk).filter(|v| !v.is_empty()) {
                    sources.insert(v.clone());
                    named_a_site = true;
                }
            }
            // Fall back to the MODULE that produced the record. `provider`,
            // `source`, `source_db` and `dbname` are optional attributes only
            // the paid providers set, so a scan served entirely by free modules
            // rendered all three provenance lines as "(none)" — a section whose
            // whole job is to say where the data came from asserting that
            // nothing was known, while the evidence tree printed every module
            // by name a few lines below. `Evidence::source` is documented as
            // "Module that produced this evidence" and is always populated, so
            // it is the honest floor for this roll-up.
            if !named_a_site && !ev.source.is_empty() {
                sources.insert(ev.source.clone());
            }
        }
    }

    let mut s = String::new();
    let _ = writeln!(s, "═══════════════════════════════════════════════════════");
    let dossier_state = match partial_export_reason(&scan) {
        None => "complete, unredacted".to_string(),
        Some(reason) => format!("partial, {reason}, unredacted"),
    };
    let _ = writeln!(s, "HUNTSMAN FULL DOSSIER — {dossier_state}");
    let _ = writeln!(s, "═══════════════════════════════════════════════════════");
    let _ = writeln!(s, "scan id    : {}", scan.id);
    let _ = writeln!(
        s,
        "target     : {} = {}",
        scan.target.kind.canonical_str(),
        scan.target.value
    );
    let _ = writeln!(s, "status     : {:?}", scan.status);
    // WHY the expansion stopped, not just that the scan ended. Immutable once
    // terminal, so the bundle stays byte-identical across exports.
    if let Some(r) = scan.stop_reason {
        let _ = writeln!(s, "stopped    : {}", r.label());
    }
    let _ = writeln!(s, "entities   : {}", entities.len());
    let _ = writeln!(s, "relations  : {}", relations.len());
    // Full module accounting — including the timed-out/skipped/cached counts the
    // header historically dropped. A timed-out module is a stronger
    // incompleteness signal than a dedup, so total transparency requires it.
    let _ = writeln!(s, "modules    : {}", scan.module_accounting_line());
    // …and, for a scan that has not finalised, the live tally from the event
    // stream. `module_accounting_line` already discloses that its six columns
    // are unwritten before finalise; this is the number that IS available, so
    // an operator exporting mid-scan sees the work that has actually happened
    // instead of only being told the counters are empty. Queried solely on the
    // non-terminal path: a completed scan pays nothing, and its bundle stays
    // byte-identical across exports (the determinism contract in
    // `render_debug_bundle`) because no live-varying line is added to it.
    if !scan.status.is_terminal() {
        let tally = crate::core::event::ModuleEventTally::from_events(&store.events_for_scan(sid)?);
        if !tally.is_empty() {
            let _ = writeln!(
                s,
                "observed   : {}  (live, counted from this scan's event stream)",
                tally.summary_line()
            );
        }
    }

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
        // `generation` is the entity's pivot distance from the seed (0 = seed
        // itself, N = N hops out along its derivation trail). The web Browse
        // detail pane already shows it ("Generation: N hops from seed"), so a
        // bundle that advertises "every field" must not be the one artifact
        // that drops it — without it a finding two pivots deep is
        // indistinguishable from the operator's own input.
        let _ = writeln!(
            s,
            "    uid={}  raw_value={}  observed_at={} ({})  generation={}",
            e.uid,
            e.raw_value,
            e.observed_at,
            crate::util::timefmt::compact_utc(e.observed_at),
            e.generation
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
            // An INFERRED record is a derivation (a name permuted from a
            // username, coordinates computed from an address), not something
            // anyone observed. That distinction decides how much the reader
            // should trust the line, so it belongs in the line itself — the
            // bundle previously rendered inferences and direct observations
            // identically.
            let inferred = if ev.is_inferred { "  (inferred)" } else { "" };
            let _ = writeln!(s, "    ├─ [{}] {}{marker}{inferred}", ev.source, ev.summary);
            // Per-evidence provenance the entity-level `observed_at` cannot
            // convey: WHEN this particular record was taken, and (for account
            // attributions) HOW ownership was established. `verification` gates
            // the correlator's account-attribution rules, so showing it is what
            // lets a reader audit why an account was tied to the subject.
            let _ = writeln!(
                s,
                "    │    recorded_at = {} ({})",
                ev.recorded_at,
                crate::util::timefmt::compact_utc(ev.recorded_at)
            );
            if let Some(v) = ev.verification {
                let _ = writeln!(s, "    │    verification = {v:?}");
            }
            for (k, v) in &ev.attributes {
                if !v.is_empty() {
                    let _ = writeln!(s, "    │    {k} = {v}");
                }
            }
        }
    }

    if !relations.is_empty() {
        // Resolve each endpoint UID to `value (kind)` so the relation graph is
        // legible in the primary human dossier (mirrors print_dossier /
        // scan_relations) instead of opaque hex→hex. render_full carries EVERY
        // entity (candidates included), so endpoints resolve; the short-uid stub
        // is a defensive fallback only. Lookup-only map (never iterated) — output
        // stays byte-deterministic. UIDs are hex ASCII, so the slice is byte-safe.
        let by_uid: std::collections::HashMap<&str, &crate::core::entity::Entity> =
            entities.iter().map(|e| (e.uid.as_str(), e)).collect();
        let label = |uid: &str| {
            super::relation_endpoint_label(&by_uid, uid, |e| format!("{} ({})", e.value, e.kind))
        };
        let _ = writeln!(s, "\n── RELATIONS ──");
        for r in &relations {
            let _ = writeln!(
                s,
                "  {} ──{}──▶ {}  (conf={:.2})",
                label(&r.from_uid),
                r.kind,
                label(&r.to_uid),
                r.confidence
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

/// Render the complete scan event sequence as **structured JSON lines** — one
/// JSON object per event, in order, via
/// [`Event::to_log_line`](crate::core::event::Event::to_log_line): `{"time":…,
/// "level":…,"kind":…, …fields}` with no box-drawing, tree, or status glyphs, so
/// the log is both machine-parseable (one object per line) and clean to read.
/// Pure (no storage I/O) so callers fetch `events` once via
/// [`StoragePort::events_for_scan`](crate::core::port::StoragePort::events_for_scan)
/// and pass the slice in — shared by [`render_debug_bundle`]'s §3 and the
/// standalone HTTP download endpoint `api::scan_export::scan_events_log`
/// (`GET /api/v1/scans/{id}/events.log`), so the two never drift apart. Every
/// event and its exact ordering is preserved; only the raw JSON envelope is
/// dropped in favour of the readable line — the full per-entity detail already
/// lives in the debug bundle's dossier section, and the machine-readable events
/// remain available verbatim from `GET /api/v1/scans/{id}/events.history`.
pub(crate) fn render_event_log(events: &[crate::core::event::Event]) -> String {
    use std::fmt::Write as _;

    let mut s = String::new();
    for ev in events {
        let _ = writeln!(s, "{}", ev.to_log_line());
    }
    s
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
///      expansion ticks/stops) as a readable, aligned per-event timeline plus a
///      per-type breakdown, so the exact order of operations and every decision
///      is reconstructable at a glance;
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

    let scan = store
        .get_scan(sid)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    let snapshot_state = match partial_export_reason(&scan) {
        None => "complete scan snapshot".to_string(),
        Some(reason) => format!("partial {reason} scan snapshot"),
    };
    let mut s = String::new();
    let _ = writeln!(s, "=== HUNTSMAN DEBUG BUNDLE — {snapshot_state} ===");
    let _ = writeln!(s, "Self-contained: results, sequence, and every flaw.");
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
        // `rank` (severity × max child C_eff) is what `correlations_for_scan`
        // sorts this list by, and the web Correlations view prints it beside
        // each hit. Showing it here too means a reader of the bundle can
        // explain the ordering they are looking at instead of inferring it —
        // and can see when a LOW-severity rule outranks a MEDIUM one because
        // its child entities are far better corroborated.
        let _ = writeln!(
            s,
            "  • [{}] {} ({}, rank {:.2}) — {}  · entities: {}",
            c.rule_id,
            c.rule_name,
            c.severity,
            c.rank,
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
    let fix = extract_au_location_fix(&correlations, &fix_entities);
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

    // 3. Complete scan sequence (every event), as structured JSON lines.
    let events = store.events_for_scan(sid)?;
    let _ = writeln!(s, "\n== SCAN SEQUENCE ({} events) ==", events.len());
    if events.is_empty() {
        let _ = writeln!(
            s,
            "  (no events recorded — event persistence disabled, or an import not a live scan)"
        );
    }
    s.push_str(&render_event_log(&events));

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
    /// the self-update error message, if the update lifecycle is in its `Error`
    /// phase (a failed auto-update leaves the binary stale).
    pub update_error: Option<&'a str>,
    /// commits behind upstream (`Some(n>0)` ⇒ a newer build exists) — surfaced
    /// because a stale build may be reproducing already-fixed bugs.
    pub update_commits_behind: Option<u64>,
    /// `(service, total_keys)` for each configured service whose pooled keys are
    /// ALL non-active — its keyed modules return nothing silently.
    pub dead_key_services: Vec<(&'a str, usize)>,
    /// the first `PRAGMA integrity_check` problem row when the on-disk DB is
    /// corrupt (`None` ⇒ healthy `["ok"]`).
    pub db_integrity_issue: Option<&'a str>,
    /// whether the SQLite `-wal` sidecar has grown past the safe bound.
    pub wal_oversized: bool,
}

/// The `-wal` size (bytes) above which the write-ahead log is considered to be
/// running away — checkpointing has stalled and the sidecar is eating device
/// storage. 64 MiB: comfortably above a healthy transient WAL, well below a
/// level that matters on a phone.
pub(crate) const WAL_RUNAWAY_BYTES: u64 = 64 * 1024 * 1024;

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
    // A failed self-update leaves the binary stale — surface it loudly.
    if let Some(msg) = inp.update_error {
        issues.push(DetectedIssue {
            severity: SEV_CRITICAL,
            category: "update",
            detail: format!("self-update FAILED — the binary is stale: {msg}"),
        });
    }
    // Running behind upstream: a stale build may be reproducing bugs already
    // fixed in a newer release. Grounded in a real operator debug bundle whose
    // three module errors (`stackoverflow_user` invalid-filter, `bluesky_user`
    // 400-not-found, `see_know` `.icu` DNS) were each already fixed upstream —
    // the bundle just had no way to say "you are on an old build; update".
    if let Some(behind) = inp.update_commits_behind.filter(|n| *n > 0) {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "update",
            detail: format!(
                "build is {behind} commit(s) behind upstream — run `hse update`; module errors you are seeing may already be fixed in a newer build"
            ),
        });
    }
    // A configured service whose keys are ALL non-active (exhausted / invalid /
    // rate-limited / revoked) is the largest INVISIBLE failure class: the keyed
    // module returns `Ok(empty)` with no error and no failure streak (e.g.
    // `see_know` short-circuits on `is_key_invalid()`/exhausted budget), so it
    // never reaches the error-based health arms above — the pool is the only
    // place the silent death is visible.
    for (service, total) in &inp.dead_key_services {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "key-pool",
            detail: format!(
                "service `{service}`: all {total} pooled key(s) are non-active (exhausted/invalid/rate-limited/revoked) — its keyed modules return nothing silently; top up or rotate (`hse keys`)"
            ),
        });
    }
    // On-disk database corruption — the highest-severity, most-invisible signal:
    // the self-test only checks a throwaway temp DB, so a corrupt real store
    // never shows anywhere else.
    if let Some(issue) = inp.db_integrity_issue {
        issues.push(DetectedIssue {
            severity: SEV_CRITICAL,
            category: "storage",
            detail: format!(
                "database integrity check FAILED: {issue} — back up the DB and consider `hse` re-import; corruption silently loses/garbles stored findings"
            ),
        });
    }
    if inp.wal_oversized {
        issues.push(DetectedIssue {
            severity: SEV_WARNING,
            category: "storage",
            detail:
                "the SQLite -wal sidecar has grown past 64 MiB — checkpointing appears stalled; it will keep eating device storage until the process cleanly closes the DB"
                    .to_string(),
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

/// A value-free per-service key-pool summary the caller hands in (mapped from
/// the api layer's `summarize_pool`), so the renderer stays self-contained and
/// never touches key material. A pool is genuinely dead only when it has
/// neither an ACTIVE nor an UNTESTED key ([`KeyPoolSummary::is_dead`]) — an
/// untested key has simply not been probed yet and may work on first use, so it
/// must NOT count as dead (a real-binary run flagged an untested `shodan` key
/// "ALL DEAD" before this distinction was added).
pub(crate) struct KeyPoolSummary {
    pub service: String,
    pub total: usize,
    pub active: usize,
    pub untested: usize,
    pub rate_limited: usize,
    pub exhausted: usize,
    pub invalid: usize,
    pub revoked: usize,
    /// Mean health across the pool's *tested* keys, or `None` when every key is
    /// still untested (no operational history to grade). Rendered as "n/a"
    /// rather than a fabricated score in that case.
    pub avg_health: Option<f64>,
}

impl KeyPoolSummary {
    /// True iff the pool holds keys but NONE can currently be dispatched and
    /// none remain untested — every key is exhausted / invalid / rate-limited /
    /// revoked, so the service's keyed modules silently return nothing.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.total > 0 && self.active == 0 && self.untested == 0
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
    /// Per-service key-pool health (value-free), for the KEY POOL section and
    /// the silently-dead-pool verdict arm.
    pub key_pool: Vec<KeyPoolSummary>,
    /// `PRAGMA integrity_check` rows for the REAL on-disk store — `["ok"]` when
    /// healthy, one or more problem descriptions when corrupt (the self-test
    /// only round-trips a throwaway temp DB, never the operator's data).
    pub db_integrity: Vec<String>,
    /// Size of the SQLite `-wal` sidecar in bytes, or `None` if not found. A
    /// runaway WAL (checkpointing stalled) is a real on-device disk-footprint
    /// failure mode.
    pub wal_bytes: Option<u64>,
    /// Commits the running binary is behind upstream, or `None` if never
    /// checked / offline. A build that is behind may be hitting bugs already
    /// fixed upstream — the exact situation a real operator debug bundle showed
    /// (three module errors, every one already fixed in a newer build).
    pub update_commits_behind: Option<u64>,
    /// Unix seconds of the last successful upstream check, `0` if never.
    pub update_last_checked: u64,
    /// The update lifecycle phase, stringified — `"idle"`/`"checking"`/
    /// `"applying"`/`"restarting"`, or `"error: <msg>"` preserving the payload.
    pub update_phase: String,
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
        "=== HUNTSMAN SYSTEM DEBUG BUNDLE — full engine self-diag ==="
    );
    let _ = writeln!(s, "One file: what's wrong, the proof, and every module.");

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
        // The handler stringifies the update phase as `"error: <msg>"` for the
        // `Error` variant; recover the message for the verdict.
        update_error: inp.update_phase.strip_prefix("error: "),
        update_commits_behind: inp.update_commits_behind,
        dead_key_services: inp
            .key_pool
            .iter()
            .filter(|k| k.is_dead())
            .map(|k| (k.service.as_str(), k.total))
            .collect(),
        // Healthy integrity is exactly `["ok"]`; any other row is a problem.
        db_integrity_issue: inp
            .db_integrity
            .iter()
            .find(|r| r.as_str() != "ok")
            .map(String::as_str),
        wal_oversized: inp.wal_bytes.is_some_and(|b| b > WAL_RUNAWAY_BYTES),
    });
    write_detected_issues(&mut s, &issues);

    // ── 1. Environment fingerprint (build / host / module set / key presence) ──
    // Reuse the `curl_present` already computed for the verdict — one spawn, not two.
    s.push_str(&super::environment::render_environment(curl_present));

    write_update_status(&mut s, inp);
    write_disabled_capabilities(&mut s);
    write_validation(&mut s, &inp.selftest);
    write_module_health(&mut s, &module_health);
    write_search_engine_liveness(&mut s, &engines, &engines_down, &engines_blocked);
    write_scraper_health(&mut s, inp);
    write_key_authentication(&mut s, inp);
    write_provider_quotas(&mut s, &provider_budgets, &quota_exhausted);
    write_key_pool(&mut s, inp);
    write_storage_health(&mut s, inp);
    write_recent_scans(&mut s, inp);
    write_recent_logs(&mut s, inp);
    write_source_files(&mut s);

    s
}

/// ── 0. DETECTED ISSUES — the self-diagnosing verdict, read first. ──
fn write_detected_issues(s: &mut String, issues: &[DetectedIssue]) {
    use std::fmt::Write as _;
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
    for i in issues {
        let _ = writeln!(s, "  [{}] {}: {}", i.severity, i.category, i.detail);
    }
}

/// ── 1a. Update / build freshness — is this binary current? ──
fn write_update_status(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "\n── UPDATE STATUS ──");
    let behind = match inp.update_commits_behind {
        Some(0) => "up to date".to_string(),
        Some(n) => format!("{n} commit(s) BEHIND upstream — run `hse update`"),
        None => "unknown (never checked / offline)".to_string(),
    };
    let _ = writeln!(s, "  commits_behind: {behind}");
    let _ = writeln!(s, "  phase         : {}", inp.update_phase);
    let last = if inp.update_last_checked == 0 {
        "never".to_string()
    } else {
        crate::util::timefmt::compact_utc(inp.update_last_checked)
    };
    let _ = writeln!(s, "  last_checked  : {last}");
}

/// ── 1b. Disabled capabilities (operator toggles) — the single most direct
///        answer to "why didn't module/feature X run?" that isn't a bug: an
///        operator turned it off in `~/.huntsman/settings.json`. ──
fn write_disabled_capabilities(s: &mut String) {
    use std::fmt::Write as _;
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
}

/// ── 2. Validation — the full self-test suite (`hse selftest`). ──
fn write_validation(s: &mut String, selftest: &crate::selftest::Report) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "\n── VALIDATION (SELF-TEST) ──");
    let _ = writeln!(s, "  {}", selftest.summary());
    s.push_str(&selftest.render());
    s.push('\n');
}

/// ── 3. Live per-process module health (failure streaks). ──
fn write_module_health(s: &mut String, module_health: &[crate::core::engine::ModuleHealth]) {
    use std::fmt::Write as _;
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
    for h in module_health {
        let last = h
            .last_success_at
            .map_or_else(|| "never this process".to_string(), |t| t.to_string());
        let _ = writeln!(
            s,
            "  {:<28} {} consecutive failure(s) · last success: {}",
            h.name, h.consecutive_failures, last
        );
    }
}

/// ── 4a. Search-engine liveness (latest cached sweep). ──
fn write_search_engine_liveness(
    s: &mut String,
    engines: &crate::modules::search_engines::health::HealthSnapshot,
    engines_down: &[&str],
    engines_blocked: &[&str],
) {
    use std::fmt::Write as _;
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
}

/// ── 4b. Cross-scan scraper health (persisted drift). ──
fn write_scraper_health(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
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
}

/// ── 4b′. Key authentication — which keyed sources the upstream is actively
///        REJECTING (auth-shaped errors: 401/403, "invalid API key", "API key
///        not found", …), lifted out of the generic drift errors above so a
///        dead credential is called out explicitly with the exact upstream
///        message and the env var most likely holding it. Grounded in observed
///        responses — never mis-reports a working key like a synthetic probe. ──
fn write_key_authentication(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let auth_rejected = crate::util::key_health::auth_failing_sources(&inp.scraper_health);
    let _ = writeln!(
        s,
        "\n── KEY AUTHENTICATION ({} source(s) rejected by upstream) ──",
        auth_rejected.len()
    );
    if auth_rejected.is_empty() {
        let _ = writeln!(
            s,
            "  ✓ no keyed source is being rejected for bad credentials"
        );
    }
    for i in &auth_rejected {
        let env = i.likely_env_var.unwrap_or("(unmapped)");
        // Capped for the report line, with the truncation disclosed — the full
        // string stays on the issue and is served whole by the keys API.
        let detail = i.detail_capped(200);
        let _ = writeln!(
            s,
            "  [AUTH-REJECT] {:<20} {env} · {} failure(s) · {detail}",
            i.module, i.consecutive_failures
        );
    }
}

/// ── 4c. Keyed-provider quota budgets (why a keyed module returns nothing). ──
fn write_provider_quotas(
    s: &mut String,
    provider_budgets: &[(&str, crate::util::budget::BudgetSnapshot)],
    quota_exhausted: &[&str],
) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── PROVIDER QUOTAS ({} exhausted) ──",
        quota_exhausted.len()
    );
    for (name, b) in provider_budgets {
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
}

/// ── 4d. Key-pool health — value-free per-service status. A service with keys
///        but 0 ACTIVE is a silent top-source death (invisible to the
///        error-based health above). ──
fn write_key_pool(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let dead_pools = inp.key_pool.iter().filter(|k| k.is_dead()).count();
    let _ = writeln!(
        s,
        "\n── KEY POOL ({} service(s) pooled, {} fully dead) ──",
        inp.key_pool.len(),
        dead_pools
    );
    if inp.key_pool.is_empty() {
        let _ = writeln!(
            s,
            "  (no keys in the pool — free modules still run; keyed modules skip cleanly)"
        );
    }
    for k in &inp.key_pool {
        let dead = if k.is_dead() { "  · ALL DEAD" } else { "" };
        // "n/a" (not a fabricated 0.00) when no key has been exercised yet.
        let health = k
            .avg_health
            .map_or_else(|| "n/a".to_string(), |h| format!("{h:.2}"));
        let _ = writeln!(
            s,
            "  {:<14} {}/{} active · {} untested · {} rate-limited · {} exhausted · {} invalid · {} revoked · health {}{}",
            k.service,
            k.active,
            k.total,
            k.untested,
            k.rate_limited,
            k.exhausted,
            k.invalid,
            k.revoked,
            health,
            dead
        );
    }
}

/// ── 4e. Storage health — the REAL on-disk DB (self-test only checks a
///        throwaway temp DB, so corruption is invisible everywhere else). ──
fn write_storage_health(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
    let integrity_ok = inp.db_integrity.iter().all(|r| r == "ok");
    let _ = writeln!(s, "\n── STORAGE HEALTH (real on-disk DB) ──");
    if integrity_ok {
        let _ = writeln!(s, "  integrity: ok");
    } else {
        let _ = writeln!(
            s,
            "  integrity: FAIL — {} issue(s):",
            inp.db_integrity
                .iter()
                .filter(|r| r.as_str() != "ok")
                .count()
        );
        for row in inp.db_integrity.iter().filter(|r| r.as_str() != "ok") {
            let _ = writeln!(s, "    • {row}");
        }
    }
    match inp.wal_bytes {
        Some(b) => {
            let note = if b > WAL_RUNAWAY_BYTES {
                "  · RUNAWAY (checkpointing stalled)"
            } else {
                ""
            };
            let _ = writeln!(s, "  WAL size : {} KiB{note}", b / 1024);
        }
        None => {
            let _ = writeln!(s, "  WAL size : (no -wal sidecar found)");
        }
    }
}

/// ── 5. Recent scans (with each failed scan's error inline). ──
fn write_recent_scans(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
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
}

/// ── 6. Recent verbose logs (the in-memory TRACE ring). ──
fn write_recent_logs(s: &mut String, inp: &SystemDebugInputs) {
    use std::fmt::Write as _;
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
}

/// ── 7. Source-file manifest (build fingerprint — every file the binary carries). ──
fn write_source_files(s: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        s,
        "\n── SOURCE FILES ({} files, {} LOC) ──",
        crate::source_manifest::SOURCE_FILES.len(),
        crate::source_manifest::SOURCE_TOTAL_LINES,
    );
    for (path, lines) in crate::source_manifest::SOURCE_FILES {
        let _ = writeln!(s, "  {lines:>6}  {path}");
    }
}

pub(super) fn render_report(store: &Store, sid: &str, include_infra: bool) -> Result<String> {
    // Default dossier hides quarantined `candidate` entities (non-target
    // breach-dump rows) — the confirmed-footprint view. They remain available
    // over HTTP via `report.json?include_candidates=1`.
    let report = build_scan_report(store as _, sid, false, include_infra)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    serde_json::to_string_pretty(&report)
        .map_err(|e| Error::Other(format!("report serialise: {e}")))
}

/// Canonical scan-report JSON envelope. Shared by the HTTP endpoint
/// `/api/v1/scans/{id}/report.json` and the `hse export --format
/// report` CLI subcommand so the on-device and over-the-wire
/// dossiers stay byte-equivalent.
///
/// Generic over the storage handle: the HTTP layer hands in an
/// `Arc<dyn StoragePort>` (via `&*s.store`), the CLI hands in a
/// `&Store` directly. Both expose `get_scan / entities_for_scan /
/// correlations_for_scan` with matching signatures.
///
/// Returns `Ok(None)` when no scan with that id exists, so callers
/// can map straight to a 404. Bubbles storage errors otherwise.
pub(crate) fn build_scan_report(
    store: &dyn crate::core::port::StoragePort,
    scan_id: &str,
    include_candidates: bool,
    include_infra: bool,
) -> crate::core::error::Result<Option<serde_json::Value>> {
    let Some(scan) = store.get_scan(scan_id)? else {
        return Ok(None);
    };
    let mut entities = store.entities_for_scan(scan_id)?;
    // Quarantine in the dossier too: speculative `candidate` entities (the
    // non-target breach-dump rows) are hidden by default so the report reads
    // as the target's confirmed footprint. `include_candidates=true` returns
    // the full set for investigation.
    if !include_candidates {
        entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
    }
    // Strip platform/shared-infrastructure entities (cloud buckets, CDN IPs,
    // analytics IDs sourced from third-party platform pages) from default
    // output. They inflate the count and obscure subject-owned entities.
    // `include_infra=true` (via `--include-infra` or `--output full`) restores
    // them.
    if !include_infra {
        // The operator-provided seed is the subject — it must ALWAYS appear in
        // its own report, even when it is itself infrastructure (e.g. a scan
        // seeded with a datacenter/CDN IP that an IP module re-emits as
        // `hosting`, which then merges `platform-infra` onto the seed anchor).
        entities.retain(|e| !e.has_tag(crate::core::tags::PLATFORM_INFRA) || e.has_tag("seed"));
    }
    // Self-resolving document: every `correlations[].entity_uids` entry must
    // name an entity present in this same envelope. The correlator runs over
    // the full infra-inclusive set (only candidates are excluded), so under the
    // default `include_infra=false` a finding on a platform-infra entity — a
    // compromised hosting IP that AU-004 fires Critical on — referenced a UID
    // the `entities` array no longer carried, and the report's highest-severity
    // finding could not be explained from the document itself. Union the
    // referenced infra entities back (they are part of a finding, so they are
    // subject-relevant by definition); a correlation that references a hidden
    // CANDIDATE is dropped instead — the quarantine wins over completeness.
    // `entities_to_gexf` enforces the same both-endpoints-present invariant for
    // relation edges.
    let mut correlations = store.correlations_for_scan(scan_id)?;
    {
        let present: std::collections::HashSet<&str> =
            entities.iter().map(|e| e.uid.as_str()).collect();
        let mut missing: Vec<String> = correlations
            .iter()
            .flat_map(|c| c.entity_uids.iter())
            .filter(|uid| !present.contains(uid.as_str()))
            .cloned()
            .collect();
        missing.sort_unstable();
        missing.dedup();
        for uid in missing {
            if let Some(e) = store.get_entity(&uid)? {
                let hidden_candidate =
                    !include_candidates && e.has_tag(crate::core::tags::CANDIDATE);
                if !hidden_candidate {
                    entities.push(e);
                }
            }
        }
        let present: std::collections::HashSet<&str> =
            entities.iter().map(|e| e.uid.as_str()).collect();
        correlations.retain(|c| c.entity_uids.iter().all(|u| present.contains(u.as_str())));
    }
    let best_location = extract_au_location_fix(&correlations, &entities);
    // The calibrated 0–100 Exposure Index — the SAME headline verdict the CLI
    // `print_dossier` and the debug bundle both open with. This envelope is the
    // canonical over-the-wire/on-device dossier (shared by GET report.json and
    // `hse export --format report`), yet it was the one dossier rendering that
    // omitted the summary score, so a consumer reading report.json alone could
    // not tell a MINIMAL scan from a HIGH one without recomputing it. `assess`
    // is pure and excludes candidate/sub-floor rows internally, so the score is
    // identical whether or not this envelope filtered candidates above, and the
    // determinism audit still holds (nothing here varies but `exported_at`).
    let exposure = crate::core::exposure::assess(&entities, &correlations);
    // Provider coverage: what the engine actually managed to ask, derived from
    // this scan's own dispatch events. Without it a MINIMAL report is
    // ambiguous — a clean sweep that found nothing and a sweep where twelve
    // providers never answered render identically, and only the first is
    // evidence of absence. `null` when the scan has no retained module events
    // (an old scan whose log has been pruned), because an EMPTY coverage list
    // would read as "every provider answered", which is precisely the false
    // clean negative this block exists to prevent.
    let coverage =
        crate::core::intelligence::provider_coverage_from_events(&store.events_for_scan(scan_id)?);
    let provider_coverage = if coverage.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::json!({
            "complete": crate::core::intelligence::coverage_is_complete(&coverage),
            "unresolved_count": coverage
                .iter()
                .filter(|row| !row.outcome.is_resolved())
                .count(),
            "providers": coverage,
        })
    };
    Ok(Some(serde_json::json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        "exposure": exposure,
        // Best AU geolocation fix synthesised by AU-059 cross-seed geo synergy.
        // `null` when no AU-059 fired; present with full structured fields when
        // ≥2 orthogonal AU source classes converged on a location.
        "best_location": best_location,
        // Which providers answered, which broke, and which were never asked —
        // so a thin report can be read as a thin result rather than as a clean
        // one. See the derivation above for the failure-dominant aggregation.
        "provider_coverage": provider_coverage,
        // DETERMINISM: `exported_at` is the SOLE intentional source of
        // non-determinism in any export. It is meaningful here — report.json is a
        // point-in-time snapshot whose "when was this pulled" is part of its
        // value — and is the documented exception to byte-reproducibility. The
        // diffable/reproducible artifacts are the debug bundle (no timestamp,
        // proven byte-stable) and entity-level `scan_diff`. The
        // `export_formats_determinism_audit` test pins that NO OTHER field of the
        // report varies across renders, so any newly-introduced non-determinism
        // fails CI rather than silently breaking reproducibility.
        "exported_at": crate::core::entity::unix_now(),
    })))
}

/// Parse the structured geo-fix fields that AU-059 embeds in its description.
///
/// AU-059 description format:
/// `"N AU coordinate(s) from M orthogonal source class(es) [C1, C2] converge on
///  LAT,LON (geohash=GH, state=STATE); synergy confidence SC — MITRE T1591.001"`
///
/// Returns a JSON object `{lat, lon, geohash, state, synergy_confidence,
/// source_count, class_count, severity}` from the highest-rank AU-059 firing,
/// or `serde_json::Value::Null` when no AU-059 correlation exists for the scan.
/// The AU-059 `best_location` for the export, read **structurally** from the
/// scan entities rather than by parsing the finding prose. It is present iff
/// AU-059 actually fired this scan (the gated, ranked finding); the geo fields
/// come from the one canonical [`crate::core::correlator::au059_synergy_fix`]
/// computation the rule itself uses, so the structured export and the finding
/// can never drift (they did, by construction, when this re-parsed the prose).
/// Severity and the post-hoc `rank` are taken from the emitted correlation.
pub(crate) fn extract_au_location_fix(
    correlations: &[crate::core::correlator::Correlation],
    entities: &[crate::core::entity::Entity],
) -> serde_json::Value {
    // Independent-source corroboration (computed regardless of which headline fix
    // wins): how many DISTINCT methods agree on a locality, folding in the
    // postcode-grain signals the synergy fix can't see. Attached to whichever fix
    // is returned so the JSON surface always reports the corroboration strength.
    let corroboration = crate::core::correlator::au_location_corroboration(entities).map(|c| {
        serde_json::json!({
            "lat": c.lat,
            "lon": c.lon,
            "radius_km": c.radius_km,
            "state": c.state,
            "locality": c.locality,
            "independent_classes": c.independent_classes,
            "signal_count": c.signal_count,
            "classes": c.class_names,
            "confidence": c.confidence,
        })
    });

    // Primary: the AU-059 multi-source cross-class synergy fix (strongest). The
    // structured fields are recomputed from the entities, never parsed from prose.
    let best = correlations
        .iter()
        .filter(|c| c.rule_id == "AU-059")
        .max_by(|a, b| {
            a.rank
                .partial_cmp(&b.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    let mut fix = if let Some(c) = best
        && let Some(synergy) = crate::core::correlator::au059_synergy_fix(entities)
    {
        serde_json::json!({
            "lat": synergy.lat,
            "lon": synergy.lon,
            "radius_km": synergy.radius_km,
            "geohash": synergy.geohash,
            "state": synergy.state,
            "synergy_confidence": synergy.synergy_confidence,
            "severity": c.severity.as_canonical(),
            "rank": c.rank,
            "source_count": synergy.count,
            "class_count": synergy.class_names.len(),
            // INFRASTRUCTURE LOCATION != HUMAN LOCATION. False means every
            // contributing sighting was a registered, reported or inferred
            // place — real addresses that need not be where the person is —
            // so a consumer plotting this pin knows what it does and does not
            // assert about the subject's own position.
            "locates_subject_directly": synergy.locates_subject_directly,
            "rule_id": "AU-059",
        })
    } else {
        // Fallback: the single-signal best-location estimate, so the web/JSON
        // surface carries a headline fix whenever ANY AU location signal exists —
        // not only the ≥2-class synergy case. Carries the precision radius, nearest
        // locality, and the basis it was derived from. `Null` only when there is no
        // AU location at all.
        match crate::core::correlator::best_au_location_estimate(entities) {
            Some(est) => serde_json::json!({
                "lat": est.lat,
                "lon": est.lon,
                "radius_km": est.radius_km,
                "geohash": est.geohash,
                "state": est.state,
                "locality": est.locality,
                "confidence": est.confidence,
                "basis": est.basis,
                // As above: whether this pin observed the SUBJECT or a place
                // merely associated with them.
                "locates_subject_directly": est.locates_subject_directly,
                "source": "single-signal",
            }),
            None => serde_json::Value::Null,
        }
    };

    if let Some(obj) = fix.as_object_mut()
        && let Some(corr) = corroboration
    {
        obj.insert("corroboration".to_string(), corr);
    }
    fix
}

#[cfg(test)]
mod tests {
    use super::{partial_export_reason, render_raw_response_body};

    /// A minimal, fully-populated [`super::SystemDebugInputs`] with empty
    /// collections and a healthy DB — enough to drive
    /// [`super::render_system_debug_bundle`] through every section without
    /// touching the store or the network.
    fn minimal_system_debug_inputs() -> super::SystemDebugInputs {
        super::SystemDebugInputs {
            selftest: crate::selftest::Report {
                ok: true,
                passed: 0,
                warned: 0,
                failed: 0,
                total: 0,
                elapsed_ms: 0,
                version: "test".into(),
                checks: vec![],
            },
            scans: vec![],
            scraper_health: vec![],
            scraper_events_checked: 0,
            log_dump: String::new(),
            log_lines: 0,
            key_pool: vec![],
            db_integrity: vec!["ok".to_string()],
            wal_bytes: None,
            update_commits_behind: Some(0),
            update_last_checked: 0,
            update_phase: "idle".into(),
        }
    }

    /// Characterization guard for the system debug bundle: it is assembled
    /// section by section, and this pins the section set AND their order so the
    /// per-section-helper refactor cannot silently drop, reorder, or duplicate a
    /// section. Substrings (not whole lines) so live counts in the headers don't
    /// make the test brittle.
    #[test]
    fn system_debug_bundle_emits_every_section_in_canonical_order() {
        let out = super::render_system_debug_bundle(&minimal_system_debug_inputs());
        const SECTIONS: &[&str] = &[
            "=== HUNTSMAN SYSTEM DEBUG BUNDLE",
            "── DETECTED ISSUES",
            "── UPDATE STATUS ──",
            "── DISABLED CAPABILITIES",
            "── VALIDATION (SELF-TEST) ──",
            "── MODULE HEALTH",
            "── SEARCH-ENGINE LIVENESS",
            "── SCRAPER HEALTH",
            "── KEY AUTHENTICATION",
            "── PROVIDER QUOTAS",
            "── KEY POOL",
            "── STORAGE HEALTH (real on-disk DB) ──",
            "── RECENT SCANS",
            "── RECENT LOGS",
            "── SOURCE FILES",
        ];
        let mut cursor = 0usize;
        for header in SECTIONS {
            match out[cursor..].find(header) {
                Some(off) => cursor += off + header.len(),
                None => panic!("section {header:?} missing or out of order in:\n{out}"),
            }
        }
    }

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

    /// The defect this pins: `partial_export_reason` classified on
    /// `ScanStatus` alone, and a budget-truncated scan reaches
    /// `ScanStatus::Complete` like any other. So the dossier header read
    /// "complete, unredacted" and the debug bundle read "complete scan
    /// snapshot" for a scan whose expansion had stopped with candidates still
    /// queued — precisely the false claim this function's own doc says an
    /// evidentiary artifact must never make.
    #[test]
    fn a_budget_truncated_scan_is_not_branded_a_complete_export() {
        use crate::core::scan::{Scan, ScanStatus, StopReason, Target, TargetKind};

        let mk = |stop: Option<StopReason>| {
            let mut sc = Scan::new(
                "s1",
                Target {
                    kind: TargetKind::Email,
                    value: "a@b.test".into(),
                },
            );
            sc.status = ScanStatus::Complete;
            sc.stop_reason = stop;
            sc
        };

        for stop in [StopReason::MaxEntities(500), StopReason::MaxWallTime(60)] {
            assert_eq!(
                partial_export_reason(&mk(Some(stop))),
                Some("budget-truncated"),
                "{stop:?} must mark the export partial"
            );
        }

        // …and the converse, so the "partial" brand keeps its meaning: a scan
        // that genuinely ran out of candidates, one that ran every requested
        // depth round, and a row written before `stop_reason` existed are all
        // complete exports.
        for stop in [
            None,
            Some(StopReason::NoMoreCandidates),
            Some(StopReason::DepthExhausted),
        ] {
            assert_eq!(
                partial_export_reason(&mk(stop)),
                None,
                "{stop:?} is a complete export"
            );
        }
    }

    /// The pre-existing classifications must survive unchanged — this function
    /// is the single source both artifact headers share.
    #[test]
    fn non_complete_statuses_keep_their_partial_reasons() {
        use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};

        for (status, want) in [
            (ScanStatus::Aborted, "aborted"),
            (ScanStatus::Failed, "failed"),
            (ScanStatus::Pending, "live"),
            (ScanStatus::Running, "live"),
        ] {
            let mut sc = Scan::new(
                "s1",
                Target {
                    kind: TargetKind::Email,
                    value: "a@b.test".into(),
                },
            );
            sc.status = status;
            assert_eq!(partial_export_reason(&sc), Some(want), "{status:?}");
        }
    }
}
