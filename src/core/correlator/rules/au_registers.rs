//! AU correlation rules — Australian multi-register cross-reference intelligence.
//!
//! These rules fire when a person or organisation appears in two or more
//! independent Australian government registers in the same scan, producing
//! high-confidence identity anchors that no single-source module can reach:
//!
//! * [`rule_au_085_insolvency_director_link`]   (AU-085) — AFSA NPII + ASIC director
//! * [`rule_au_086_tpb_abn_chain`]              (AU-086) — TPB register + ABN/ACN
//! * [`rule_au_087_employer_address_corroboration`] (AU-087) — Seek listing ↔ registered address
//! * [`rule_au_088_cross_register_identity`]    (AU-088) — person in 3+ AU federal registers
//! * [`rule_au_089_tpb_professional_dual_reg`]  (AU-089) — TPB agent + AHPRA/ASIC dual-registration
//! * [`rule_au_090_asic_banned_director_conflict`] (AU-090) — ASIC banned + active ASIC director
//! * [`rule_au_091_fsr_insolvency_conflict`]    (AU-091) — ASIC FSR adviser + AFSA insolvency
//! * [`rule_au_092_trademark_company_pivot`]    (AU-092) — IP Australia trademark + ASIC company

use super::*;

// ── AU-085 — AFSA insolvency × ASIC director link ────────────────────────────

/// AU-085 — A person appears in both the AFSA National Personal Insolvency
/// Index and the ASIC company directors register.
///
/// The CORPORATIONS ACT 2001 §206B bans undischarged bankrupts from managing
/// corporations without court leave. When AFSA insolvency data and an ASIC
/// directorship both resolve to the same person (canonical name overlap), the
/// combination raises a CRITICAL compliance alert — either the person has
/// obtained court leave (explain-or-deny), is managing in breach (serious
/// offence), or the directorship predates the insolvency event (timeline
/// intelligence). Either way this is the highest-priority finding an AU
/// corporate due-diligence scan can produce.
pub(in crate::core::correlator) fn rule_au_085_insolvency_director_link(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let afsa_persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.has_tag("afsa-npii"))
        .collect();

    if afsa_persons.is_empty() {
        return Vec::new();
    }

    let asic_persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Person
                && e.evidence_sources().iter().any(|s| *s == "asic_director")
        })
        .collect();

    if asic_persons.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for afsa in &afsa_persons {
        let afsa_lc = afsa.value.to_ascii_lowercase();
        let afsa_tokens: Vec<&str> = afsa_lc
            .split_whitespace()
            .filter(|t| t.len() >= 3)
            .collect();

        for asic in &asic_persons {
            let asic_lc = asic.value.to_ascii_lowercase();
            // Canonical name overlap: both surname and at least one given name
            // token match (≥3 chars each). Prevents collisions on very short names.
            let overlap = afsa_tokens
                .iter()
                .filter(|&&tok| asic_lc.contains(tok))
                .count();
            if overlap < 2 {
                continue;
            }

            let admin_type = afsa
                .tags
                .iter()
                .find(|t| t.starts_with("insolvency:"))
                .map_or("insolvency:unknown", String::as_str);

            let is_current = afsa.has_tag("insolvency:current");
            let severity = if is_current {
                Severity::Critical
            } else {
                Severity::High
            };

            let status_desc = if is_current { "CURRENT" } else { "former" };

            out.push(Correlation {
                rule_id: "AU-085".into(),
                rule_name: "AFSA insolvency × ASIC directorship link".into(),
                severity,
                description: format!(
                    "'{}' appears in both the AFSA NPII ({admin_type}, {status_desc}) and the \
                     ASIC company directors register — potential Corporations Act §206B \
                     breach; verify court leave or timeline",
                    afsa.value
                ),
                entity_uids: vec![afsa.uid.clone(), asic.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}

// ── AU-086 — TPB registration × ABN/ACN chain ────────────────────────────────

/// AU-086 — A TPB-registered practitioner has an ABN/ACN entity in the same scan.
///
/// Tax agents and BAS agents are legally required to have an ABN. When an ABN
/// entity is present alongside a TPB registration for the same name, the
/// ABN can be confirmed as belonging to the practitioner's practice — and
/// pivoted into `abn_lookup` (ABR) to surface the registered business address,
/// trust structure, or company extract.
pub(in crate::core::correlator) fn rule_au_086_tpb_abn_chain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let tpb_entities: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.has_tag("tpb-registered")
                && (e.kind == EntityKind::Person || e.kind == EntityKind::Organisation)
        })
        .collect();

    if tpb_entities.is_empty() {
        return Vec::new();
    }

    let abn_entities: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::AbnAcn)
        .collect();

    if abn_entities.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for tpb in &tpb_entities {
        // Find an ABN that appears in the TPB entity's evidence (sourced by
        // ato_tax_agents parsing the same record row).
        let linked_abn = abn_entities.iter().find(|abn| {
            abn.has_tag("tpb-registered")
                || abn
                    .evidence_sources()
                    .iter()
                    .any(|s| *s == "ato_tax_agents")
        });

        if let Some(abn) = linked_abn {
            let reg_type = tpb
                .tags
                .iter()
                .map(String::as_str)
                .find(|t| t.starts_with("tpb:"))
                .map_or("registered", |t| t.trim_start_matches("tpb:"));

            out.push(Correlation {
                rule_id: "AU-086".into(),
                rule_name: "TPB practitioner × ABN chain".into(),
                severity: Severity::Medium,
                description: format!(
                    "TPB-registered {} '{}' ({reg_type}) linked to ABN {} — \
                     confirms the practice entity for ABR pivot",
                    if tpb.kind == EntityKind::Organisation {
                        "organisation"
                    } else {
                        "individual"
                    },
                    tpb.value,
                    abn.value
                ),
                entity_uids: vec![tpb.uid.clone(), abn.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}

// ── AU-087 — Seek employer address × registered address corroboration ─────────

/// AU-087 — A Seek job listing address corroborates the subject's registered
/// business address from ASIC, ABR, or the ACNC register.
///
/// An organisation's registered address (legal requirement) and its Seek
/// hiring location converging independently is strong evidence of genuine
/// physical presence — and rules out PO-box-only or nominee-address setups.
/// The Seek address also reflects the CURRENT operating location regardless of
/// when the ASIC/ABR address was last updated.
pub(in crate::core::correlator) fn rule_au_087_employer_address_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let seek_addrs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address && e.has_tag("seek-location"))
        .collect();

    if seek_addrs.is_empty() {
        return Vec::new();
    }

    // Registered-address sources: ASIC, ABN, ACNC, AHPRA, TPB — any address
    // that came from an authoritative AU register (not social or people-search).
    let reg_addr_sources = [
        "asic_director",
        "abn_lookup",
        "acnc_charities",
        "ahpra",
        "ato_tax_agents",
        "au_property",
        "au_electoral",
    ];

    let registered_addrs: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Address
                && e.evidence_sources()
                    .iter()
                    .any(|s| reg_addr_sources.contains(s))
        })
        .collect();

    if registered_addrs.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for seek_addr in &seek_addrs {
        let seek_lc = seek_addr.value.to_ascii_lowercase();
        // Extract state abbreviation and suburb tokens from the Seek address.
        let seek_tokens: Vec<&str> = seek_lc
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 3)
            .collect();

        for reg_addr in &registered_addrs {
            let reg_lc = reg_addr.value.to_ascii_lowercase();
            // Count overlapping suburb/state tokens (at least 2 for a match —
            // suburb + state, or suburb + postcode).
            let overlap = seek_tokens
                .iter()
                .filter(|&&tok| reg_lc.contains(tok))
                .count();
            if overlap < 2 {
                continue;
            }

            let reg_source = reg_addr
                .evidence_sources()
                .into_iter()
                .find(|s| reg_addr_sources.contains(s))
                .unwrap_or("register");

            out.push(Correlation {
                rule_id: "AU-087".into(),
                rule_name: "Seek employer location × registered address".into(),
                severity: Severity::Medium,
                description: format!(
                    "Seek job listing location '{}' corroborates registered address '{}' \
                     (from {reg_source}) — confirms current physical operating location",
                    seek_addr.value, reg_addr.value
                ),
                entity_uids: vec![seek_addr.uid.clone(), reg_addr.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}

// ── AU-088 — Cross-register Australian federal identity ───────────────────────

/// AU-088 — A person entity appears in three or more independent Australian
/// government registers in the same scan.
///
/// Multi-register presence is the highest-confidence identity anchor available
/// for Australian persons. Each register is maintained by a different federal
/// agency with independent entry requirements; a matching name across three or
/// more is effectively impossible to fake and rules out same-name namesake
/// confusion in all but the most unusual cases.
pub(in crate::core::correlator) fn rule_au_088_cross_register_identity(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // AU government register source names.
    const AU_GOV_SOURCES: &[&str] = &[
        "afsa_insolvency",
        "ato_tax_agents",
        "asic_director",
        "ahpra",
        "au_electoral",
        "abn_lookup",
        "acnc_charities",
        "au_property",
        "acma_rrl",
        "austlii",
    ];

    let persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();

    let mut out = Vec::new();

    for person in &persons {
        let sources: Vec<&str> = person
            .evidence_sources()
            .into_iter()
            .filter(|s| AU_GOV_SOURCES.contains(s))
            .collect();

        // Deduplicate source list (entity merge already aggregates — but
        // belt-and-suspenders).
        let mut unique_sources: Vec<&str> = sources.clone();
        unique_sources.sort_unstable();
        unique_sources.dedup();

        if unique_sources.len() < 3 {
            continue;
        }

        let n = unique_sources.len();
        out.push(Correlation {
            rule_id: "AU-088".into(),
            rule_name: "Cross-register Australian federal identity".into(),
            severity: Severity::High,
            description: format!(
                "'{}' independently confirmed in {} Australian government registers \
                 ({}) — highest-confidence identity anchor; namesake confusion \
                 effectively excluded",
                person.value,
                n,
                unique_sources.join(", ")
            ),
            entity_uids: vec![person.uid.clone()],
            scan_id: scan_id.into(),
            ts,
            rank: 0.0,
        });
    }

    out
}

// ── AU-089 — TPB + AHPRA/ASIC professional dual-registration ─────────────────

/// AU-089 — A person or organisation is registered in both the TPB (tax/BAS)
/// and another Australian professional register (AHPRA or ASIC).
///
/// Dual professional registration is a high-value intelligence finding:
/// a person who is both a registered tax agent and an AHPRA-regulated health
/// practitioner, or both a tax agent and an ASIC-licensed financial adviser,
/// has an unusually broad professional footprint. This cross-sector presence
/// is a strong disambiguation signal (few namesakes share both registrations)
/// and may reveal primary/secondary income streams, professional capacity
/// conflicts, or a mixed-practice firm.
pub(in crate::core::correlator) fn rule_au_089_tpb_professional_dual_reg(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let tpb_entities: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.has_tag("tpb-registered")
                && (e.kind == EntityKind::Person || e.kind == EntityKind::Organisation)
        })
        .collect();

    if tpb_entities.is_empty() {
        return Vec::new();
    }

    // AHPRA-sourced persons.
    let ahpra_persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Person && e.evidence_sources().iter().any(|s| *s == "ahpra")
        })
        .collect();

    // ASIC-sourced persons.
    let asic_persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Person
                && e.evidence_sources().iter().any(|s| *s == "asic_director")
        })
        .collect();

    let dual_register_persons: Vec<(&Entity, &str)> = ahpra_persons
        .iter()
        .map(|e| (*e, "AHPRA"))
        .chain(asic_persons.iter().map(|e| (*e, "ASIC")))
        .collect();

    if dual_register_persons.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for tpb in &tpb_entities {
        let tpb_lc = tpb.value.to_ascii_lowercase();
        let tpb_tokens: Vec<&str> = tpb_lc.split_whitespace().filter(|t| t.len() >= 3).collect();

        for (other, other_label) in &dual_register_persons {
            let other_lc = other.value.to_ascii_lowercase();
            let overlap = tpb_tokens
                .iter()
                .filter(|&&tok| other_lc.contains(tok))
                .count();
            if overlap < 2 {
                continue;
            }

            let tpb_type = tpb
                .tags
                .iter()
                .map(String::as_str)
                .find(|t| t.starts_with("tpb:"))
                .map_or("registered", |t| t.trim_start_matches("tpb:"));

            out.push(Correlation {
                rule_id: "AU-089".into(),
                rule_name: "TPB practitioner × professional dual-registration".into(),
                severity: Severity::Medium,
                description: format!(
                    "'{}' is registered with both the TPB ({tpb_type}) and {other_label} — \
                     cross-sector professional dual-registration; strong identity anchor \
                     and potential capacity-conflict signal",
                    tpb.value
                ),
                entity_uids: vec![tpb.uid.clone(), other.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}

// ── AU-090 — ASIC banned person × active ASIC director conflict ───────────────

/// AU-090 — A person in the ASIC banned/disqualified register also appears as
/// an active ASIC company director.
///
/// Under the Corporations Act 2001 §206A–206F, a person banned or disqualified
/// by ASIC is legally prohibited from managing a corporation. Detecting the same
/// name across the ASIC banned register and the ASIC directors register in the
/// same scan is a CRITICAL compliance signal — either the person is in breach of
/// a court or ASIC order, the directorship predates the ban, or there is a name
/// collision requiring investigation.
pub(in crate::core::correlator) fn rule_au_090_asic_banned_director_conflict(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let banned: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.has_tag("asic-banned"))
        .collect();

    if banned.is_empty() {
        return Vec::new();
    }

    let directors: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Person
                && e.evidence_sources().iter().any(|s| *s == "asic_director")
        })
        .collect();

    if directors.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for ban_person in &banned {
        let ban_lc = ban_person.value.to_ascii_lowercase();
        let ban_tokens: Vec<&str> = ban_lc.split_whitespace().filter(|t| t.len() >= 3).collect();

        for director in &directors {
            let dir_lc = director.value.to_ascii_lowercase();
            let overlap = ban_tokens
                .iter()
                .filter(|&&tok| dir_lc.contains(tok))
                .count();
            if overlap < 2 {
                continue;
            }

            let ban_type = ban_person
                .tags
                .iter()
                .map(String::as_str)
                .find(|t| t.starts_with("asic:banned") || t.starts_with("asic:disqualified"))
                .unwrap_or("asic:banned");

            out.push(Correlation {
                rule_id: "AU-090".into(),
                rule_name: "ASIC banned person × active ASIC director conflict".into(),
                severity: Severity::Critical,
                description: format!(
                    "'{}' appears in both the ASIC Banned Register ({ban_type}) and the ASIC \
                     Directors Register — potential breach of Corporations Act §206A–206F \
                     prohibition on managing corporations",
                    ban_person.value
                ),
                entity_uids: vec![ban_person.uid.clone(), director.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}

// ── AU-091 — ASIC FSR adviser × AFSA insolvency conflict ─────────────────────

/// AU-091 — A person registered on the ASIC Financial Services Register also
/// appears in the AFSA National Personal Insolvency Index.
///
/// ASIC's fit-and-proper requirements under the Corporations Act 2001 and the
/// National Credit Act 2009 require financial advisers and credit licensees to
/// be financially sound. An active insolvency record (undischarged bankruptcy or
/// current debt agreement) co-occurring with an FSR listing is a CRITICAL flag
/// — ASIC may not be aware of the insolvency, or the person has failed to notify
/// their licensee. Cross-register name overlap produces actionable intelligence
/// for regulatory referral.
pub(in crate::core::correlator) fn rule_au_091_fsr_insolvency_conflict(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let fsr_persons: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person && e.has_tag("asic-fsr"))
        .collect();

    if fsr_persons.is_empty() {
        return Vec::new();
    }

    let insolvent: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Person
                && e.has_tag("afsa-npii")
                && e.has_tag("insolvency:current")
        })
        .collect();

    if insolvent.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for fsr in &fsr_persons {
        let fsr_lc = fsr.value.to_ascii_lowercase();
        let fsr_tokens: Vec<&str> = fsr_lc.split_whitespace().filter(|t| t.len() >= 3).collect();

        for ins in &insolvent {
            let ins_lc = ins.value.to_ascii_lowercase();
            let overlap = fsr_tokens
                .iter()
                .filter(|&&tok| ins_lc.contains(tok))
                .count();
            if overlap < 2 {
                continue;
            }

            let admin_type = ins
                .tags
                .iter()
                .map(String::as_str)
                .find(|t| t.starts_with("insolvency:") && *t != "insolvency:current")
                .unwrap_or("insolvency:unknown");

            let fsr_role = fsr
                .tags
                .iter()
                .map(String::as_str)
                .find(|t| t.starts_with("asic-fsr:"))
                .map_or("financial-adviser", |t| t.trim_start_matches("asic-fsr:"));

            out.push(Correlation {
                rule_id: "AU-091".into(),
                rule_name: "ASIC FSR adviser × AFSA current insolvency conflict".into(),
                severity: Severity::Critical,
                description: format!(
                    "'{}' is registered on the ASIC FSR as a {fsr_role} but also has a current \
                     insolvency record ({admin_type}) in the AFSA NPII — potential breach of \
                     fit-and-proper requirements under Corporations Act and National Credit Act",
                    fsr.value
                ),
                entity_uids: vec![fsr.uid.clone(), ins.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}

// ── AU-092 — IP Australia trademark owner × ASIC company pivot ───────────────

/// AU-092 — A trade mark owner from the IP Australia register overlaps with an
/// ASIC-registered company or director in the same scan.
///
/// Trade mark registrations in Australia require the owner's legal name — for
/// companies this is the exact ASIC-registered company name; for individuals it
/// is their legal name. When the same name appears in both the IP Australia
/// trade marks register and an ASIC register (director, company, or FSR), this
/// confirms corporate identity and reveals the trading name ↔ legal entity
/// relationship. High confidence for corporate due-diligence and asset-
/// tracing (trade marks are legal property registered against the entity).
pub(in crate::core::correlator) fn rule_au_092_trademark_company_pivot(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let trademark_owners: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            (e.kind == EntityKind::Organisation || e.kind == EntityKind::Person)
                && e.has_tag("ip-australia")
        })
        .collect();

    if trademark_owners.is_empty() {
        return Vec::new();
    }

    // ASIC-sourced entities: directors, FSR registrants, or company listings.
    let asic_entities: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            (e.kind == EntityKind::Organisation || e.kind == EntityKind::Person)
                && (e
                    .evidence_sources()
                    .iter()
                    .any(|s| *s == "asic_director" || *s == "asic_fsr" || *s == "asic_banned")
                    || e.has_tag("asic-fsr")
                    || e.has_tag("asic-banned"))
        })
        .collect();

    if asic_entities.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for tm in &trademark_owners {
        let tm_lc = tm.value.to_ascii_lowercase();
        let tm_tokens: Vec<&str> = tm_lc.split_whitespace().filter(|t| t.len() >= 3).collect();

        for asic in &asic_entities {
            let asic_lc = asic.value.to_ascii_lowercase();
            let overlap = tm_tokens
                .iter()
                .filter(|&&tok| asic_lc.contains(tok))
                .count();
            if overlap < 2 {
                continue;
            }

            let pair = (tm.uid.clone(), asic.uid.clone());
            if !seen.insert(pair) {
                continue;
            }

            let asic_register = if asic.has_tag("asic-fsr") {
                "ASIC FSR"
            } else if asic.has_tag("asic-banned") {
                "ASIC Banned Register"
            } else {
                "ASIC Directors Register"
            };

            let tm_status = tm
                .tags
                .iter()
                .map(String::as_str)
                .find(|t| t.starts_with("trademark-status:"))
                .map_or("unknown", |t| t.trim_start_matches("trademark-status:"));

            out.push(Correlation {
                rule_id: "AU-092".into(),
                rule_name: "IP Australia trademark owner × ASIC entity pivot".into(),
                severity: Severity::High,
                description: format!(
                    "'{}' appears as an IP Australia trademark owner (status: {tm_status}) and \
                     also in the {asic_register} — corporate identity confirmed across independent \
                     federal registers; strong asset-tracing anchor",
                    tm.value
                ),
                entity_uids: vec![tm.uid.clone(), asic.uid.clone()],
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            });
        }
    }

    out
}
