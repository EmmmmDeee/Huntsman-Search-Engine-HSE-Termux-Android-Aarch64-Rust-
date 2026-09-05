//! Ransomware.live victim lookup — free, keyless ransomware/extortion exposure.
//!
//! Endpoint: `GET https://api.ransomware.live/v2/searchvictims/<keyword>`. The v2
//! API is public and unauthenticated (confirmed against the provider's own
//! `/api` page: "Free — No authentication"). It full-text-searches the aggregated
//! ransomware-leak-site victim corpus and returns each matching victim with the
//! claiming group, the attack/discovery dates, country, sector, and a reference
//! URL.
//!
//! Contract (verified live against a real response, 2026-09) — an array of:
//!   `{victim, group, domain, country, activity, attackdate, discovered,
//!     claim_url, url, description}` (all string-ish; a miss is HTTP 404).
//!
//! Capability: given a `Domain` or `Organisation` seed, this answers "is this
//! subject a known ransomware/extortion victim, claimed by which group, when?" —
//! a net-new exposure signal no existing HSE module covers, and pure DISCOVERY
//! (it never fetches a leak site, only the public victim index).
//!
//! Precision over recall: the upstream search is full-text, so a bare keyword
//! can match unrelated victims via a description mention. This module keeps ONLY
//! victims whose own `domain` matches a `Domain` seed, or whose `victim` name
//! matches an `Organisation` seed — never emitting an incidental description hit
//! as if it were the subject (RULE.md: no fabricated or over-broad findings).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

/// Stable evidence-source string. `pub(crate)` so a test can pin it and no
/// sibling module can silently claim the same corpus.
pub(crate) const SRC: &str = "ransomware_live";

/// One victim record from the v2 `searchvictims` array. Every field is optional
/// so a schema addition or a partially-populated record never fails the whole
/// parse into a false miss.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Victim {
    victim: Option<String>,
    group: Option<String>,
    domain: Option<String>,
    country: Option<String>,
    activity: Option<String>,
    attackdate: Option<String>,
    discovered: Option<String>,
    claim_url: Option<String>,
    /// Ransomware.live's own canonical reference page for this victim.
    url: Option<String>,
}

/// Ransomware.live victim-index module (domain/org → ransomware/extortion
/// victim records, keyless).
pub struct RansomwareLive;

#[async_trait]
impl Module for RansomwareLive {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Ransomware.live victim index — keyless check of whether a domain or org is a known ransomware/extortion victim"
    }

    fn priority(&self) -> u8 {
        120
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        // Free-or-bought threat-intel vendor data about victim organisations —
        // the category's own definition. Its default ATT&CK mapping (T1597.001)
        // is correct; no override needed.
        ModuleCategory::Threat
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::Domain,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let keyword = target.value.trim();
        if keyword.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.ransomware.live/v2/searchvictims/{}",
            urlencode(keyword)
        );
        // 404 is the upstream's clean "no such victim" signal → empty; any other
        // non-2xx surfaces as a real ModuleError (fail-closed).
        let Some(victims): Option<Vec<Victim>> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };
        Ok(build_result(&victims, target, &ctx.scan_id))
    }
}

/// How strongly a victim record matches the seed — drives both the retain
/// decision and the emitted confidence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Match {
    /// The victim's own `domain` equals (or is a sub/parent-domain of) a
    /// `Domain` seed — an authoritative, unambiguous hit.
    Domain,
    /// The victim `name` matches an `Organisation` seed — real but fuzzier
    /// (organisation names are not unique keys).
    Org,
}

/// Decide whether `victim` genuinely IS the seed subject (not an incidental
/// description mention), and how strongly.
fn classify(victim: &Victim, target: &Target) -> Option<Match> {
    let needle = target.value.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return None;
    }
    match target.kind {
        TargetKind::Domain => {
            let d = victim.domain.as_deref()?.trim().to_ascii_lowercase();
            (d == needle
                || d.ends_with(&format!(".{needle}"))
                || needle.ends_with(&format!(".{d}")))
            .then_some(Match::Domain)
        }
        TargetKind::Organisation => {
            let name = victim.victim.as_deref()?.trim().to_ascii_lowercase();
            if name.is_empty() {
                return None;
            }
            (name == needle || name.contains(&needle) || needle.contains(&name))
                .then_some(Match::Org)
        }
        _ => None,
    }
}

/// Build entities from the matching victims. Pure of I/O so it is unit-tested
/// against fixtures; `process` stays a thin network adapter.
fn build_result(victims: &[Victim], target: &Target, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for v in victims {
        let Some(kind) = classify(v, target) else {
            continue;
        };
        let conf = match kind {
            Match::Domain => confidence::HIGH_PLUSPLUS,
            Match::Org => confidence::HIGH,
        };

        // Provenance shared by every entity this victim mints.
        let group = v.group.as_deref().map(str::trim).filter(|g| !g.is_empty());
        let mut ev = Evidence::new(SRC, "Ransomware.live victim index");
        for (k, val) in [
            ("group", group),
            ("attackdate", v.attackdate.as_deref()),
            ("discovered", v.discovered.as_deref()),
            ("country", v.country.as_deref()),
            ("sector", v.activity.as_deref()),
            ("claim_url", v.claim_url.as_deref()),
            ("reference", v.url.as_deref()),
        ] {
            if let Some(val) = val.map(str::trim).filter(|s| !s.is_empty()) {
                ev = ev.with_attr(k, val);
            }
        }

        let group_tag = group.map(|g| format!("group:{}", g.to_lowercase()));

        // The victim organisation — a genuine Organisation pivot when the seed
        // was a Domain, or a reinforcement when it was the Organisation itself.
        if let Some(name) = v.victim.as_deref().map(str::trim).filter(|n| n.len() >= 2) {
            let mut e = Entity::new(EntityKind::Organisation, name, conf, scan_id);
            e.tag(SRC);
            e.tag("ransomware-victim");
            if let Some(t) = &group_tag {
                e.tag(t.clone());
            }
            e.add_evidence(ev.clone());
            result.push(e);
        }

        // The victim's domain — a new Domain pivot when the seed was an
        // Organisation (skipped when it merely echoes a Domain seed handled
        // above, since a self-referential pivot adds nothing).
        if let Some(dom) = v
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|d| d.contains('.'))
        {
            let mut e = Entity::new(EntityKind::Domain, dom, conf, scan_id);
            e.tag(SRC);
            e.tag("ransomware-victim");
            if let Some(t) = &group_tag {
                e.tag(t.clone());
            }
            e.add_evidence(ev.clone());
            result.push(e);
        }

        // The reference page — a durable lead for the analyst to corroborate.
        if let Some(reference) = v
            .url
            .as_deref()
            .map(str::trim)
            .filter(|u| u.starts_with("http"))
        {
            let mut e = Entity::new(EntityKind::Url, reference, confidence::HIGH_PLUS, scan_id);
            e.tag(SRC);
            e.tag("ransomware-victim");
            e.tag("reference");
            if let Some(t) = &group_tag {
                e.tag(t.clone());
            }
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    result
}

#[cfg(test)]
mod tests;
