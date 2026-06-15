//! Australian Electoral Commission (AEC) and state electoral roll lookups.
//!
//! Queries the AEC's public "Check your enrolment" tool and the equivalent
//! state commission pages (NSW, VIC, QLD, SA, WA, TAS, ACT, NT) to confirm
//! enrolment and extract the electoral division (which maps to a suburb/postcode
//! range). Electoral roll enrolment in Australia is compulsory, so this is a
//! high-confidence residential-address signal orthogonal to business registers,
//! unclaimed-money records, and people-finder directories.
//!
//! Sources (all free, keyless, public HTML):
//!   * AEC — `https://electorate.aec.gov.au/NameSearch.aspx`
//!   * NSW Electoral Commission — `https://check.elections.nsw.gov.au/`
//!   * VEC (Victoria) — `https://check.vec.vic.gov.au/`
//!   * ECQ (Queensland) — `https://enrol.ecq.qld.gov.au/check`
//!   * ECSA (South Australia) — `https://www.ecsa.sa.gov.au/enrolment/check-enrolment`
//!   * WAEC (Western Australia) — `https://check.elections.wa.gov.au/CheckEnrolment`
//!   * TEC (Tasmania) — `https://www.tec.tas.gov.au/rolls/Check_Enrolment/search`
//!   * Elections ACT — `https://www.elections.act.gov.au/electoral_rolls/check_your_enrolment`
//!   * NTEC (Northern Territory) — `https://ntec.nt.gov.au/voters/check-enrolment`
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (electoral division → suburb)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Confidence model:
//!   * Confirmed enrolment with division + suburb: 0.72 (electoral roll is
//!     compulsory and address-verified; higher than directory sources)
//!   * Division only (no suburb resolved): 0.58
//!   * Address from division centroid lookup: 0.65 (derived, not raw)
//!
//! The module is AU-restricted: it only accepts `FullName` targets and only
//! emits when the division geography maps inside Australia.

mod division_map;
mod entity;
mod parse;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use futures::future::join_all;

use crate::core::{
    entity::{Entity, EntityKind},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

pub(crate) use entity::build_electoral_entities;
pub(crate) use parse::extract_division;

pub(super) const SRC: &str = "au_electoral";

pub struct AuElectoral;

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuElectoral {
    fn name(&self) -> &'static str {
        "au_electoral"
    }

    fn description(&self) -> &'static str {
        "AEC and state electoral commission enrolment lookups — confirms residential \
         electoral division (suburb/state) for an AU full-name seed"
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Address, EntityKind::Coordinates]
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn priority(&self) -> u8 {
        85
    }

    fn max_timeout_ms(&self) -> u64 {
        // Nine parallel EC lookups; each ~3–5 s, so 20 s covers the batch.
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let encoded = crate::util::http::urlencode(full_name);
        let mut all_entities: Vec<Entity> = Vec::new();

        // ── AEC national lookup ──────────────────────────────────────────
        let (first, last) = split_name(full_name);
        if !last.is_empty() {
            let aec_url = format!(
                "https://electorate.aec.gov.au/NameSearch.aspx?surname={}&firstname={}",
                crate::util::http::urlencode(last),
                crate::util::http::urlencode(first),
            );
            if let Ok(resp) = ctx
                .http
                .get(&aec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── NSW Electoral Commission ─────────────────────────────────────
        if all_entities.is_empty() {
            let nsw_url = format!("https://check.elections.nsw.gov.au/search?name={}", encoded);
            if let Ok(resp) = ctx
                .http
                .get(&nsw_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── Victorian Electoral Commission ────────────────────────────────
        if all_entities.is_empty() {
            let vec_url = format!("https://check.vec.vic.gov.au/search?name={}", encoded);
            if let Ok(resp) = ctx
                .http
                .get(&vec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── ECQ Queensland ───────────────────────────────────────────────
        if all_entities.is_empty() {
            let ecq_url = format!("https://enrol.ecq.qld.gov.au/check?name={}", encoded);
            if let Ok(resp) = ctx
                .http
                .get(&ecq_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .send_tagged(SRC)
                .await
                && let Ok(body) = resp.text().await
                && let Some((div, suburb)) = extract_division(&body)
            {
                all_entities.extend(build_electoral_entities(
                    &div,
                    suburb.as_deref(),
                    full_name,
                    &ctx.scan_id,
                ));
            }
        }

        // ── SA, WA, TAS, ACT, NT — run in parallel ───────────────────────
        if all_entities.is_empty() {
            let (enc_surname, enc_first) = {
                let (f, l) = split_name(full_name);
                (
                    crate::util::http::urlencode(l),
                    crate::util::http::urlencode(f),
                )
            };

            let ecsa_url = format!(
                "https://www.ecsa.sa.gov.au/enrolment/check-enrolment?surname={}&firstname={}",
                enc_surname, enc_first,
            );
            let waec_url = format!(
                "https://check.elections.wa.gov.au/CheckEnrolment?Surname={}&FirstName={}",
                enc_surname, enc_first,
            );
            let tec_url = format!(
                "https://www.tec.tas.gov.au/rolls/Check_Enrolment/search?surname={}&first_name={}",
                enc_surname, enc_first,
            );
            let act_url = format!(
                "https://www.elections.act.gov.au/electoral_rolls/check_your_enrolment?surname={}&firstname={}",
                enc_surname, enc_first,
            );
            let ntec_url = format!(
                "https://ntec.nt.gov.au/voters/check-enrolment?surname={}&firstname={}",
                enc_surname, enc_first,
            );

            let make_req = |url: &str| {
                ctx.http
                    .get(url)
                    .header("Accept", "text/html,application/xhtml+xml")
                    .header(
                        "User-Agent",
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    )
                    .send_tagged(SRC)
            };

            let (ecsa_res, waec_res, tec_res, act_res, ntec_res) = {
                let futs = join_all([
                    make_req(&ecsa_url),
                    make_req(&waec_url),
                    make_req(&tec_url),
                    make_req(&act_url),
                    make_req(&ntec_url),
                ]);
                let mut v = futs.await;
                // Drain in order: ECSA, WAEC, TEC, ACT, NTEC.
                let ntec = v.pop().unwrap();
                let act = v.pop().unwrap();
                let tec = v.pop().unwrap();
                let waec = v.pop().unwrap();
                let ecsa = v.pop().unwrap();
                (ecsa, waec, tec, act, ntec)
            };

            // ── ECSA (SA) ────────────────────────────────────────────────
            if let Ok(resp) = ecsa_res
                && let Ok(body) = resp.text().await
            {
                let (enrolled, div) = parse::parse_ecsa(&body);
                if enrolled {
                    let div_name = div.as_deref().unwrap_or("SA electorate");
                    all_entities.extend(build_electoral_entities(
                        div_name,
                        None,
                        full_name,
                        &ctx.scan_id,
                    ));
                }
            }

            // ── WAEC (WA) ────────────────────────────────────────────────
            if all_entities.is_empty()
                && let Ok(resp) = waec_res
                && let Ok(body) = resp.text().await
            {
                let (enrolled, div) = parse::parse_waec(&body);
                if enrolled {
                    let div_name = div.as_deref().unwrap_or("WA electorate");
                    all_entities.extend(build_electoral_entities(
                        div_name,
                        None,
                        full_name,
                        &ctx.scan_id,
                    ));
                }
            }

            // ── TEC (TAS) ────────────────────────────────────────────────
            if all_entities.is_empty()
                && let Ok(resp) = tec_res
                && let Ok(body) = resp.text().await
            {
                let (enrolled, div) = parse::parse_tec(&body);
                if enrolled {
                    let div_name = div.as_deref().unwrap_or("TAS electorate");
                    all_entities.extend(build_electoral_entities(
                        div_name,
                        None,
                        full_name,
                        &ctx.scan_id,
                    ));
                }
            }

            // ── Elections ACT ─────────────────────────────────────────────
            if all_entities.is_empty()
                && let Ok(resp) = act_res
                && let Ok(body) = resp.text().await
            {
                let (enrolled, div) = parse::parse_elections_act(&body);
                if enrolled {
                    let div_name = div.as_deref().unwrap_or("ACT electorate");
                    all_entities.extend(build_electoral_entities(
                        div_name,
                        None,
                        full_name,
                        &ctx.scan_id,
                    ));
                }
            }

            // ── NTEC (NT) ─────────────────────────────────────────────────
            if all_entities.is_empty()
                && let Ok(resp) = ntec_res
                && let Ok(body) = resp.text().await
            {
                let (enrolled, div) = parse::parse_ntec(&body);
                if enrolled {
                    let div_name = div.as_deref().unwrap_or("NT electorate");
                    all_entities.extend(build_electoral_entities(
                        div_name,
                        None,
                        full_name,
                        &ctx.scan_id,
                    ));
                }
            }
        }

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}

/// Split `"First Last"` into `("First", "Last")`. Pure.
fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    if let Some(pos) = trimmed.find(' ') {
        (&trimmed[..pos], trimmed[pos + 1..].trim_start())
    } else {
        (trimmed, "")
    }
}
