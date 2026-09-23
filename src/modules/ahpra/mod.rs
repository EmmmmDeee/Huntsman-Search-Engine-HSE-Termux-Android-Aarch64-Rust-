//! AHPRA (Australian Health Practitioner Regulation Agency) register scrape.
//! Free HTML scrape; no key required.
//!
//! Endpoint: `GET https://www.ahpra.gov.au/Registration/Registers-of-Practitioners.aspx`
//! Query params: Spousesurname={name} or Organisation={org}
//!
//! **UNVERIFIED query contract — observed IGNORED (2026-09-23, REQ-AHPRA-002).**
//! Live, with this module's default User-Agent, the register answers the GET
//! above with its blank search page: an Angular POST form (`id="mainform"`,
//! fields `name-reg`, `name-reg-detail`, `health-profession`), no `<table>`,
//! the searched name nowhere in it. The query string is not read. Such a page
//! is refused as a failure by [`register_rows`], never parsed into "not a
//! registered practitioner"; the POST API behind the form is unverified and
//! deliberately not guessed at.

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "ahpra";

/// AHPRA's public register page — the one URL this module requests.
const REGISTER_URL: &str = "https://www.ahpra.gov.au/Registration/Registers-of-Practitioners.aspx";

pub struct Ahpra;

/// Scrape the AHPRA register search-results table into
/// `(name, profession, registration_number)` rows.
///
/// A dependency-free `<tr>`/`<td>` walk (no scraper crate, in keeping with the
/// lean Termux build): each cell's text is taken via
/// [`strip_tags_plain`](crate::util::html::strip_tags_plain) and rows
/// with at least three cells are kept. The header row (`Name`/`Practitioner`)
/// and nameless rows are dropped, so the result is data-only. Pure given
/// `html` — unit-testable against a captured response.
pub(super) fn parse_ahpra_html(html: &str) -> Vec<(String, String, String)> {
    // Returns Vec<(name, profession, registration_number)>. The `<tr>`/`<td>`
    // table walk is shared via `util::html::table_rows`; this keeps only the
    // AHPRA-specific column mapping and header/nameless-row drop.
    let mut results = Vec::new();
    for cells in crate::util::html::table_rows(html) {
        if cells.len() >= 3 {
            let name = cells[0].clone();
            let profession = cells[1].clone();
            let reg_no = cells[2].clone();
            if !name.is_empty() && name != "Name" && name != "Practitioner" {
                results.push((name, profession, reg_no));
            }
        }
    }
    results
}

/// The practitioner rows on a fetched register page — or an `Err` when the page
/// is the register's bare search form, which answers no query at all.
///
/// The register serves that form for the GET this module sends (see the module
/// docs), and it parses to zero rows. Zero rows used to be `Ok(empty)`, which
/// `core::coverage` files as `CleanNegative`: "the subject is not a registered
/// health practitioner", minted from a page that never ran the search. Until
/// REQ-AHPRA-002 that was masked only because the challenge detector misread
/// the same page as a Cloudflare wall.
///
/// `Error::Module`, not `Error::Skipped`: the provider WAS asked (a skip's
/// contract is "never queried"), and its answer broke the contract this module
/// reads, which coverage files as `Failed` — never a negative. No genuine
/// zero-match results page has been captured, so no row-less page carrying the
/// form is trusted as one. Rows, when a page does carry them, are kept. Pure
/// given `html`.
pub(super) fn register_rows(html: &str) -> Result<Vec<(String, String, String)>> {
    let rows = parse_ahpra_html(html);
    if rows.is_empty() && carries_search_form(html) {
        return Err(Error::module(
            SRC,
            "the register answered with its blank search form, not results — it ignores \
             this module's GET query, so the subject was NOT looked up (not a finding \
             that they are unregistered)",
        ));
    }
    Ok(rows)
}

/// Whether `html` carries the register's own search form — the
/// `<form … id="mainform" …>` of the live capture (REQ-AHPRA-002).
fn carries_search_form(html: &str) -> bool {
    crate::util::str_util::find_ascii_ci(html, "id=\"mainform\"").is_some()
}

/// GET the register page for `target` from `register_url` and return its HTML,
/// or `None` for a `404`. The endpoint is a parameter so the whole request
/// path — status typing, the bounded body read, the anti-bot-page guard — runs
/// against a loopback in tests; production passes [`REGISTER_URL`].
pub(super) async fn fetch_register_page(
    client: &reqwest::Client,
    register_url: &str,
    target: &Target,
) -> Result<Option<String>> {
    let value = target.value.trim();
    let param = match target.kind {
        TargetKind::Organisation => {
            format!("Organisation={}", crate::util::http::urlencode(value))
        }
        _ => format!("Spousesurname={}", crate::util::http::urlencode(value)),
    };
    let url = format!("{register_url}?{param}");

    let resp = client.get(&url).send_tagged(SRC).await?;
    let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[404]).await? else {
        return Ok(None);
    };
    // An empty result from this registry is a NEGATIVE CLAIM about the
    // subject, which an analyst will act on, so a connection reset while
    // streaming the body must never be able to produce one — see
    // `read_body_capped_or_fail`. Fail closed, as the sibling AU scrapers
    // already do (`asic_director::fetch_register_page`, `app_links`'
    // `FetchOutcome::TransportFailed`).
    crate::util::http::read_body_capped_or_fail(SRC, resp, 512 * 1024)
        .await
        .map(Some)
}

/// Remove HTML tags from a table cell, returning its visible text — a
/// single-pass character filter that drops everything between `<` and `>`.
/// Sufficient for the flat, well-formed AHPRA cells; the caller trims.

#[async_trait]
impl Module for Ahpra {
    fn name(&self) -> &'static str {
        "ahpra"
    }

    fn description(&self) -> &'static str {
        "AHPRA practitioner-register recon — enumerates registered health practitioners by name or organisation"
    }

    fn priority(&self) -> u8 {
        86
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        // AHPRA register lookups by name/organisation emit one Person per row with name,
        // profession/role tag, and registration number — exactly Employee Names (T1589.003)
        // + Identify Roles (T1591.004); no DNS/location/business data to justify an override.
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        let Some(html) = fetch_register_page(&ctx.http, REGISTER_URL, target).await? else {
            return Ok(ModuleResult::new());
        };

        // The blank search form is an `Err`, never zero practitioners.
        let practitioners = register_rows(&html)?;
        // Only a FullName seed names a practitioner; an Organisation search
        // returns that organisation's practitioners, whose own names differ.
        let name_seed = match target.kind {
            TargetKind::Organisation => None,
            _ => Some(value),
        };
        let mut result = ModuleResult::new();
        result.extend(build_practitioner_entities(
            &practitioners,
            name_seed,
            &ctx.scan_id,
        ));

        Ok(result)
    }
}

/// The identity caution every row this module surfaces carries.
///
/// AHPRA's register is searched by NAME and publishes no date of birth, so a
/// row says "a registered practitioner has this name", never "the subject is a
/// registered practitioner". Same contract, wording and mechanism as the
/// sibling name-matched registers (`asic_persons`, `sanctions_ofac`,
/// `openarch`, `austlii`, `trove_au`, `europeana`).
const NAME_ONLY_CAUTION: &str = "Name-only match against the national AHPRA register — it publishes no date of birth, so \
     verify identity (the registration number, profession and principal place of practice) \
     before treating this as the subject; common names collide.";

/// Sharper caution for a name the register itself returned more than once.
const MULTI_HOLDER_CAUTION: &str = "This search returned MORE THAN ONE registered practitioner with this exact name, so the \
     name provably does not identify one person — the registration numbers below belong to \
     different practitioners. Resolve by registration number before using any of it.";

/// One `Person` entity per parsed practitioner — EVERY row that is actually
/// about the seed, no cap. The HTML body is already size-bounded by
/// `read_body_capped` (the real resource limit), so capping here would silently
/// drop practitioners 21..N of a common-surname register search (Smith/Nguyen/
/// Lee return many).
///
/// `name_seed` is `Some` only for a `FullName` target: rows must then share the
/// seed's whole-word tokens, the same gate `asic_persons` applies to the ASIC
/// registers, so the register's own fuzzy matching cannot hand back an
/// unrelated practitioner as the subject. It is `None` for an `Organisation`
/// search, where the practitioners legitimately have names of their own and
/// gating on the seed would discard every genuine row.
///
/// Every surviving row is a name match and nothing more, so all of them carry
/// `needs-identity-verification` and a caution, at the confidence::MEDIUM_PLUS
/// the AU registers use for a single-source name hit — not the HIGH_PLUS this
/// used to mint, which sat ABOVE that anchor for weaker evidence.
///
/// A name this very result set holds more than once is a PROVEN collision: two
/// different real practitioners share it, and because the entity value is the
/// name the engine's merge would otherwise fuse them into one composite record
/// carrying both registration numbers. Those rows go through
/// [`crate::util::namesake::mark_ambiguous`] — below the expansion floor,
/// flagged, and their records' ownership unverified — and their caution says
/// why, so the merged entity describes its own ambiguity instead of
/// fabricating a practitioner who does not exist. Pure and testable.
pub(super) fn build_practitioner_entities(
    practitioners: &[(String, String, String)],
    name_seed: Option<&str>,
    scan_id: &str,
) -> Vec<Entity> {
    let relevant: Vec<&(String, String, String)> = practitioners
        .iter()
        .filter(|(name, _, _)| {
            name_seed.is_none_or(|seed| crate::util::str_util::whole_word_token_match(name, seed))
        })
        .collect();

    // Consolidated onto `util::namesake` (REQ-GLEIF-001): this counting used to
    // live here as an inline `HashMap` keyed on `to_ascii_lowercase()`, which
    // only approximated the engine's identity — `identity_fold` uses full
    // Unicode `to_lowercase` and collapses internal whitespace, so two rows the
    // engine really does fuse could slip past an ASCII-only key. The shared
    // authority keys on `derive_uid` itself, and `gleif_lei` now asks the same
    // question of company names through it.
    let shared = crate::util::namesake::NameCollisions::of(
        &EntityKind::Person,
        relevant.iter().map(|(name, _, _)| name.as_str()),
    );

    let mut out = Vec::with_capacity(relevant.len());
    for (name, profession, reg_no) in relevant {
        let multi_holder = shared.is_shared(&EntityKind::Person, name);
        let mut person = Entity::new(EntityKind::Person, name, confidence::MEDIUM_PLUS, scan_id);
        person.tag("ahpra");
        person.tag("health-practitioner");
        person.tag("needs-identity-verification");
        if !profession.is_empty() {
            person.tag(format!(
                "profession:{}",
                profession.to_lowercase().replace(' ', "-")
            ));
        }
        person.add_evidence(
            Evidence::new(SRC, format!("AHPRA registered practitioner: {name}"))
                .with_attr("profession", profession)
                .with_attr("registration_number", reg_no)
                .with_attr("source", "ahpra.gov.au")
                .with_attr(
                    "caution",
                    if multi_holder {
                        MULTI_HOLDER_CAUTION
                    } else {
                        NAME_ONLY_CAUTION
                    },
                ),
        );
        // After the evidence: the mark also stamps each record's ownership
        // (REQ-NAMESAKE-001). The partial copy this replaces scored the row at
        // `confidence::MEDIUM` — the expansion floor itself, not below it.
        if multi_holder {
            crate::util::namesake::mark_ambiguous(&mut person);
        }
        out.push(person);
    }
    out
}
