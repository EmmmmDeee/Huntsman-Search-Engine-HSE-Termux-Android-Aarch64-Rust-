//! Open Archives (openarchieven.nl) — the aggregated index of civil, church
//! and population registers from ~50 archives (Netherlands and Belgium above
//! all, plus French INSEE deaths and the US "Reclaim The Records" releases),
//! through its public JSON API.
//!
//! Endpoint: `GET https://api.openarch.nl/1.0/records/search.json?name={name}&lang=en&number_show=10`
//! Keyless; the API host's robots.txt allows everything.
//!
//! Wire shape (live 2026-09-06): `{"query":{…},"response":{"number_found":9539,
//! "docs":[{"pid":"Person1","identifier":"ad5284dd-…","archive_code":"rtr",
//! "archive_org":"Reclaim The Records","archive":"Reclaim The Records",
//! "personname":"Aaron John Smith","relationtype":"Deceased","eventtype":"Death",
//! "eventdate":{"day":16,"month":9,"year":2018},"eventplace":["Usa"],
//! "sourcetype":"Dossier","url":"https://www.openarchieven.nl/rtr:ad5284dd-…/en"},…]}}`.
//! The localised duplicates (`_relationtype`, `_eventtype`) are ignored;
//! `eventdate` parts are absent when the register did not record them.
//!
//! What it yields for a full-name seed: one `Person` per distinct person name
//! the registers record (the engine merges same-name entities, so each
//! register entry lands as its own evidence record — event, date, place, the
//! person's role in the record, the holding archive) and one `Url` source per
//! entry, tagged as a document to read rather than a page to mine. The API's
//! name search is fuzzy (`John Smith` matches `Aaron John Smith`), and a
//! civil register is genealogy — namesakes across two centuries are the norm
//! — so every entity carries `needs-identity-verification` and a sub-medium
//! confidence; a hit whose recorded name does not even share the seed's
//! whole-word tokens is demoted further.
//!
//! MITRE ATT&CK: People-category default — T1589.003 / T1591.004; a birth,
//! marriage or death register entry is identity information.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "openarch";
/// Records requested per search — a common name has thousands of register
/// entries; ten is a reviewable sample, and the total is reported alongside.
const ROWS: usize = 10;

/// Open Archives genealogy collector — see the module docs for the wire format
/// and the identity-verification confidence policy.
pub struct OpenArch;

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct OaResp {
    response: Option<OaResponse>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct OaResponse {
    number_found: Option<u64>,
    docs: Vec<OaDoc>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(super) struct OaDoc {
    pub(super) identifier: Option<String>,
    pub(super) archive_code: Option<String>,
    pub(super) archive: Option<String>,
    pub(super) personname: Option<String>,
    pub(super) relationtype: Option<String>,
    pub(super) eventtype: Option<String>,
    pub(super) eventdate: Option<OaDate>,
    pub(super) eventplace: Vec<String>,
    pub(super) sourcetype: Option<String>,
    pub(super) url: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(super) struct OaDate {
    pub(super) day: Option<u32>,
    pub(super) month: Option<u32>,
    pub(super) year: Option<u32>,
}

impl OaDate {
    /// ISO-style rendering with only the parts the register recorded:
    /// `1973-05-26`, `1973-05`, `1973`, or `None` without a year.
    pub(super) fn render(&self) -> Option<String> {
        let year = self.year?;
        Some(match (self.month, self.day) {
            (Some(m), Some(d)) => format!("{year:04}-{m:02}-{d:02}"),
            (Some(m), None) => format!("{year:04}-{m:02}"),
            _ => format!("{year:04}"),
        })
    }
}

#[async_trait]
impl Module for OpenArch {
    fn name(&self) -> &'static str {
        "openarch"
    }

    fn description(&self) -> &'static str {
        "Open Archives genealogy — civil, church and population register entries for a full name across ~50 European and US archives"
    }

    fn priority(&self) -> u8 {
        44
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // Historical register indexes change at archive-release cadence, not
        // scan cadence; a day's cache spares the free API repeat traffic.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let name = target.value.trim();
        if name.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.openarch.nl/1.0/records/search.json?name={}&lang=en&number_show={ROWS}",
            crate::util::http::urlencode(name)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        // A 404 means the API path itself moved — not a statement about the
        // person; every other non-2xx is an error, never an empty answer.
        let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let body: OaResp = crate::util::http::json_decode(SRC, resp).await?;
        let Some(response) = body.response else {
            return Ok(ModuleResult::new());
        };
        Ok(build_entities(
            name,
            response.number_found.unwrap_or(0),
            &response.docs,
            &ctx.scan_id,
        ))
    }
}

/// True when every whole-word token of the seed appears in the recorded
/// person name — the API's fuzzy name match otherwise surfaces
/// `Aaron John Smith` for `John Smith`, which still shares both tokens, but
/// also partial matches that share only one.
pub(super) fn recorded_name_covers_seed(recorded: &str, seed: &str) -> bool {
    seed.split_whitespace()
        .all(|tok| crate::util::str_util::shares_whole_word_token(recorded, tok))
}

/// One `Person` per distinct recorded name (each register entry as its own
/// evidence) plus one `Url` source per entry. Pure (no I/O) so the extraction
/// is unit-tested directly; empty when the index found nothing.
pub(super) fn build_entities(
    seed: &str,
    number_found: u64,
    docs: &[OaDoc],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if number_found == 0 || docs.is_empty() {
        return result;
    }
    let mut seen_urls = std::collections::HashSet::new();
    for doc in docs.iter().take(ROWS) {
        let Some(personname) = doc
            .personname
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let covers = recorded_name_covers_seed(personname, seed);
        let conf = if covers {
            confidence::LOW_MEDIUM
        } else {
            confidence::LOW
        };
        let date = doc.eventdate.as_ref().and_then(OaDate::render);
        let place = doc.eventplace.join(", ");
        let summary = format!(
            "Open Archives {}: {}{}{} — {}",
            doc.sourcetype.as_deref().unwrap_or("register entry"),
            doc.eventtype.as_deref().unwrap_or("event"),
            date.as_deref().map(|d| format!(" {d}")).unwrap_or_default(),
            if place.is_empty() {
                String::new()
            } else {
                format!(", {place}")
            },
            doc.archive.as_deref().unwrap_or("unnamed archive"),
        );
        let mut ev = Evidence::new(SRC, summary.clone())
            .with_attr("recorded_name", personname)
            .with_attr("index_total", number_found.to_string());
        if let Some(role) = &doc.relationtype {
            ev = ev.with_attr("role_in_record", role);
        }
        if let Some(t) = &doc.eventtype {
            ev = ev.with_attr("event_type", t);
        }
        if let Some(d) = &date {
            ev = ev.with_attr("event_date", d);
        }
        if !place.is_empty() {
            ev = ev.with_attr("event_place", &place);
        }
        if let Some(a) = &doc.archive {
            ev = ev.with_attr("archive", a);
        }
        if let Some(c) = &doc.archive_code {
            ev = ev.with_attr("archive_code", c);
        }
        if let Some(s) = &doc.sourcetype {
            ev = ev.with_attr("source_type", s);
        }
        if let Some(id) = &doc.identifier {
            ev = ev.with_attr("record_id", id);
        }
        if let Some(u) = &doc.url {
            ev = ev.with_attr("url", u);
        }
        if !covers {
            ev = ev.with_attr(
                "caution",
                "The recorded name does not contain every word of the seed — a \
                 fuzzy index match, not necessarily the same person.",
            );
        }

        let mut person = Entity::new(EntityKind::Person, personname, conf, scan_id);
        person.tag(SRC);
        person.tag("genealogy");
        person.tag("civil-register");
        person.tag("needs-identity-verification");
        person.add_evidence(ev.clone());
        result.push(person);

        // The register entry itself, as a source to read — not a page to mine
        // for the other people a register names.
        if let Some(u) = doc.url.as_deref()
            && (u.starts_with("http://") || u.starts_with("https://"))
            && seen_urls.insert(u.to_string())
        {
            let mut url_e = Entity::new(EntityKind::Url, u, conf, scan_id);
            url_e.tag(SRC);
            url_e.tag("genealogy");
            url_e.tag(crate::core::tags::SOURCE_DOCUMENT);
            url_e.tag("needs-identity-verification");
            url_e.add_evidence(ev);
            result.push(url_e);
        }
    }
    result
}
