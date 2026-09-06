//! WikiTree — the collaborative single-family-tree genealogy wiki, through
//! its public JSON API (`api.wikitree.com`).
//!
//! Endpoint: `GET https://api.wikitree.com/api.php?action=searchPerson&FirstName={first}&LastName={last}&fields={FIELDS}&format=json&limit=10&appId=HuntsmanSearchEngine`
//! Keyless. `appId` is the caller identifier the API asks every client to
//! send, not a credential: the same query without it answers
//! `429 [{"status":"Limit exceeded."}]` — live-confirmed 2026-09-06, as was
//! the shape below with it.
//!
//! Wire shape (live 2026-09-06): a one-element JSON array —
//! `[{"status":0,"matches":[{"Id":6819925,"Name":"Smith-54274","FirstName":"John",
//! "LastNameAtBirth":"Smith","BirthDate":"1880-11-24","DeathDate":"1951-08-19",
//! "BirthLocation":"Woodville, New Zealand","DeathLocation":"Palmerston North,
//! New Zealand","Father":6953891,"Mother":20479519,"index":0},…,
//! {"Id":6611905,"Name":"Smith-52589","index":2}],"total":602,"start":0,"limit":3}]`.
//! `status` is `0` on success and an error string otherwise; a match may be a
//! stub (`Id` + `Name` only — a profile whose details are private); dates are
//! `YYYY-MM-DD` with `00` for the parts the tree does not know.
//!
//! What it yields for a full-name seed: one `Person` per distinct rendered
//! name (the engine merges same-name entities, so each profile lands as its
//! own evidence record — WikiTree id, birth and death date and place, gender,
//! parent profile ids) and one `Url` source per profile
//! (`https://www.wikitree.com/wiki/{Name}`), tagged as a document to read
//! rather than a page to mine. Namesakes are the norm in a family tree (602
//! "John Smith" profiles born around 1880), so every entity carries
//! `needs-identity-verification` and a sub-medium confidence; the operator,
//! or a later corroborating source, decides which profile is the subject's.
//! Stubs carry nothing to corroborate and are counted, not emitted.
//!
//! MITRE ATT&CK: People-category default — T1589.003 / T1591.004; birth,
//! death and kin are identity information.
//!
//! Terms: the API is free for non-commercial use and asks callers to
//! identify themselves (`appId`) and keep request rates modest — one request
//! per seed, cached for a day (profiles change slowly).

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "wikitree";
/// The caller identifier WikiTree's API asks every client to send.
const APP_ID: &str = "HuntsmanSearchEngine";
/// Profiles requested per search — a name with hundreds of namesakes still
/// yields a bounded, reviewable set; the total is reported alongside.
const LIMIT: usize = 10;
/// The profile fields requested — exactly the ones the parser reads.
const FIELDS: &str = "Id,Name,FirstName,MiddleName,LastNameAtBirth,LastNameCurrent,BirthDate,DeathDate,BirthLocation,DeathLocation,Gender,Father,Mother";

pub struct WikiTree;

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct WtEnvelope {
    /// `0` on success; an error string (`"Limit exceeded."`) otherwise.
    status: serde_json::Value,
    matches: Vec<WtMatch>,
    total: Option<u64>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(super) struct WtMatch {
    #[serde(rename = "Id")]
    pub(super) id: Option<u64>,
    /// The WikiTree profile id (`Smith-54274`) — the wiki page name.
    #[serde(rename = "Name")]
    pub(super) name: Option<String>,
    #[serde(rename = "FirstName")]
    pub(super) first_name: Option<String>,
    #[serde(rename = "MiddleName")]
    pub(super) middle_name: Option<String>,
    #[serde(rename = "LastNameAtBirth")]
    pub(super) last_name_at_birth: Option<String>,
    #[serde(rename = "LastNameCurrent")]
    pub(super) last_name_current: Option<String>,
    #[serde(rename = "BirthDate")]
    pub(super) birth_date: Option<String>,
    #[serde(rename = "DeathDate")]
    pub(super) death_date: Option<String>,
    #[serde(rename = "BirthLocation")]
    pub(super) birth_location: Option<String>,
    #[serde(rename = "DeathLocation")]
    pub(super) death_location: Option<String>,
    #[serde(rename = "Gender")]
    pub(super) gender: Option<String>,
    /// Parent profile numeric ids; `0`/absent when the tree has none.
    #[serde(rename = "Father")]
    pub(super) father: Option<u64>,
    #[serde(rename = "Mother")]
    pub(super) mother: Option<u64>,
}

impl WtMatch {
    /// `First Middle LastAtBirth` from the parts the profile has; `None` for a
    /// stub (no first or birth surname — details private).
    pub(super) fn display_name(&self) -> Option<String> {
        let first = self
            .first_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let last = self
            .last_name_at_birth
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let mut parts = vec![first];
        if let Some(m) = self
            .middle_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            parts.push(m);
        }
        parts.push(last);
        Some(parts.join(" "))
    }
}

/// A WikiTree date with its unknown `00` parts trimmed: `1880-02-00` →
/// `1880-02`, `1940-00-00` → `1940`, `0000-00-00`/empty → `None`.
pub(super) fn trim_wikitree_date(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let mut parts = raw.split('-');
    let year = parts.next()?;
    if year.is_empty()
        || year.chars().all(|c| c == '0')
        || !year.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let mut out = year.to_string();
    for p in parts {
        if p.is_empty() || p.chars().all(|c| c == '0') {
            break;
        }
        out.push('-');
        out.push_str(p);
    }
    Some(out)
}

#[async_trait]
impl Module for WikiTree {
    fn name(&self) -> &'static str {
        "wikitree"
    }

    fn description(&self) -> &'static str {
        "WikiTree genealogy — family-tree profiles matching a full name, with birth, death and parent links"
    }

    fn priority(&self) -> u8 {
        43
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
        // A collaborative tree changes at edit cadence, not scan cadence, and
        // the API asks for modest request rates.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // The one name parser the codebase has (particles, suffixes, initials)
        // decides what the first and last names are — not a second splitter.
        let Some(parsed) = crate::modules::name_intel::permute::parse(target.value.trim()) else {
            return Ok(ModuleResult::new());
        };
        let (first, last) = (parsed.display_first(), parsed.display_last());
        if first.is_empty() || last.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.wikitree.com/api.php?action=searchPerson&FirstName={}&LastName={}&fields={FIELDS}&format=json&limit={LIMIT}&appId={APP_ID}",
            crate::util::http::urlencode(first),
            crate::util::http::urlencode(last)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;
        // A 404 means the API path itself moved; a 429 (rate limit) is an
        // error, never an empty answer about the person.
        let Some(resp) = crate::util::http::ok_or_absent(SRC, resp, &[404]).await? else {
            return Ok(ModuleResult::new());
        };
        let envelopes: Vec<WtEnvelope> = crate::util::http::json_decode(SRC, resp).await?;
        let Some(envelope) = envelopes.into_iter().next() else {
            return Err(Error::module(SRC, "empty response envelope"));
        };
        if envelope.status.as_u64() != Some(0) {
            return Err(Error::module(
                SRC,
                format!("API status: {}", envelope.status),
            ));
        }
        Ok(build_entities(
            target.value.trim(),
            envelope.total.unwrap_or(0),
            &envelope.matches,
            &ctx.scan_id,
        ))
    }
}

/// One `Person` per distinct rendered profile name (each profile as its own
/// evidence) plus one `Url` source per profile; stubs are counted, not
/// emitted. Pure (no I/O) so the extraction is unit-tested directly; empty
/// when the tree has no match.
pub(super) fn build_entities(
    seed: &str,
    total: u64,
    matches: &[WtMatch],
    scan_id: &str,
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if total == 0 || matches.is_empty() {
        return result;
    }
    let stubs = matches
        .iter()
        .filter(|m| m.display_name().is_none())
        .count();
    let mut seen_urls = std::collections::HashSet::new();
    for m in matches.iter().take(LIMIT) {
        let (Some(display), Some(profile)) = (m.display_name(), m.name.as_deref().map(str::trim))
        else {
            continue;
        };
        if profile.is_empty() {
            continue;
        }
        let born = m.birth_date.as_deref().and_then(trim_wikitree_date);
        let died = m.death_date.as_deref().and_then(trim_wikitree_date);
        let birth_place = m
            .birth_location
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let death_place = m
            .death_location
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        // A profile with at least one dated or placed event is corroborable;
        // a name-only profile is not, and says so.
        let has_detail =
            born.is_some() || died.is_some() || birth_place.is_some() || death_place.is_some();
        let conf = if has_detail {
            confidence::LOW_MEDIUM
        } else {
            confidence::LOW
        };
        let profile_url = format!("https://www.wikitree.com/wiki/{profile}");
        let mut summary = format!("WikiTree profile {profile}");
        if let Some(b) = &born {
            summary.push_str(&format!(": born {b}"));
            if let Some(p) = birth_place {
                summary.push_str(&format!(", {p}"));
            }
        }
        if let Some(d) = &died {
            summary.push_str(&format!("; died {d}"));
            if let Some(p) = death_place {
                summary.push_str(&format!(", {p}"));
            }
        }
        let mut ev = Evidence::new(SRC, summary)
            .with_attr("profile_id", profile)
            .with_attr("url", &profile_url)
            .with_attr("matches_total", total.to_string());
        if let Some(id) = m.id {
            ev = ev.with_attr("wikitree_user_id", id.to_string());
        }
        if let Some(b) = &born {
            ev = ev.with_attr("born", b);
        }
        if let Some(p) = birth_place {
            ev = ev.with_attr("birth_place", p);
        }
        if let Some(d) = &died {
            ev = ev.with_attr("died", d);
        }
        if let Some(p) = death_place {
            ev = ev.with_attr("death_place", p);
        }
        if let Some(g) = m.gender.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            ev = ev.with_attr("gender", g);
        }
        if let Some(cur) =
            m.last_name_current.as_deref().map(str::trim).filter(|s| {
                !s.is_empty() && Some(*s) != m.last_name_at_birth.as_deref().map(str::trim)
            })
        {
            ev = ev.with_attr("current_surname", cur);
        }
        if let Some(f) = m.father.filter(|f| *f > 0) {
            ev = ev.with_attr("father_user_id", f.to_string());
        }
        if let Some(mo) = m.mother.filter(|mo| *mo > 0) {
            ev = ev.with_attr("mother_user_id", mo.to_string());
        }
        if stubs > 0 {
            ev = ev.with_attr("private_profiles_matching", stubs.to_string());
        }
        if !has_detail {
            ev = ev.with_attr(
                "caution",
                "The profile records no birth or death date or place — nothing to corroborate against.",
            );
        }
        if !crate::util::str_util::shares_whole_word_token(&display, seed) {
            ev = ev.with_attr(
                "caution",
                "The profile's rendered name shares no whole word with the seed.",
            );
        }

        let mut person = Entity::new(EntityKind::Person, &display, conf, scan_id);
        person.tag(SRC);
        person.tag("genealogy");
        person.tag("family-tree");
        person.tag("needs-identity-verification");
        person.add_evidence(ev.clone());
        result.push(person);

        if seen_urls.insert(profile_url.clone()) {
            let mut url_e = Entity::new(EntityKind::Url, &profile_url, conf, scan_id);
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
