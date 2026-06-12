//! Proxycurl LinkedIn profile extraction. Paid (Bearer Token).
//!
//! Endpoints:
//! - username / URL → `GET …/api/v2/linkedin?url=https://linkedin.com/in/{id}`
//! - email          → `GET …/api/linkedin/profile/resolve/email?work_email=…`
//!
//! Auth: Bearer Token (`HUNTSMAN_PROXYCURL_KEY`).
//!
//! Every field the paid API returns is mapped to an entity or evidence
//! attribute — nothing harvested is discarded. The field → output mapping:
//!
//! | LinkedIn field                         | Output                              |
//! |----------------------------------------|-------------------------------------|
//! | `full_name` / `first`+`last`           | `Person` (name)                     |
//! | `headline`,`occupation`,`summary`,…    | evidence attrs on the `Person`      |
//! | `city`/`state`/`country_full_name`     | `Address` (+`country:` tag)         |
//! | `experiences[].company`/`title`/dates/`location` | `Organisation` (+attrs)   |
//! | `education[].school`/`degree`/`field`  | `education` attr on the `Person`    |
//! | `personal_emails[]`                    | `Email` + derived non-freemail `Domain` |
//! | `personal_numbers[]`                   | `Phone`                             |
//!
//! The whole field→entity mapping lives in the pure [`build_entities`] so it is
//! unit-tested without a live API; `process` only owns URL construction, auth,
//! transport, and error mapping.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::domains::is_freemail;
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;
use crate::util::str_util::truncate_safe;

const KEY_ENV: &str = "HUNTSMAN_PROXYCURL_KEY";
const SRC: &str = "proxycurl";

/// Caps on per-profile output, keeping a single dump bounded.
const MAX_EMAILS: usize = 3;
const MAX_PHONES: usize = 3;
const MAX_EXPERIENCES: usize = 5;
const MAX_LISTED: usize = 3; // companies/schools surfaced inline on the Person
/// Professional `summary` is a free-text bio; cap it before persisting.
const SUMMARY_CAP: usize = 280;

pub struct Proxycurl;

#[derive(Deserialize)]
struct LinkedInProfile {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    headline: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    country_full_name: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    occupation: Option<String>,
    #[serde(default)]
    public_identifier: Option<String>,
    #[serde(default)]
    connections: Option<u64>,
    #[serde(default)]
    experiences: Vec<Experience>,
    #[serde(default)]
    education: Vec<Education>,
    #[serde(default)]
    personal_emails: Vec<String>,
    #[serde(default)]
    personal_numbers: Vec<String>,
}

#[derive(Deserialize)]
struct Experience {
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    starts_at: Option<DateField>,
    #[serde(default)]
    ends_at: Option<DateField>,
    #[serde(default)]
    location: Option<String>,
}

#[derive(Deserialize)]
struct Education {
    #[serde(default)]
    school: Option<String>,
    #[serde(default)]
    degree_name: Option<String>,
    #[serde(default)]
    field_of_study: Option<String>,
}

#[derive(Deserialize)]
struct DateField {
    #[serde(default)]
    year: Option<u32>,
    #[serde(default)]
    month: Option<u32>,
}

impl DateField {
    fn to_string_approx(&self) -> String {
        match (self.year, self.month) {
            (Some(y), Some(m)) => format!("{y}-{m:02}"),
            (Some(y), None) => y.to_string(),
            _ => String::new(),
        }
    }
}

use crate::util::str_util::nonempty;

impl LinkedInProfile {
    /// Best display name: prefer `full_name`, else compose `first`+`last`, else
    /// whichever single part exists. The email-resolve endpoint frequently
    /// returns only `first_name`/`last_name`, so the fallback is what makes that
    /// path yield a `Person` at all. `None` when no usable name is present.
    fn display_name(&self) -> Option<String> {
        if let Some(n) = nonempty(&self.full_name).filter(|s| s.chars().count() >= 2) {
            return Some(n.to_string());
        }
        match (nonempty(&self.first_name), nonempty(&self.last_name)) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            (Some(s), None) | (None, Some(s)) => Some(s.to_string()),
            (None, None) => None,
        }
    }
}

impl Education {
    /// `"School — Degree, Field"` (whichever parts are present), or `None` when
    /// there is no school to anchor the entry.
    fn describe(&self) -> Option<String> {
        let school = nonempty(&self.school)?;
        let detail: Vec<&str> = [nonempty(&self.degree_name), nonempty(&self.field_of_study)]
            .into_iter()
            .flatten()
            .collect();
        Some(if detail.is_empty() {
            school.to_string()
        } else {
            format!("{school} — {}", detail.join(", "))
        })
    }
}

/// The registrable-ish domain of an email's local@domain, lowercased.
fn email_domain(email: &str) -> Option<String> {
    let domain = email.rsplit_once('@')?.1.trim().to_lowercase();
    (domain.contains('.') && domain.len() >= 4).then_some(domain)
}

/// Build all entities from a parsed profile. **Pure** (no network / IO / clock)
/// so every field→entity mapping and confidence is unit-tested directly.
///
/// Confidences encode source authority: a named LinkedIn profile is strong
/// (0.85); a personal email is strong (0.80); a domain *derived* from that email
/// is weaker (0.68); a self-reported location is soft (0.60).
fn build_entities(profile: &LinkedInProfile, target: &Target, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    // ── Person (the anchor) ───────────────────────────────────────────────
    if let Some(name) = profile.display_name() {
        let mut pe = Entity::new(EntityKind::Person, &name, 0.85, scan_id);
        pe.tag("proxycurl");
        pe.tag("linkedin");
        let mut ev = Evidence::new(SRC, format!("LinkedIn profile: {name}"))
            .with_attr("target", &target.value);
        if let Some(h) = nonempty(&profile.headline) {
            ev = ev.with_attr("headline", h);
        }
        if let Some(occ) = nonempty(&profile.occupation) {
            ev = ev.with_attr("occupation", occ);
        }
        if let Some(pid) = nonempty(&profile.public_identifier) {
            ev = ev.with_attr("linkedin_id", pid);
        }
        if let Some(c) = profile.connections {
            ev = ev.with_attr("connections", c.to_string());
        }
        if let Some(summary) = nonempty(&profile.summary) {
            ev = ev.with_attr("summary", truncate_safe(summary, SUMMARY_CAP));
        }
        let current: Vec<&str> = profile
            .experiences
            .iter()
            .filter(|e| e.ends_at.is_none())
            .filter_map(|e| nonempty(&e.company))
            .take(MAX_LISTED)
            .collect();
        if !current.is_empty() {
            ev = ev.with_attr("current_companies", current.join(", "));
        }
        if !profile.experiences.is_empty() {
            ev = ev.with_attr("experience_count", profile.experiences.len().to_string());
        }
        let schools: Vec<String> = profile
            .education
            .iter()
            .filter_map(Education::describe)
            .take(MAX_LISTED)
            .collect();
        if !schools.is_empty() {
            ev = ev.with_attr("education", schools.join("; "));
        }
        pe.add_evidence(ev);
        result.push(pe);
    }

    // ── Address (needs ≥2 of city/state/country to be meaningful) ─────────
    let loc_parts: Vec<&str> = [
        nonempty(&profile.city),
        nonempty(&profile.state),
        nonempty(&profile.country_full_name),
    ]
    .into_iter()
    .flatten()
    .collect();
    if loc_parts.len() >= 2 {
        let location = loc_parts.join(", ");
        let mut ae = Entity::new(EntityKind::Address, &location, 0.60, scan_id);
        ae.tag("proxycurl");
        ae.tag("linkedin");
        ae.tag("geoint");
        if let Some(cc) = nonempty(&profile.country) {
            ae.tag(format!("country:{}", cc.to_uppercase()));
        }
        if let Some(state_str) = nonempty(&profile.state)
            && let Some(sc) = crate::util::address_au::state_code(state_str)
        {
            ae.tag(format!("au-state:{sc}"));
            ae.tag("country:AU");
        }
        ae.add_evidence(Evidence::new(SRC, format!("LinkedIn location: {location}")));
        result.push(ae);

        if let Some((lat, lon)) = crate::util::city_coords::city_coords(&location) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.52, scan_id);
            c.tag("proxycurl");
            c.tag("linkedin");
            c.tag("addr-derived");
            c.tag("geoint");
            if let Some(cc) = nonempty(&profile.country) {
                c.tag(format!("country:{}", cc.to_uppercase()));
            }
            if let Some(state_str) = nonempty(&profile.state)
                && let Some(sc) = crate::util::address_au::state_code(state_str)
            {
                c.tag(format!("au-state:{sc}"));
                c.tag("country:AU");
            }
            c.add_evidence(Evidence::new(
                SRC,
                format!("Inline geocode of LinkedIn location '{location}' → {coord_val}"),
            ));
            result.push(c);
        }
    }

    // ── Emails + their (non-freemail) domains — single deduped pass ────────
    let mut seen_emails = HashSet::new();
    let mut seen_domains = HashSet::new();
    for email in profile
        .personal_emails
        .iter()
        .map(|e| e.trim())
        .filter(|e| e.contains('@'))
    {
        // Dedup case-insensitively, then cap the DISTINCT addresses.
        if !seen_emails.insert(email.to_lowercase()) {
            continue;
        }
        let mut ee = Entity::new(EntityKind::Email, email, 0.80, scan_id);
        ee.tag("proxycurl");
        ee.tag("linkedin");
        ee.add_evidence(Evidence::new(SRC, "Personal email from LinkedIn"));
        result.push(ee);

        if let Some(domain) = email_domain(email)
            && !is_freemail(&domain)
            && seen_domains.insert(domain.clone())
        {
            let mut de = Entity::new(EntityKind::Domain, &domain, 0.68, scan_id);
            de.tag("proxycurl");
            de.tag("linkedin");
            de.tag("derived");
            de.add_evidence(Evidence::new(SRC, "Email domain from LinkedIn profile"));
            result.push(de);
        }

        if seen_emails.len() >= MAX_EMAILS {
            break;
        }
    }

    // ── Phones ────────────────────────────────────────────────────────────
    for phone in profile
        .personal_numbers
        .iter()
        .map(|p| p.trim())
        .filter(|p| p.len() >= 7)
        .take(MAX_PHONES)
    {
        let mut phe = Entity::new(EntityKind::Phone, phone, 0.75, scan_id);
        phe.tag("proxycurl");
        phe.tag("linkedin");
        phe.add_evidence(Evidence::new(SRC, "Phone from LinkedIn"));
        result.push(phe);
    }

    // ── Organisations (employers) — title, dates, and job location ────────
    for exp in profile.experiences.iter().take(MAX_EXPERIENCES) {
        let Some(company) = nonempty(&exp.company).filter(|c| c.chars().count() >= 2) else {
            continue;
        };
        let mut oe = Entity::new(EntityKind::Organisation, company, 0.65, scan_id);
        oe.tag("proxycurl");
        oe.tag("linkedin");
        let mut ev = Evidence::new(SRC, format!("Employer: {company}"));
        if let Some(title) = nonempty(&exp.title) {
            ev = ev.with_attr("title", title);
        }
        if let Some(loc) = nonempty(&exp.location) {
            ev = ev.with_attr("location", loc);
        }
        if let Some(start) = exp.starts_at.as_ref().map(DateField::to_string_approx)
            && !start.is_empty()
        {
            ev = ev.with_attr("start_date", start);
        }
        match exp.ends_at.as_ref().map(DateField::to_string_approx) {
            Some(end) if !end.is_empty() => ev = ev.with_attr("end_date", end),
            _ => oe.tag("current-employer"),
        }
        oe.add_evidence(ev);
        result.push(oe);
    }

    result
}

#[async_trait]
impl Module for Proxycurl {
    fn name(&self) -> &'static str {
        "proxycurl"
    }
    fn description(&self) -> &'static str {
        "LinkedIn profile extraction — employment, education, and certifications via Proxycurl"
    }
    fn priority(&self) -> u8 {
        88
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Username | TargetKind::Url | TargetKind::Email
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Email,
            EntityKind::Domain,
            EntityKind::Phone,
            EntityKind::Organisation,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let Some(api_url) = profile_url(target) else {
            return Ok(ModuleResult::new());
        };

        let resp = ctx
            .http
            .get(&api_url)
            .bearer_auth(key)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let profile: LinkedInProfile = crate::util::http::json_decode(SRC, resp).await?;

        Ok(build_entities(&profile, target, &ctx.scan_id))
    }
}

/// The Proxycurl endpoint for a target, or `None` when the target can't address
/// a LinkedIn profile (so the module no-ops rather than spending a paid call).
fn profile_url(target: &Target) -> Option<String> {
    match target.kind {
        TargetKind::Email => {
            let email = target.value.trim();
            email.contains('@').then(|| {
                format!(
                    "https://nubela.co/proxycurl/api/linkedin/profile/resolve/email?work_email={}",
                    urlencode(email),
                )
            })
        }
        TargetKind::Url => {
            let v = target.value.trim();
            v.to_lowercase()
                .contains("linkedin.com/in/")
                .then(|| linkedin_lookup_url(v))
        }
        TargetKind::Username => {
            let username = target.value.trim();
            (!username.is_empty() && username.len() <= 100)
                .then(|| linkedin_lookup_url(&format!("https://linkedin.com/in/{username}")))
        }
        _ => None,
    }
}

fn linkedin_lookup_url(linkedin_url: &str) -> String {
    format!(
        "https://nubela.co/proxycurl/api/v2/linkedin?url={}",
        urlencode(linkedin_url),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::new(TargetKind::Username, "janedoe")
    }

    fn full_profile() -> LinkedInProfile {
        let raw = r#"{
            "full_name": "Jane Doe",
            "first_name": "Jane",
            "last_name": "Doe",
            "headline": "Software Engineer",
            "summary": "Builds reliable systems.",
            "city": "Melbourne",
            "state": "Victoria",
            "country_full_name": "Australia",
            "country": "au",
            "occupation": "Senior Software Engineer at Atlassian",
            "public_identifier": "jane-doe",
            "connections": 500,
            "experiences": [
                {"company": "Atlassian", "title": "Senior Engineer",
                 "starts_at": {"year": 2020, "month": 1}, "location": "Sydney, Australia"},
                {"company": "Canva", "title": "Engineer",
                 "starts_at": {"year": 2017}, "ends_at": {"year": 2019, "month": 12}}
            ],
            "education": [
                {"school": "University of Melbourne", "degree_name": "BSc", "field_of_study": "Computer Science"}
            ],
            "personal_emails": ["jane@acme-corp.com", "jane@gmail.com", "jane@acme-corp.com"],
            "personal_numbers": ["+61412345678", "123"]
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    // ── Module surface ──────────────────────────────────────────────────
    #[test]
    fn accepts_username_url_and_email() {
        let m = Proxycurl;
        assert!(m.accepts(&Target::new(TargetKind::Username, "johndoe")));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://linkedin.com/in/johndoe"
        )));
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(Proxycurl.cost(), ModuleCost::Paid));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Proxycurl.name(), "proxycurl");
        assert_eq!(Proxycurl.priority(), 88);
        assert_eq!(Proxycurl.max_timeout_ms(), 15_000);
    }

    // ── URL construction (process's only non-pure decision) ─────────────
    #[test]
    fn profile_url_per_kind() {
        let email = profile_url(&Target::new(TargetKind::Email, "a@b.com")).unwrap();
        assert!(email.contains("resolve/email?work_email="));
        let url = profile_url(&Target::new(TargetKind::Url, "https://linkedin.com/in/x")).unwrap();
        assert!(url.contains("api/v2/linkedin?url="));
        let user = profile_url(&Target::new(TargetKind::Username, "x")).unwrap();
        assert!(user.contains("linkedin.com%2Fin%2Fx"));
        // No-op targets spend no paid call.
        assert!(profile_url(&Target::new(TargetKind::Email, "not-an-email")).is_none());
        assert!(profile_url(&Target::new(TargetKind::Url, "https://twitter.com/x")).is_none());
        assert!(profile_url(&Target::new(TargetKind::Username, "")).is_none());
        assert!(profile_url(&Target::new(TargetKind::Domain, "x.com")).is_none());
    }

    // ── Pure parsing helpers ────────────────────────────────────────────
    #[test]
    fn date_field_to_string() {
        let mk = |y, m| DateField { year: y, month: m };
        assert_eq!(mk(Some(2020), Some(3)).to_string_approx(), "2020-03");
        assert_eq!(mk(Some(2020), None).to_string_approx(), "2020");
        assert_eq!(mk(None, None).to_string_approx(), "");
    }

    #[test]
    fn display_name_prefers_full_then_falls_back() {
        let mk = |full: Option<&str>, f: Option<&str>, l: Option<&str>| {
            let mut p: LinkedInProfile = serde_json::from_str("{}").unwrap();
            p.full_name = full.map(String::from);
            p.first_name = f.map(String::from);
            p.last_name = l.map(String::from);
            p.display_name()
        };
        assert_eq!(
            mk(Some("Jane Q. Doe"), None, None).as_deref(),
            Some("Jane Q. Doe")
        );
        // full_name absent → compose first+last (the email-resolve case).
        assert_eq!(
            mk(None, Some("Jane"), Some("Doe")).as_deref(),
            Some("Jane Doe")
        );
        assert_eq!(mk(None, Some("Jane"), None).as_deref(), Some("Jane"));
        assert_eq!(mk(None, None, Some("Doe")).as_deref(), Some("Doe"));
        assert_eq!(mk(None, None, None), None);
        // blanks/whitespace are not a name.
        assert_eq!(mk(Some("   "), None, None), None);
        // short multibyte names are accepted (byte-length would have rejected).
        assert_eq!(mk(Some("李明"), None, None).as_deref(), Some("李明"));
    }

    #[test]
    fn education_describe_combines_available_parts() {
        let mk = |s: Option<&str>, d: Option<&str>, f: Option<&str>| {
            Education {
                school: s.map(String::from),
                degree_name: d.map(String::from),
                field_of_study: f.map(String::from),
            }
            .describe()
        };
        assert_eq!(
            mk(Some("MIT"), Some("PhD"), Some("CS")).as_deref(),
            Some("MIT — PhD, CS")
        );
        assert_eq!(
            mk(Some("MIT"), Some("PhD"), None).as_deref(),
            Some("MIT — PhD")
        );
        assert_eq!(mk(Some("MIT"), None, None).as_deref(), Some("MIT"));
        assert_eq!(mk(None, Some("PhD"), Some("CS")), None); // no school → no entry
    }

    #[test]
    fn email_domain_extracts_registrable() {
        assert_eq!(
            email_domain("a@acme-corp.com").as_deref(),
            Some("acme-corp.com")
        );
        assert_eq!(
            email_domain("a@SUB.Example.COM").as_deref(),
            Some("sub.example.com")
        );
        assert_eq!(email_domain("no-at-sign"), None);
        assert_eq!(email_domain("a@x"), None); // no dot / too short
    }

    // ── The core: build_entities maps every field, with no waste ─────────
    #[test]
    fn build_entities_extracts_full_profile() {
        let r = build_entities(&full_profile(), &target(), "scan");
        let by =
            |k: EntityKind| -> Vec<&Entity> { r.entities.iter().filter(|e| e.kind == k).collect() };

        // Person, with EVERY harvested attribute (incl. summary + education
        // degree/field — the fields the old code discarded).
        let person = by(EntityKind::Person);
        assert_eq!(person.len(), 1);
        let pe = person[0];
        assert_eq!(pe.value, "Jane Doe");
        let ev = &pe.evidence[0];
        assert_eq!(
            ev.attributes.get("headline").map(String::as_str),
            Some("Software Engineer")
        );
        assert_eq!(
            ev.attributes.get("summary").map(String::as_str),
            Some("Builds reliable systems.")
        );
        assert_eq!(
            ev.attributes.get("linkedin_id").map(String::as_str),
            Some("jane-doe")
        );
        assert_eq!(
            ev.attributes.get("connections").map(String::as_str),
            Some("500")
        );
        assert_eq!(
            ev.attributes.get("current_companies").map(String::as_str),
            Some("Atlassian")
        );
        assert_eq!(
            ev.attributes.get("experience_count").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            ev.attributes.get("education").map(String::as_str),
            Some("University of Melbourne — BSc, Computer Science")
        );

        // Address from ≥2 location parts, with an uppercased country tag.
        let addr = by(EntityKind::Address);
        assert_eq!(addr.len(), 1);
        assert_eq!(addr[0].value, "Melbourne, Victoria, Australia");
        assert!(addr[0].has_tag("country:AU"));

        // Emails capped + their domains deduped; freemail domain dropped.
        let emails = by(EntityKind::Email);
        assert_eq!(
            emails.len(),
            2,
            "two distinct addresses (3rd is a dup of #1)"
        );
        let domains = by(EntityKind::Domain);
        assert_eq!(
            domains.len(),
            1,
            "acme-corp.com once; gmail.com is freemail"
        );
        assert_eq!(domains[0].value, "acme-corp.com");

        // Phones: the 7+ digit number only.
        let phones = by(EntityKind::Phone);
        assert_eq!(phones.len(), 1);
        assert_eq!(phones[0].value, "+61412345678");

        // Organisations: both employers; current one tagged; job LOCATION kept.
        let orgs = by(EntityKind::Organisation);
        assert_eq!(orgs.len(), 2);
        let atlassian = orgs.iter().find(|e| e.value == "Atlassian").unwrap();
        assert!(atlassian.has_tag("current-employer"));
        assert_eq!(
            atlassian.evidence[0]
                .attributes
                .get("location")
                .map(String::as_str),
            Some("Sydney, Australia")
        );
        assert_eq!(
            atlassian.evidence[0]
                .attributes
                .get("start_date")
                .map(String::as_str),
            Some("2020-01")
        );
        let canva = orgs.iter().find(|e| e.value == "Canva").unwrap();
        assert!(!canva.has_tag("current-employer"));
        assert_eq!(
            canva.evidence[0]
                .attributes
                .get("end_date")
                .map(String::as_str),
            Some("2019-12")
        );
    }

    #[test]
    fn build_entities_empty_profile_yields_nothing() {
        let p: LinkedInProfile = serde_json::from_str("{}").unwrap();
        assert!(build_entities(&p, &target(), "scan").entities.is_empty());
    }

    #[test]
    fn build_entities_resolves_name_from_first_last_only() {
        // The email-resolve endpoint shape: no full_name, just first/last.
        let p: LinkedInProfile =
            serde_json::from_str(r#"{"first_name":"Sam","last_name":"Vimes"}"#).unwrap();
        let r = build_entities(&p, &target(), "scan");
        let person: Vec<_> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Person)
            .collect();
        assert_eq!(person.len(), 1);
        assert_eq!(person[0].value, "Sam Vimes");
    }

    #[test]
    fn build_entities_single_location_part_is_not_an_address() {
        let p: LinkedInProfile =
            serde_json::from_str(r#"{"full_name":"A B","country_full_name":"Australia"}"#).unwrap();
        let r = build_entities(&p, &target(), "scan");
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Address));
    }
}
