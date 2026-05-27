//! Proxycurl LinkedIn profile extraction. Paid (Bearer Token).
//!
//! Endpoint: `GET https://nubela.co/proxycurl/api/v2/linkedin?url=https://linkedin.com/in/{target}`
//! Auth:     Bearer Token (`HUNTSMAN_PROXYCURL_KEY`).
//!
//! Extracts full employment history, education, certifications,
//! and summary from LinkedIn profiles.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, urlencode};

const KEY_ENV: &str = "HUNTSMAN_PROXYCURL_KEY";
const SRC: &str = "proxycurl";

pub struct Proxycurl;

#[derive(Deserialize)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let api_url = if target.kind == TargetKind::Email {
            let email = target.value.trim();
            if !email.contains('@') {
                return Ok(ModuleResult::new());
            }
            format!(
                "https://nubela.co/proxycurl/api/linkedin/profile/resolve/email?work_email={}",
                urlencode(email),
            )
        } else {
            let linkedin_url = if target.kind == TargetKind::Url {
                let v = target.value.trim().to_lowercase();
                if !v.contains("linkedin.com/in/") {
                    return Ok(ModuleResult::new());
                }
                target.value.trim().to_string()
            } else {
                let username = target.value.trim();
                if username.is_empty() || username.len() > 100 {
                    return Ok(ModuleResult::new());
                }
                format!("https://linkedin.com/in/{username}")
            };
            format!(
                "https://nubela.co/proxycurl/api/v2/linkedin?url={}",
                urlencode(&linkedin_url),
            )
        };

        let url = api_url;

        let resp = ctx
            .http
            .get(&url)
            .bearer_auth(key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let profile: LinkedInProfile = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut result = ModuleResult::new();

        if let Some(name) = profile.full_name.as_deref()
            && name.len() >= 3
        {
            let mut pe = Entity::new(EntityKind::Person, name, 0.85, &ctx.scan_id);
            pe.tag("proxycurl");
            pe.tag("linkedin");
            let mut ev = Evidence::new(SRC, format!("LinkedIn profile: {name}"))
                .with_attr("target", &target.value);
            if let Some(h) = profile.headline.as_deref() {
                ev = ev.with_attr("headline", h);
            }
            if let Some(occ) = profile.occupation.as_deref() {
                ev = ev.with_attr("occupation", occ);
            }
            if let Some(pid) = profile.public_identifier.as_deref() {
                ev = ev.with_attr("linkedin_id", pid);
            }
            if let Some(c) = profile.connections {
                ev = ev.with_attr("connections", c.to_string());
            }
            if !profile.experiences.is_empty() {
                let current: Vec<&str> = profile
                    .experiences
                    .iter()
                    .filter(|e| e.ends_at.is_none())
                    .filter_map(|e| e.company.as_deref())
                    .take(3)
                    .collect();
                if !current.is_empty() {
                    ev = ev.with_attr("current_companies", current.join(", "));
                }
                ev = ev.with_attr("experience_count", profile.experiences.len().to_string());
            }
            if !profile.education.is_empty() {
                let schools: Vec<&str> = profile
                    .education
                    .iter()
                    .filter_map(|e| e.school.as_deref())
                    .take(3)
                    .collect();
                if !schools.is_empty() {
                    ev = ev.with_attr("education", schools.join(", "));
                }
            }
            pe.add_evidence(ev);
            result.push(pe);
        }

        let loc_parts: Vec<&str> = [
            profile.city.as_deref(),
            profile.state.as_deref(),
            profile.country_full_name.as_deref(),
        ]
        .iter()
        .filter_map(|p| *p)
        .filter(|p| !p.is_empty())
        .collect();

        if loc_parts.len() >= 2 {
            let location = loc_parts.join(", ");
            let mut ae = Entity::new(EntityKind::Address, &location, 0.60, &ctx.scan_id);
            ae.tag("proxycurl");
            ae.tag("linkedin");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(SRC, format!("LinkedIn location: {location}")));
            if let Some(cc) = profile.country.as_deref() {
                ae.tag(format!("country:{}", cc.to_uppercase()));
            }
            result.push(ae);
        }

        for email in profile.personal_emails.iter().take(3) {
            if email.contains('@') {
                let mut ee = Entity::new(EntityKind::Email, email, 0.80, &ctx.scan_id);
                ee.tag("proxycurl");
                ee.tag("linkedin");
                ee.add_evidence(Evidence::new(
                    SRC,
                    "Personal email from LinkedIn".to_string(),
                ));
                result.push(ee);
            }
        }

        for email in &profile.personal_emails {
            if let Some(domain) = email.split('@').nth(1) {
                let domain = domain.trim().to_lowercase();
                if domain.contains('.')
                    && domain.len() >= 4
                    && !crate::modules::email_parse::is_freemail(&domain)
                {
                    let mut de = Entity::new(EntityKind::Domain, &domain, 0.68, &ctx.scan_id);
                    de.tag("proxycurl");
                    de.tag("linkedin");
                    de.tag("derived");
                    de.add_evidence(Evidence::new(SRC, "Email domain from LinkedIn profile"));
                    result.push(de);
                }
            }
        }

        for phone in profile.personal_numbers.iter().take(3) {
            if phone.len() >= 7 {
                let mut phe = Entity::new(EntityKind::Phone, phone, 0.75, &ctx.scan_id);
                phe.tag("proxycurl");
                phe.tag("linkedin");
                phe.add_evidence(Evidence::new(SRC, "Phone from LinkedIn".to_string()));
                result.push(phe);
            }
        }

        for exp in profile.experiences.iter().take(5) {
            if let Some(company) = exp.company.as_deref()
                && company.len() >= 2
            {
                let mut oe = Entity::new(EntityKind::Organisation, company, 0.65, &ctx.scan_id);
                oe.tag("proxycurl");
                oe.tag("linkedin");
                let mut ev = Evidence::new(SRC, format!("Employer: {company}"));
                if let Some(title) = exp.title.as_deref() {
                    ev = ev.with_attr("title", title);
                }
                if let Some(start) = &exp.starts_at {
                    let s = start.to_string_approx();
                    if !s.is_empty() {
                        ev = ev.with_attr("start_date", s);
                    }
                }
                if let Some(end) = &exp.ends_at {
                    let e = end.to_string_approx();
                    if !e.is_empty() {
                        ev = ev.with_attr("end_date", e);
                    }
                } else {
                    oe.tag("current-employer");
                }
                oe.add_evidence(ev);
                result.push(oe);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parse_response() {
        let raw = r#"{
            "full_name": "Jane Doe",
            "first_name": "Jane",
            "last_name": "Doe",
            "headline": "Software Engineer",
            "city": "Melbourne",
            "state": "Victoria",
            "country_full_name": "Australia",
            "country": "AU",
            "occupation": "Senior Software Engineer at Atlassian",
            "connections": 500,
            "experiences": [
                {"company": "Atlassian", "title": "Senior Engineer", "starts_at": {"year": 2020, "month": 1}}
            ],
            "education": [
                {"school": "University of Melbourne", "degree_name": "BSc", "field_of_study": "CS"}
            ],
            "personal_emails": ["jane@example.com"],
            "personal_numbers": ["+61412345678"]
        }"#;
        let r: LinkedInProfile = serde_json::from_str(raw).unwrap();
        assert_eq!(r.full_name.as_deref(), Some("Jane Doe"));
        assert_eq!(r.country.as_deref(), Some("AU"));
        assert_eq!(r.experiences.len(), 1);
        assert_eq!(r.personal_emails.len(), 1);
    }

    #[test]
    fn date_field_to_string() {
        let d = DateField {
            year: Some(2020),
            month: Some(3),
        };
        assert_eq!(d.to_string_approx(), "2020-03");
        let d2 = DateField {
            year: Some(2020),
            month: None,
        };
        assert_eq!(d2.to_string_approx(), "2020");
        let d3 = DateField {
            year: None,
            month: None,
        };
        assert_eq!(d3.to_string_approx(), "");
    }
}
