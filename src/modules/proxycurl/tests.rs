use super::Proxycurl;
use super::build::build_entities;
use super::build::email_domain;
use super::types::{Certification, DateField, Education, LinkedInProfile};
use super::url::profile_url;
use crate::core::{
    confidence,
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

fn target() -> Target {
    Target::new(TargetKind::Username, "janedoe")
}

#[test]
fn emails_and_phones_are_not_capped() {
    // A profile listing five distinct personal emails and five valid phones — all
    // must surface. The prior MAX_EMAILS/MAX_PHONES=3 caps dropped the subject's
    // own real contact pivots (and the emails' derived non-freemail domains).
    let raw = r#"{
        "public_identifier": "multi",
        "personal_emails": ["a@acme1.com","b@acme2.com","c@acme3.com","d@acme4.com","e@acme5.com"],
        "personal_numbers": ["+61400000001","+61400000002","+61400000003","+61400000004","+61400000005"]
    }"#;
    let profile: LinkedInProfile = serde_json::from_str(raw).expect("should succeed");
    let r = build_entities(&profile, &target(), "scan");
    let count = |k: EntityKind| r.entities.iter().filter(|e| e.kind == k).count();
    assert_eq!(
        count(EntityKind::Email),
        5,
        "every distinct personal email emitted, not capped at 3"
    );
    assert_eq!(
        count(EntityKind::Phone),
        5,
        "every valid personal phone emitted, not capped at 3"
    );
    assert_eq!(
        count(EntityKind::Domain),
        5,
        "each email's derived non-freemail domain emitted"
    );
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
        "certifications": [
            {"name": "AWS Certified Solutions Architect", "authority": "Amazon Web Services"},
            {"name": "CISSP"}
        ],
        "personal_emails": ["jane@acme-corp.com", "jane@gmail.com", "jane@acme-corp.com"],
        "personal_numbers": ["+61412345678", "123"]
    }"#;
    serde_json::from_str(raw).expect("should succeed")
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
    let email = profile_url(&Target::new(TargetKind::Email, "a@b.com")).expect("should succeed");
    assert!(email.contains("resolve/email?work_email="));
<<<<<<< HEAD
    let url = profile_url(&Target::new(TargetKind::Url, "https://linkedin.com/in/x")).expect("should succeed");
=======
    let url = profile_url(&Target::new(TargetKind::Url, "https://linkedin.com/in/x"))
        .expect("should succeed");
>>>>>>> origin/main
    assert!(url.contains("api/v2/linkedin?url="));
    let user = profile_url(&Target::new(TargetKind::Username, "x")).expect("should succeed");
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
        let mut p: LinkedInProfile = serde_json::from_str("{}").expect("should succeed");
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
fn certification_describe_combines_name_and_authority() {
    let mk = |n: Option<&str>, a: Option<&str>| {
        Certification {
            name: n.map(String::from),
            authority: a.map(String::from),
        }
        .describe()
    };
    assert_eq!(
        mk(Some("CISSP"), Some("ISC2")).as_deref(),
        Some("CISSP (ISC2)")
    );
    assert_eq!(mk(Some("CISSP"), None).as_deref(), Some("CISSP"));
    assert_eq!(mk(None, Some("ISC2")), None); // no name → no entry
}

#[test]
fn build_entities_omits_certifications_attr_when_absent() {
    // A profile with no certifications must not carry an empty attr.
<<<<<<< HEAD
    let profile: LinkedInProfile = serde_json::from_str(r#"{"full_name": "Jane Doe"}"#).expect("should succeed");
=======
    let profile: LinkedInProfile =
        serde_json::from_str(r#"{"full_name": "Jane Doe"}"#).expect("should succeed");
>>>>>>> origin/main
    let r = build_entities(&profile, &target(), "scan");
    let person = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("person entity");
    assert!(
        !person.evidence[0].attributes.contains_key("certifications"),
        "no certifications field → no attr"
    );
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
fn build_entities_mints_the_vanity_handle_as_a_username() {
    // The `public_identifier` (`/in/{slug}`) is a cross-platform identity pivot,
    // not just the Person's `linkedin_id` attribute — it must also surface as a
    // platform-prefixed Username so BFS can pivot on the handle.
    let r = build_entities(&full_profile(), &target(), "scan");
    let handle = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("vanity handle surfaces as a Username");
    assert_eq!(handle.value, "linkedin:jane-doe");
    assert!(handle.has_tag("linkedin") && handle.has_tag("proxycurl"));
}

#[test]
fn build_entities_extracts_full_profile() {
    use crate::core::entity::Entity;
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
    // Certifications the description() promised but the struct never parsed.
    assert_eq!(
        ev.attributes.get("certifications").map(String::as_str),
        Some("AWS Certified Solutions Architect (Amazon Web Services); CISSP")
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

    // Organisations: both employers plus the alma mater; current employer
    // tagged; job LOCATION kept; school carries degree/field_of_study.
    let orgs = by(EntityKind::Organisation);
    assert_eq!(orgs.len(), 3);
    let uni = orgs
        .iter()
        .find(|e| e.value == "University of Melbourne")
        .expect("should succeed");
    assert!(uni.has_tag("education"));
    assert_eq!(uni.confidence, confidence::MEDIUM_HIGH);
    assert_eq!(
        uni.evidence[0].attributes.get("degree").map(String::as_str),
        Some("BSc")
    );
    assert_eq!(
        uni.evidence[0]
            .attributes
            .get("field_of_study")
            .map(String::as_str),
        Some("Computer Science")
    );
<<<<<<< HEAD
    let atlassian = orgs.iter().find(|e| e.value == "Atlassian").expect("should succeed");
=======
    let atlassian = orgs
        .iter()
        .find(|e| e.value == "Atlassian")
        .expect("should succeed");
>>>>>>> origin/main
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
<<<<<<< HEAD
    let canva = orgs.iter().find(|e| e.value == "Canva").expect("should succeed");
=======
    let canva = orgs
        .iter()
        .find(|e| e.value == "Canva")
        .expect("should succeed");
>>>>>>> origin/main
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
    let p: LinkedInProfile = serde_json::from_str("{}").expect("should succeed");
    assert!(build_entities(&p, &target(), "scan").entities.is_empty());
}

#[test]
fn build_entities_resolves_name_from_first_last_only() {
    // The email-resolve endpoint shape: no full_name, just first/last.
<<<<<<< HEAD
    let p: LinkedInProfile =
        serde_json::from_str(r#"{"first_name":"Sam","last_name":"Vimes"}"#).expect("should succeed");
=======
    let p: LinkedInProfile = serde_json::from_str(r#"{"first_name":"Sam","last_name":"Vimes"}"#)
        .expect("should succeed");
>>>>>>> origin/main
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
<<<<<<< HEAD
        serde_json::from_str(r#"{"full_name":"A B","country_full_name":"Australia"}"#).expect("should succeed");
=======
        serde_json::from_str(r#"{"full_name":"A B","country_full_name":"Australia"}"#)
            .expect("should succeed");
>>>>>>> origin/main
    let r = build_entities(&p, &target(), "scan");
    assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Address));
}
