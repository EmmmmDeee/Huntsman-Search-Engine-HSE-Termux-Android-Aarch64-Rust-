use super::*;

const SRC_URL: &str = "https://example.com/.well-known/security.txt";

fn kinds(es: &[Entity], k: &EntityKind) -> usize {
    es.iter().filter(|e| &e.kind == k).count()
}

#[test]
fn module_metadata() {
    let m = SecurityTxt;
    assert_eq!(m.name(), "security_txt");
    assert!(!m.description().trim().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/x")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn parses_a_full_security_txt() {
    let body = "\
# Our security policy
Contact: mailto:security@example.com
Contact: tel:+12015550123
Contact: https://example.com/security-contact
Encryption: https://example.com/pgp-key.txt
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
Expires: 2027-01-01T00:00:00.000Z
";
    let es = parse_security_txt(body, SRC_URL, "s");

    assert_eq!(kinds(&es, &EntityKind::Email), 1, "one email contact");
    assert_eq!(kinds(&es, &EntityKind::Phone), 1, "one phone contact");
    // web contact + encryption + canonical + policy = 4 Urls.
    assert_eq!(kinds(&es, &EntityKind::Url), 4, "four URL fields");

    let email = es.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(email.value, "security@example.com");
    assert!(email.has_tag("security-contact") && email.has_tag("security-txt"));

    // The Encryption URL is tagged pgp.
    assert!(
        es.iter()
            .any(|e| e.kind == EntityKind::Url && e.has_tag("pgp")),
        "encryption URL tagged pgp"
    );
}

#[test]
fn bare_email_contact_without_mailto_scheme_is_accepted() {
    let es = parse_security_txt("Contact: security@example.org\n", SRC_URL, "s");
    assert_eq!(kinds(&es, &EntityKind::Email), 1);
    assert_eq!(es[0].value, "security@example.org");
}

#[test]
fn comments_blanks_and_unknown_fields_are_ignored() {
    let body = "\
# comment line

Expires: 2027-01-01T00:00:00Z
Preferred-Languages: en, fr
Contact: mailto:abuse@example.com
";
    let es = parse_security_txt(body, SRC_URL, "s");
    // Only the Contact email; Expires / Preferred-Languages / comment ignored.
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Email);
}

#[test]
fn field_names_are_case_insensitive() {
    let es = parse_security_txt("CONTACT: mailto:sec@example.com\n", SRC_URL, "s");
    assert_eq!(kinds(&es, &EntityKind::Email), 1);
}

#[test]
fn repeated_contacts_are_deduplicated() {
    let body = "\
Contact: mailto:security@example.com
Contact: mailto:security@example.com
Contact: mailto:SECURITY@example.com
";
    let es = parse_security_txt(body, SRC_URL, "s");
    assert_eq!(es.len(), 1, "same address (case-insensitive) emitted once");
}

#[test]
fn non_url_encryption_value_is_ignored() {
    // A PGP fingerprint (openpgp4fpr:) carries no fetchable location.
    let body = "\
Contact: mailto:security@example.com
Encryption: openpgp4fpr:5F2B4756ABC0123456789ABCDEF0123456789ABC
";
    let es = parse_security_txt(body, SRC_URL, "s");
    assert_eq!(kinds(&es, &EntityKind::Url), 0, "fingerprint is not a Url");
    assert_eq!(kinds(&es, &EntityKind::Email), 1);
}

#[test]
fn acknowledgements_spelling_variants_both_parse() {
    let us = parse_security_txt("Acknowledgments: https://example.com/thanks\n", SRC_URL, "s");
    let uk = parse_security_txt("Acknowledgements: https://example.com/thanks\n", SRC_URL, "s");
    assert_eq!(kinds(&us, &EntityKind::Url), 1);
    assert_eq!(kinds(&uk, &EntityKind::Url), 1);
}

#[test]
fn looks_like_security_txt_guards_html_200() {
    assert!(looks_like_security_txt("Contact: mailto:a@b.com\n"));
    assert!(looks_like_security_txt("# hi\nCONTACT: https://x/y\n"));
    // A 200-OK HTML "not found" page must NOT be treated as a security.txt.
    assert!(!looks_like_security_txt(
        "<!doctype html><html><body>404 Not Found</body></html>"
    ));
    assert!(!looks_like_security_txt("Policy: https://x/p\n"));
}

#[test]
fn is_http_url_matches_only_web_urls() {
    assert!(is_http_url("https://example.com"));
    assert!(is_http_url("HTTP://example.com"));
    assert!(!is_http_url("mailto:a@b.com"));
    assert!(!is_http_url("openpgp4fpr:ABCD"));
}
