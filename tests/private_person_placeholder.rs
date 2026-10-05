use huntsman_recon::validation::{ValueKind, is_placeholder_entity, is_whois_privacy_placeholder};

#[test]
fn whois_private_person_placeholder_is_rejected_without_rejecting_private_limited() {
    assert!(
        is_whois_privacy_placeholder("Private Person"),
        "live v1.41 evidence showed WHOIS emitted this privacy placeholder as a real Person"
    );
    assert!(is_whois_privacy_placeholder("PRIVATE PERSON"));
    assert!(is_placeholder_entity(&ValueKind::Person, "Private Person"));

    assert!(
        !is_whois_privacy_placeholder("Infosys Private Limited"),
        "a bare `private` substring is too broad: legitimate Private Limited companies must survive"
    );
    assert!(!is_placeholder_entity(&ValueKind::Person, "Alice Smith"));
}
