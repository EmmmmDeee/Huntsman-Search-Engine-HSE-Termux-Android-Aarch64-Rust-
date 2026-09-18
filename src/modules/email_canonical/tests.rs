use crate::core::confidence;
use super::*;
    use std::collections::HashMap;

    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    #[test]
    fn gmail_dots_are_stripped() {
        assert_eq!(
            canonicalise("john.doe@gmail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn gmail_plus_tag_and_dots_stripped_together() {
        assert_eq!(
            canonicalise("john.doe+newsletter@gmail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn googlemail_alias_folds_to_gmail() {
        assert_eq!(
            canonicalise("johndoe@googlemail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn case_is_normalised() {
        assert_eq!(
            canonicalise("JOHN.DOE@GMAIL.COM").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn plus_tag_stripped_for_non_gmail_provider() {
        // +tag subaddressing applies broadly; dots are NOT stripped off-Gmail.
        assert_eq!(
            canonicalise("jane+promo@outlook.com").as_deref(),
            Some("jane@outlook.com")
        );
        // dots are significant for non-Gmail → no change → None
        assert_eq!(canonicalise("jane.smith@outlook.com"), None);
    }

    #[test]
    fn already_canonical_yields_none() {
        assert_eq!(canonicalise("johndoe@gmail.com"), None);
        assert_eq!(canonicalise("jane@outlook.com"), None);
    }

    #[test]
    fn malformed_addresses_yield_none() {
        assert_eq!(canonicalise("notanemail"), None);
        assert_eq!(canonicalise("@gmail.com"), None);
        assert_eq!(canonicalise("user@localhost"), None); // no dot in domain
        assert_eq!(canonicalise("+tag@gmail.com"), None); // empty base local
    }

    #[tokio::test]
    async fn process_emits_canonical_email_above_floor() {
        let t = Target::new(TargetKind::Email, "j.doe+work@googlemail.com");
        let r = EmailCanonical.process(&t, &ctx()).await.expect("should succeed");
        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Email);
        assert_eq!(e.value, "jdoe@gmail.com");
        assert!(
            e.confidence >= confidence::MEDIUM,
            "canonical mailbox should pivot at depth"
        );
        assert!(e.has_tag("canonical"));
        assert_eq!(e.evidence[0].source, SRC);
    }

    #[tokio::test]
    async fn process_emits_nothing_when_already_canonical() {
        let t = Target::new(TargetKind::Email, "jdoe@gmail.com");
        let r = EmailCanonical.process(&t, &ctx()).await.expect("should succeed");
        assert!(r.entities.is_empty());
    }

    #[test]
    fn accepts_email_only_and_is_passive() {
        assert!(EmailCanonical.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!EmailCanonical.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(EmailCanonical.is_passive());
        assert_eq!(EmailCanonical.category(), ModuleCategory::Email);
    }

#[test]
fn an_unknown_domain_keeps_its_plus_tag() {
    // REQ-EMAILCANON-001. `+tag` subaddressing is a per-mail-server opt-in
    // (RFC 5233), not a property of the address string, so folding it for
    // EVERY domain fused two potentially DIFFERENT real people onto one
    // identity — and this module emits the fold as a new Email entity at
    // `CANON_CONF` (0.80, deliberately above the expansion floor), calling it
    // "a proven-equivalent address (not a guess)", so the scan then pivots the
    // whole email pipeline onto the fabricated link.
    //
    // Concretely: `bob+x@smallbiz.example` and `bob@smallbiz.example` on a
    // domain that never enabled subaddressing may be two different mailboxes
    // (or one held and one undeliverable). An unrecognised domain must
    // therefore keep its tag — a missed merge is recoverable, a false merge
    // silently corrupts an identity.
    //
    // The old behaviour was not an oversight but an active belief: the shared
    // helper's own doctest asserted `jane+promo@corp.com` → `jane@corp.com`
    // on a plainly generic domain.
    for arbitrary in [
        "bob+x@smallbiz.example",
        "jane+promo@corp.com",
        "user+tag@selfhosted.dev",
        "a+b@some-company.com.au",
    ] {
        assert_eq!(
            canonicalise(arbitrary).as_deref(),
            None,
            "{arbitrary} has no canonical form distinct from itself, so no \
             entity may be minted claiming equivalence",
        );
    }
}

#[test]
fn a_known_subaddressing_provider_still_folds_its_plus_tag() {
    // Guard for the fix above: the allowlisted providers' tags must still
    // fold, or the fix has traded a false merge for a missed one across every
    // major consumer mailbox. Each of these is documented default-on.
    for (tagged, want) in [
        ("jane+promo@outlook.com", "jane@outlook.com"),
        ("jane+promo@hotmail.com", "jane@hotmail.com"),
        ("jane+promo@live.com", "jane@live.com"),
        ("jane+promo@fastmail.com", "jane@fastmail.com"),
        ("jane+promo@proton.me", "jane@proton.me"),
        ("jane+promo@protonmail.com", "jane@protonmail.com"),
        ("jane+promo@icloud.com", "jane@icloud.com"),
        ("jane+promo@me.com", "jane@me.com"),
    ] {
        assert_eq!(
            canonicalise(tagged).as_deref(),
            Some(want),
            "{tagged} is a documented subaddressing provider and must still fold",
        );
    }
}
