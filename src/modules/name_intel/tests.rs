use super::*;
    use std::collections::HashMap;

    fn ctx(scan: &str) -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: scan.into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    #[tokio::test]
    async fn metadata_and_acceptance() {
        let m = NameIntel;
        assert_eq!(m.name(), "name_intel");
        assert!(m.is_passive());
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Meyers")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        // Default consumes() (probes accepts) must report exactly FullName so
        // the dispatch index serves it — and only it.
        assert_eq!(m.consumes(), vec![TargetKind::FullName]);
    }

    #[tokio::test]
    async fn emits_usernames_emails_and_pivots() {
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Jordan Leigh Meyers 1987"),
                &ctx("scan-x"),
            )
            .await
            .unwrap();

        let mut persons = 0;
        let mut usernames = 0;
        let mut emails = 0;
        let mut pivots = 0;
        let mut gravatar_seen = false;
        for e in &out.entities {
            match e.kind {
                EntityKind::Person => {
                    persons += 1;
                    // The subject anchor: the operator's name, Probable-tier, so
                    // derived handles have an individual to attach to.
                    assert!(e.has_tag("subject") && e.has_tag("seed"));
                    assert_eq!(e.classify(), crate::core::entity::Classification::Probable);
                }
                EntityKind::Username => {
                    usernames += 1;
                    assert!(e.has_tag("name-derived"));
                }
                EntityKind::Email => {
                    emails += 1;
                    assert!(e.has_tag("permuted"));
                    assert!(e.value.contains('@'));
                    if e.evidence
                        .iter()
                        .any(|ev| ev.attributes.contains_key("gravatar"))
                    {
                        gravatar_seen = true;
                    }
                }
                EntityKind::Url => {
                    pivots += 1;
                    assert!(e.has_tag("search-pivot"));
                    assert!(e.raw_value.starts_with("https://"));
                }
                ref other => panic!("unexpected kind {other}"),
            }
        }
        assert_eq!(persons, 1, "exactly one subject Person anchor");
        assert!(usernames > 5, "expected several usernames, got {usernames}");
        assert!(emails > 0, "expected emails, got {emails}");
        assert!(pivots > 5, "expected several pivots, got {pivots}");
        assert!(gravatar_seen, "emails must carry a gravatar attribute");
    }

    #[tokio::test]
    async fn source_name_attribute_is_cleaned_not_the_raw_contaminated_target() {
        // A re-expansion pass can feed a quote/comma-contaminated breach Person
        // value back in as the target. Every emitted entity's `source_name`
        // evidence attribute must record the CLEANED display name, never the raw
        // `"Matthew Diegmann",`, so a later merge can't accumulate the observed
        // junk `"Matthew Diegmann",; Matthew Diegmann`.
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "\"Matthew Diegmann\","),
                &ctx("scan-z"),
            )
            .await
            .unwrap();
        assert!(!out.entities.is_empty(), "the contaminated name still parses");
        for e in &out.entities {
            for ev in &e.evidence {
                if let Some(sn) = ev.attributes.get("source_name") {
                    assert_eq!(
                        sn, "Matthew Diegmann",
                        "source_name must be the cleaned name, not the raw target"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn single_token_name_yields_only_the_subject_anchor() {
        // A mononym ("Madonna", "Sukarno") can't split into first/last, so there
        // are no derived usernames/emails — but the operator's subject must STILL
        // be anchored as a node in its own report. `seed_anchor_entity` delegates
        // FullName to this module, so it is the SOLE anchor for a name seed; if it
        // emitted nothing here the subject would vanish entirely (the bug this
        // fixes), breaking the always-anchored invariant.
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Madonna"),
                &ctx("scan-y"),
            )
            .await
            .unwrap();
        assert_eq!(
            out.entities.len(),
            1,
            "a mononym yields exactly the subject anchor (no derived identifiers)"
        );
        let p = &out.entities[0];
        assert_eq!(p.kind, EntityKind::Person);
        assert_eq!(p.value, "Madonna");
        assert!(
            p.has_tag("seed") && p.has_tag("subject"),
            "the anchor must carry the seed/subject tags"
        );
    }

    #[tokio::test]
    async fn non_latin_name_emits_person_and_pivots_but_no_handles() {
        // Cyrillic name: Иван Петров (Ivan Petrov). ASCII-folds to empty handle
        // tokens, so username/email permutation must be skipped. A Person anchor
        // and display-name search pivots must still be emitted.
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Иван Петров"),
                &ctx("scan-z"),
            )
            .await
            .unwrap();

        assert!(
            out.entities.iter().any(|e| e.kind == EntityKind::Person),
            "Person anchor must be emitted for non-Latin name"
        );
        assert!(
            out.entities.iter().any(|e| e.kind == EntityKind::Url),
            "search-pivot Urls must be emitted for non-Latin name"
        );
        assert!(
            !out.entities.iter().any(|e| e.kind == EntityKind::Username),
            "no Username should be emitted when ASCII handle is empty"
        );
        assert!(
            !out.entities.iter().any(|e| e.kind == EntityKind::Email),
            "no Email should be emitted when ASCII handle is empty"
        );
    }

    #[tokio::test]
    async fn subject_person_confidence_is_probable_tier() {
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Alex Torres"),
                &ctx("scan-p"),
            )
            .await
            .unwrap();
        let person = out
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("Person anchor must be present");
        assert!(
            person.confidence >= permute::SUBJECT_CONF,
            "Person anchor confidence {:.2} must be at least SUBJECT_CONF ({:.2})",
            person.confidence,
            permute::SUBJECT_CONF
        );
        assert!(
            person.has_tag("seed") && person.has_tag("subject"),
            "Person anchor must carry 'seed' and 'subject' tags"
        );
    }

    #[tokio::test]
    async fn attack_techniques_matches_produced_entity_kinds() {
        // With no override this module silently inherited the full People
        // default (T1589.003 + T1591.004) — over-claiming Identify Roles
        // (this module has zero role/organisational logic anywhere) while
        // never crediting the Email Addresses technique for the Email
        // entities it explicitly produces. Mirrors the same over/under-claim
        // fix already shipped for `pgp`.
        let m = NameIntel;
        let techniques = m.attack_techniques();
        assert!(
            techniques.contains(&"T1589.003"),
            "Employee Names: the subject Person anchor and derived usernames"
        );
        assert!(
            techniques.contains(&"T1589.002"),
            "Email Addresses: derived speculative Email entities"
        );
        assert!(
            !techniques.contains(&"T1591.004"),
            "Identify Roles must not be claimed: no role/org info is ever derived"
        );
        for &id in techniques {
            assert!(
                crate::core::attack::technique(id).is_some(),
                "{id} must be a catalogued Reconnaissance technique"
            );
        }
    }

    // ── Onur Ada seed ────────────────────────────────────────────────────────
    // Validate the full module pipeline with "Onur Ada" as the live starting seed.
    // This is a pure offline derivation test — no network, no I/O, byte-identical.

    #[tokio::test]
    async fn onur_ada_full_pipeline_produces_person_handles_emails_and_pivots() {
        let m = NameIntel;
        let out = m
            .process(&Target::new(TargetKind::FullName, "Onur Ada"), &ctx("scan-onur-ada"))
            .await
            .unwrap();

        let person = out
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("Person anchor must be emitted for 'Onur Ada'");
        assert_eq!(
            person.classify(),
            crate::core::entity::Classification::Probable,
            "Person anchor must be Probable-tier"
        );
        assert!(person.has_tag("subject") && person.has_tag("seed"));

        let usernames: Vec<_> = out.entities.iter().filter(|e| e.kind == EntityKind::Username).collect();
        let emails: Vec<_> = out.entities.iter().filter(|e| e.kind == EntityKind::Email).collect();
        let pivots: Vec<_> = out.entities.iter().filter(|e| e.kind == EntityKind::Url).collect();
        assert!(usernames.len() > 5, "expected several derived handles, got {}", usernames.len());
        assert!(!emails.is_empty(), "expected email candidates for 'Onur Ada'");
        assert!(pivots.len() > 5, "expected search pivots for 'Onur Ada'");

        // Core handle shapes must be present in the derived set.
        let handles: Vec<&str> = usernames.iter().map(|e| e.value.as_str()).collect();
        for want in ["onur.ada", "onurada", "onur_ada", "ada.onur"] {
            assert!(handles.contains(&want), "missing handle '{want}': {handles:?}");
        }

        // Top email must be the primary Gmail shape.
        let first_email = emails.first().expect("at least one email").value.as_str();
        assert_eq!(first_email, "onur.ada@gmail.com", "first email must be onur.ada@gmail.com");
    }

    #[tokio::test]
    async fn onur_ada_seed_is_unexpanded_in_gap_report_until_linked() {
        // A fresh "Onur Ada" Person entity with no relations is an Unexpanded
        // orphan — the gap analysis names it, classifies it, and points at the
        // corrective scan. This test exercises the full seed→gap pipeline.
        use crate::core::{entity::EntityKind, gap};

        let mut entity = crate::core::entity::Entity::new(
            EntityKind::Person,
            "Onur Ada",
            0.65,
            "scan-onur-ada",
        );
        entity.tag("seed");
        entity.tag("subject");

        let report = gap::analyze(&[entity], &[]);
        assert!(!report.null_state, "a seeded scan is not null state");
        assert_eq!(report.total_seeds, 1);
        assert_eq!(report.isolated_seeds, 1);
        assert_eq!(report.linked_seeds, 0);
        assert_eq!(report.orphans.len(), 1);

        let orphan = &report.orphans[0];
        assert_eq!(orphan.value, "Onur Ada");
        assert_eq!(orphan.isolation, gap::Isolation::Unexpanded,
            "confidence 0.65 is above EXPAND_FLOOR — must be Unexpanded, not {:?}", orphan.isolation);
        assert_eq!(
            orphan.reinjection_target.as_deref(),
            Some("full_name"),
            "Person entity must re-inject as full_name"
        );
    }
