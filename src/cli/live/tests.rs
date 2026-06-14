use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::event::EventKind;

    #[test]
    fn render_entity_prints_full_unredacted_evidence() {
        // A stealer record: the password and raw URL MUST appear verbatim — the
        // live view is the transparency contract, nothing masked or truncated.
        let mut e = Entity::new(
            EntityKind::Credential,
            "victim@https://site/login",
            0.6,
            "scan",
        );
        e.tag("see-know");
        e.tag("stealer");
        e.add_evidence(
            Evidence::new("see_know", "SeekNow record from RedlineStealer")
                .with_attr("password", "hunter2-PLAINTEXT")
                .with_attr("url", "https://site/login")
                .with_attr("source", "RedlineStealer"),
        );
        let out = render_event(&EventKind::EntityFound { entity: e });
        assert!(out.contains("victim@https://site/login"));
        assert!(out.contains("see-know, stealer"), "tags must show: {out}");
        // The cleartext secret is present, in full, unmasked.
        assert!(out.contains("password: hunter2-PLAINTEXT"), "got: {out}");
        assert!(out.contains("url: https://site/login"));
    }

    #[test]
    fn render_event_suppresses_empty_module_done() {
        // A module that found nothing yields no line (kept quiet), but a
        // productive one is announced.
        assert_eq!(
            render_event(&EventKind::ModuleDone {
                module: "see_know".into(),
                found: 0,
            }),
            ""
        );
        assert!(
            render_event(&EventKind::ModuleDone {
                module: "see_know".into(),
                found: 3,
            })
            .contains("see_know")
        );
    }
