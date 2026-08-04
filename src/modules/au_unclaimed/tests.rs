use super::*;

#[test]
fn accepts_fullname_and_org() {
    let m = AuUnclaimed;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Ha"))); // too short
}

#[test]
fn module_metadata() {
    let m = AuUnclaimed;
    assert_eq!(m.name(), "au_unclaimed");
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert_eq!(m.cost(), ModuleCost::Free);
}

#[test]
fn module_covers_queensland() {
    // The QLD register is folded in here now (no separate qld_unclaimed module).
    let m = AuUnclaimed;
    assert!(m.description().contains("QLD"));
    // Person + Organisation pivots come from the QLD owner-parsing pass.
    assert!(m.produces().contains(&EntityKind::Person));
    assert!(m.produces().contains(&EntityKind::Organisation));
}

// A genuine end-to-end exercise of the (T2.119-fixed) `process()` path against
// the real QLD Public Trustee CKAN datastore — proving the primary fetch,
// `success` check, parse, and entity extraction all work on live data and that
// a healthy query returns `Ok` (never the new error path spuriously). Ignored
// by default (hits the network); run manually with `--ignored`. Mirrors the
// sibling ASIC modules' live tests.
#[tokio::test]
#[ignore = "hits the live data.qld.gov.au unclaimed-money datastore; run manually"]
async fn au_unclaimed_live_finds_qld_records_for_a_common_surname() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let r = AuUnclaimed
        .process(&Target::new(TargetKind::FullName, "John Smith"), &ctx)
        .await
        .expect("a healthy live QLD query must return Ok, not the T2.119 error path");
    eprintln!("au_unclaimed live: {} entities", r.entities.len());
    assert!(
        !r.entities.is_empty(),
        "the QLD unclaimed-money register holds many 'Smith' records — a live \
         query should surface at least one entity"
    );
}

// ── Queensland pass (folded in from the former `qld_unclaimed` module) ──────
//
// These pin that QLD's distinctive, richer capability survives the merge: joint
// owner parsing into Persons, company-owner Organisation pivots, the
// surname-vs-exact family classification, postcode→QLD geo addresses, and
// suburb-level locality enumeration. The evidence source stays `qld_unclaimed`
// so the downstream correlator/relation rules keyed on it keep working.
mod qld {
    use super::super::qld_helpers::{
        SRC, owner_person_names, records_to_entities, suburbs_to_entities,
    };
    use crate::core::entity::{Entity, EntityKind};
    use crate::util::ckan::Response as CkanResp;
    use crate::util::postcode_au::Locality;

    fn sample() -> CkanResp {
        let raw = r#"{
            "result": {
                "total": 3,
                "records": [
                    {"_id":1938437,"ClientId_ActNo":"210580670460","Owner":"HAYLEY AVERY & CURT AVERY","Amount":"545.74","SenderName":"INSURANCE AUSTRALIA GROUP LIMITED","DateRec":"2024-03-14","PCode":"4557","rank":0.0706241},
                    {"_id":913780,"ClientId_ActNo":"207768336631","Owner":"CURT AVERY","Amount":"0.92","SenderName":"REMUNERATION SERVICES","DateRec":"2015-03-31","PCode":"4555","rank":0.057308756},
                    {"_id":1082370,"ClientId_ActNo":"208285682789","Owner":"ERIK AVERY","Amount":"115.45","SenderName":"UNCM DEPT OF TPT AND MAIN ROADS - MAIN ROAD","DateRec":"2016-10-17","PCode":"4552","rank":0.057308756}
                ]
            }
        }"#;
        serde_json::from_str(raw).expect("should succeed")
    }

    #[test]
    fn owner_person_names_splits_joint_and_excludes_companies() {
        // Joint individuals split on `&`/`and`, each title-cased; companies and
        // the unknown-owner sentinel are excluded (the Organisation pass owns
        // companies).
        assert_eq!(
            owner_person_names("HAYLEY DIEGMANN & CURT DIEGMANN"),
            vec!["Hayley Diegmann".to_string(), "Curt Diegmann".to_string()]
        );
        assert!(owner_person_names("ACME WIDGETS PTY LTD").is_empty());
        assert!(owner_person_names("(unknown owner)").is_empty());
    }

    #[test]
    fn classifies_exact_person_vs_surname_only_family() {
        let recs = sample().result.expect("should succeed").records;
        let curt = records_to_entities(&recs, 3, "Curt Avery", "Avery", true, "s");
        let exact = |e: &Entity| e.tags.iter().any(|t| t.as_str() == "exact-name-match");
        let addrs: Vec<&Entity> = curt
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        assert!(exact(addrs[0]), "HAYLEY & CURT row is an exact Curt match");
        assert!(exact(addrs[1]), "CURT AVERY row is an exact Curt match");
        assert!(!exact(addrs[2]), "ERIK row is only a surname match");

        // The owner Person pass mints the family as first-class people, judged
        // per-person.
        let person = |v: &str| {
            curt.iter()
                .find(|e| e.kind == EntityKind::Person && e.value == v)
        };
        assert!(person("Curt Avery").is_some_and(exact));
        assert!(person("Erik Avery").is_some_and(|e| !exact(e) && e.confidence < crate::core::confidence::MEDIUM));
    }

    #[test]
    fn per_record_address_tags_are_correct_before_any_merge() {
        // Real-scan reproduction (a "Riley Morley" scan): two records at the SAME
        // postcode (4001), NEITHER owner matching the seed IN FULL — "MORLEY
        // SQUARE INVESTMENT PTY LTD" (a company, no person name at all) and
        // "FLANNAN MORLEY & GERALDINE F MORLEY" (surname-only family). Both share
        // the queried surname, so both clear the `owner_matches_query` gate and
        // reach the classifier (see
        // `cross_field_ckan_matches_are_dropped_not_attributed` for the rows that
        // do NOT clear it). Per `records_to_entities`'s own contract, EVERY
        // Address it returns for these two records must be tagged
        // `family-candidate`, never `exact-name-match` — confirms the per-record
        // classification itself is sound before any entity-merge step (which
        // happens downstream, outside this function) has a chance to union tags
        // across postcode-sharing records.
        let raw = r#"{"result":{"total":2,"records":[
            {"_id":100,"Owner":"MORLEY SQUARE INVESTMENT PTY LTD","Amount":"714.65","SenderName":"OFFICE OF INDUSTRIAL RELATIONS","DateRec":"2024-10-31","PCode":"4001"},
            {"_id":101,"Owner":"FLANNAN MORLEY & GERALDINE F MORLEY","Amount":"55.65","PCode":"4001"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .expect("should succeed")
            .result
            .expect("should succeed")
            .records;
        let ents = records_to_entities(&recs, 2, "Riley Morley", "Morley", true, "s");
        let addrs: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        assert_eq!(addrs.len(), 2, "one Address entity per record");
        for a in &addrs {
            assert!(
                a.tags.iter().any(|t| t.as_str() == "family-candidate"),
                "postcode-only address from a non-exact owner must be family-candidate: {:?}",
                a.tags
            );
            assert!(
                !a.tags.iter().any(|t| t.as_str() == "exact-name-match"),
                "neither owner matches 'Riley Morley' — must NOT be exact-name-match: {:?}",
                a.tags
            );
        }
    }

    #[test]
    fn cross_field_ckan_matches_are_dropped_not_attributed() {
        // Real-scan reproduction (seed "gift shop" → derived query "shop"):
        // CKAN's `datastore_search?q=` is full-text across EVERY column, so a
        // query for "shop" also returns rows whose *address* is "Shop 4, ..." —
        // ubiquitous in Australian retail. Their owners share nothing with the
        // seed, yet all of them were being emitted as `family-candidate` Persons
        // attributed to the subject: 60 of 85 owner Persons in the measured scan,
        // real named third parties clustered on one postcode.
        //
        // Rows whose OWNER matches the query survive (that is what makes a real
        // relative a family-candidate); rows that matched some other column are
        // dropped entirely — no Address, Person, Organisation, or money finding.
        let raw = r#"{"result":{"total":3,"records":[
            {"_id":1,"Owner":"JUNES CARD & GIFT SHOP","Amount":"75.00","PCode":"4106"},
            {"_id":2,"Owner":"Gavin Williams","Amount":"12.00","PCode":"4350"},
            {"_id":3,"Owner":"Malcolm Naismith","Amount":"31.00","PCode":"4350"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .expect("should succeed")
            .result
            .expect("should succeed")
            .records;
        let ents = records_to_entities(&recs, 3, "gift shop", "shop", true, "s");

        // The owner that genuinely contains the queried token survives.
        assert!(
            ents.iter().any(|e| e.value.to_uppercase().contains("GIFT SHOP")),
            "an owner containing the queried token must still be emitted"
        );
        // The two unrelated individuals must not appear as ANY entity kind.
        for unrelated in ["Gavin Williams", "Malcolm Naismith"] {
            assert!(
                !ents.iter().any(|e| e.value.contains(unrelated)),
                "{unrelated} matched on a non-owner column and must not be \
                 attributed to this subject: {:?}",
                ents.iter().map(|e| &e.value).collect::<Vec<_>>()
            );
        }
        // Their postcode-only Address must not leak either — 4350 belongs to the
        // dropped rows alone.
        assert!(
            !ents.iter().any(|e| e.value.contains("4350")),
            "a dropped row must contribute no Address"
        );
    }

    #[test]
    fn bare_initial_does_not_license_an_unrelated_owner_match() {
        // A single-letter token ("M") must not match an unrelated "M Smith" —
        // MIN_QUERY_TOKEN keeps initials from re-opening the cross-field hole.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":1,"Owner":"M Smith","Amount":"10.00","PCode":"4000"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .expect("should succeed")
            .result
            .expect("should succeed")
            .records;
        // Query "M Mcloughlin": "M" is a bare initial (ignored), "Mcloughlin"
        // does not appear in "M Smith" → the row is dropped.
        let ents = records_to_entities(&recs, 1, "M Mcloughlin", "M Mcloughlin", false, "s");
        assert!(
            ents.is_empty(),
            "a bare initial must not license the match: {:?}",
            ents.iter().map(|e| &e.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn company_owner_emits_organisation_for_abn_pivot() {
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":7,"Owner":"ACME WIDGETS PTY LTD","Amount":"1200.00","SenderName":"ASX","PCode":"4000"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .expect("should succeed")
            .result
            .expect("should succeed")
            .records;
        let ents = records_to_entities(&recs, 1, "ACME Widgets", "Widgets", true, "s");
        let org = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("company owner must emit an Organisation");
        assert_eq!(org.value, "ACME WIDGETS PTY LTD");
        assert!(org.tags.iter().any(|t| t.as_str() == "company-owner"));
    }

    #[test]
    fn sender_name_emits_payer_company_organisation() {
        // The SenderName — the employer/estate/insurer that LODGED the money — must
        // surface as a `sender-company` Organisation (the T1591.002 business
        // relationship), previously parsed into evidence and then dropped.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":8,"Owner":"Jane Citizen","Amount":"500.00","SenderName":"GLOBEX EMPLOYMENT PTY LTD","PCode":"4000"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .expect("should succeed")
            .result
            .expect("should succeed")
            .records;
        let ents = records_to_entities(&recs, 1, "Jane Citizen", "Citizen", true, "s");
        let sender = ents
            .iter()
            .find(|e| {
                e.kind == EntityKind::Organisation
                    && e.tags.iter().any(|t| t.as_str() == "sender-company")
            })
            .expect("SenderName company must emit a sender-company Organisation");
        assert!(
            sender.value.to_uppercase().contains("GLOBEX"),
            "got {}",
            sender.value
        );
        assert!(sender.tags.iter().any(|t| t.as_str() == "country:AU"));
    }

    #[test]
    fn parses_records_into_geo_addresses_tagged_qld_source() {
        let resp = sample();
        let result = resp.result.expect("should succeed");
        let ents = records_to_entities(
            &result.records,
            result.total.expect("should succeed"),
            "Avery",
            "Avery",
            true,
            "scan-1",
        );
        let addrs: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .collect();
        assert_eq!(addrs.len(), 3, "one address per record");
        assert_eq!(addrs[0].value, "QLD 4557, Australia");
        for e in &addrs {
            assert!(e.tags.iter().any(|t| t.as_str() == "unclaimed-money"));
            assert!(e.tags.iter().any(|t| t.as_str() == "country:AU"));
        }
        // The evidence source is preserved as `qld_unclaimed` so the downstream
        // correlator/relation rules keyed on it keep firing.
        assert_eq!(addrs[0].evidence[0].source, SRC);
        assert_eq!(SRC, "qld_unclaimed");
    }

    #[test]
    fn suburbs_enumerate_into_geocodable_candidates() {
        let locs = vec![
            Locality {
                suburb: "Maleny".into(),
                lat: -26.729,
                lon: 152.7554,
            },
            Locality {
                suburb: "Conondale".into(),
                lat: -26.7333,
                lon: 152.7167,
            },
        ];
        let ents = suburbs_to_entities(&[("4552".to_string(), locs)], "s");
        let coords: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .collect();
        assert_eq!(coords.len(), 1);
        assert!(
            coords[0]
                .tags
                .iter()
                .any(|t| t.as_str() == "postcode-centroid")
        );
        let addrs: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            addrs,
            vec![
                "Maleny, QLD 4552, Australia",
                "Conondale, QLD 4552, Australia",
            ]
        );
        assert!(ents.iter().all(|e| e.confidence < crate::core::confidence::MEDIUM));
    }
}
