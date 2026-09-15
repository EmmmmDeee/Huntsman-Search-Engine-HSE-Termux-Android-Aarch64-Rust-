use super::{EDD_PROVIDERS, PROVIDERS, Pack, generate, generate_edd, generate_pack};
use crate::core::scan::{Target, TargetKind};

#[test]
fn email_pack_covers_every_provider_in_rank_order_under_one_parent() {
    let t = Target::new(TargetKind::Email, "alice@example.com");
    let pack = generate(&t, 1_700_000_000);
    assert_eq!(pack.len(), PROVIDERS.len());
    let ranks: Vec<u32> = pack.iter().map(|q| q.rank).collect();
    assert_eq!(ranks, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(pack[0].provider, "Intelligence X");
    let parent = &pack[0].parent_query_id;
    assert!(parent.starts_with("qp-"));
    assert!(pack.iter().all(|q| &q.parent_query_id == parent));
    for q in &pack {
        assert_eq!(q.query, "alice@example.com");
        assert_eq!(q.query_type, "email");
        assert!(!q.manual_entrypoint.is_empty());
        assert_eq!(q.generated_at, 1_700_000_000);
    }
}

#[test]
fn parent_query_id_is_stable_and_target_specific() {
    let a = generate(&Target::new(TargetKind::Email, "alice@example.com"), 1);
    let b = generate(&Target::new(TargetKind::Email, "alice@example.com"), 2);
    let c = generate(&Target::new(TargetKind::Email, "bob@example.com"), 1);
    assert_eq!(a[0].parent_query_id, b[0].parent_query_id);
    assert_ne!(a[0].parent_query_id, c[0].parent_query_id);
}

#[test]
fn narrow_email_only_providers_are_dropped_for_a_username() {
    let pack = generate(&Target::new(TargetKind::Username, "kylo4kylo"), 0);
    let names: Vec<&str> = pack.iter().map(|q| q.provider).collect();
    assert!(names.contains(&"OathNet"));
    assert!(names.contains(&"Intelligence X"));
    assert!(!names.contains(&"XposedOrNot"));
    assert!(!names.contains(&"Have I Been Pwned"));
}

#[test]
fn a_kind_no_manual_provider_accepts_yields_an_empty_pack() {
    let pack = generate(&Target::new(TargetKind::Coordinates, "-27.47,153.02"), 0);
    assert!(pack.is_empty());
}

#[test]
fn empty_value_yields_an_empty_pack() {
    let pack = generate(&Target::new(TargetKind::Email, "   "), 0);
    assert!(pack.is_empty());
}

#[test]
fn gateway_and_high_trust_caveats_are_carried_to_the_operator() {
    let pack = generate(&Target::new(TargetKind::Email, "alice@example.com"), 0);
    let stolen_tax = pack.iter().find(|q| q.provider == "Stolen.tax").unwrap();
    assert!(
        stolen_tax
            .expected_result_class
            .to_ascii_lowercase()
            .contains("gateway"),
        "a multi-source gateway must be flagged as non-independent for the operator"
    );
    let hibp = pack
        .iter()
        .find(|q| q.provider == "Have I Been Pwned")
        .unwrap();
    assert!(
        hibp.expected_result_class
            .to_ascii_lowercase()
            .contains("miss"),
        "HIBP's result class must warn that a miss is not proof of no exposure"
    );
}

#[test]
fn provider_ranks_are_unique_and_dense() {
    let mut ranks: Vec<u32> = PROVIDERS.iter().map(|p| p.rank).collect();
    ranks.sort_unstable();
    let expected: Vec<u32> = (1..=PROVIDERS.len() as u32).collect();
    assert_eq!(ranks, expected);
}

#[test]
fn edd_abn_pack_starts_at_abr_and_skips_infra() {
    let pack = generate_edd(
        &Target::new(TargetKind::AbnAcn, "51 824 753 556"),
        1_700_000_000,
    );
    let names: Vec<&str> = pack.iter().map(|q| q.provider).collect();
    assert_eq!(names[0], "ABR");
    assert!(names.contains(&"ASIC Connect"));
    assert!(names.contains(&"OpenSanctions"));
    assert!(!names.contains(&"Shodan"));
    assert!(!names.contains(&"Intelligence X"));
    assert!(pack.iter().all(|q| q.query_type == "abn_acn"));
    assert!(pack.iter().all(|q| q.query == "51 824 753 556"));
}

#[test]
fn edd_domain_is_infra_not_abr() {
    let pack = generate_edd(&Target::new(TargetKind::Domain, "example.com.au"), 0);
    let names: Vec<&str> = pack.iter().map(|q| q.provider).collect();
    assert!(names.contains(&"auDA RDAP"));
    assert!(names.contains(&"WHOIS"));
    assert!(names.contains(&"Shodan"));
    assert!(names.contains(&"URLScan"));
    assert!(names.contains(&"VirusTotal"));
    assert!(!names.contains(&"ABR"));
    assert!(!names.contains(&"Trove"));
}

#[test]
fn edd_address_is_only_opencellid() {
    let pack = generate_edd(
        &Target::new(TargetKind::Address, "1 George St, Brisbane QLD"),
        0,
    );
    assert_eq!(pack.len(), 1);
    assert_eq!(pack[0].provider, "OpenCelliD");
    assert_eq!(pack[0].manual_entrypoint, "opencellid.org");
}

#[test]
fn edd_email_is_empty_exposure_owns_that_kind() {
    let pack = generate_edd(&Target::new(TargetKind::Email, "alice@example.com"), 0);
    assert!(pack.is_empty());
}

#[test]
fn edd_ranks_are_unique_and_dense() {
    let mut ranks: Vec<u32> = EDD_PROVIDERS.iter().map(|p| p.rank).collect();
    ranks.sort_unstable();
    let expected: Vec<u32> = (1..=EDD_PROVIDERS.len() as u32).collect();
    assert_eq!(ranks, expected);
}

#[test]
fn generate_pack_all_concatenates_without_crossing_parent_ids() {
    let t = Target::new(TargetKind::Domain, "example.com.au");
    let all = generate_pack(Pack::All, &t, 9);
    let exp = generate(&t, 9);
    let edd = generate_edd(&t, 9);
    assert_eq!(all.len(), exp.len() + edd.len());
    assert_eq!(&all[..exp.len()], exp.as_slice());
    assert_eq!(&all[exp.len()..], edd.as_slice());
    let parent = &all[0].parent_query_id;
    assert!(all.iter().all(|q| &q.parent_query_id == parent));
}

#[test]
fn pack_parse_tokens() {
    assert_eq!(Pack::parse("edd"), Some(Pack::Edd));
    assert_eq!(Pack::parse("EXPOSURE"), Some(Pack::Exposure));
    assert_eq!(Pack::parse("all"), Some(Pack::All));
    assert_eq!(Pack::parse("nope"), None);
}
