use super::*;
use crate::core::correlator::Correlation;
use crate::core::entity::Evidence;

fn breach_entity(kind: EntityKind, value: &str, db: &str) -> Entity {
    let mut e = Entity::new(kind, value, 0.8, "s");
    e.tag(crate::core::tags::BREACH);
    e.add_evidence(Evidence::new("oathnet-pro", "Breach record").with_attr("dbname", db));
    e
}

fn corr(severity: Severity) -> Correlation {
    Correlation::new("AU-000", "test", severity, "d".to_string(), vec![], "s", 0)
}

fn component<'a>(idx: &'a ExposureIndex, name: &str) -> &'a ExposureComponent {
    idx.components
        .iter()
        .find(|c| c.name == name)
        .expect("component present")
}

#[test]
fn empty_scan_is_minimal() {
    let idx = assess(&[], &[]);
    assert_eq!(idx.score, 0);
    assert_eq!(idx.band, ExposureBand::Minimal);
    assert_eq!(idx.components.len(), 4);
    assert!(idx.components.iter().all(|c| c.score == 0));
    assert_eq!(idx.summary_line(), "Exposure 0/100 [MINIMAL]");
}

#[test]
fn breach_corpora_accumulate_and_cap() {
    // One corpus → 12.
    let one = assess(
        &[breach_entity(EntityKind::Email, "a@x.com", "AcmeLeak")],
        &[],
    );
    assert_eq!(component(&one, "Breach exposure").score, 12);

    // Four distinct corpora → capped at 35 (not 48).
    let many = assess(
        &[
            breach_entity(EntityKind::Email, "a@x.com", "AcmeLeak"),
            breach_entity(EntityKind::Email, "a@x.com", "BetaDump"),
            breach_entity(EntityKind::Username, "alice", "GammaBreach"),
            breach_entity(EntityKind::Phone, "+61400000001", "DeltaPaste"),
        ],
        &[],
    );
    assert_eq!(component(&many, "Breach exposure").score, MAX_BREACH);

    // The same corpus seen on several entities counts once.
    let dup = assess(
        &[
            breach_entity(EntityKind::Email, "a@x.com", "AcmeLeak"),
            breach_entity(EntityKind::Username, "alice", "acmeleak"), // case-folds to same
        ],
        &[],
    );
    assert_eq!(component(&dup, "Breach exposure").score, 12);
}

#[test]
fn subject_aggregate_breach_hit_is_counted_not_just_per_row_dbname() {
    // Real captured shape (debug bundle, scan 90b936dc...): the SUBJECT's confirmed
    // email carries its TLDRtech breach appearance under `top_dbnames` (oathnet_pro)
    // and `breaches` (xposed_or_not) — never `dbname`, which only the per-row
    // co-occurrence rows use. Reading only `dbname` scored this 0; it must now count
    // the corpus, and fold the two spellings ("tldr.tech" / "TLDRtech") into one.
    let mut email = Entity::new(EntityKind::Email, "matthewdiegmann@gmail.com", 0.92, "s");
    email.tag(crate::core::tags::BREACH);
    email.add_evidence(
        Evidence::new("oathnet-pro", "OathNet: 1 breach record(s) — tldr.tech")
            .with_attr("hits", "1")
            .with_attr("top_dbnames", "tldr.tech"),
    );
    email.add_evidence(
        Evidence::new("xposed_or_not", "Found in 1 breach(es)")
            .with_attr("count", "1")
            .with_attr("breaches", "TLDRtech"),
    );
    let idx = assess(&[email], &[]);
    // One named corpus — 12, not 0 (the bug) and not 24 (double-counting the two
    // spellings of the same breach).
    assert_eq!(component(&idx, "Breach exposure").score, 12);
}

#[test]
fn top_dbnames_list_counts_each_distinct_corpus_and_drops_unknown() {
    // `top_dbnames` is a comma-separated list (seen in the real Person aggregate
    // hit). Each distinct named corpus counts once; the literal "unknown" filler
    // and duplicates do not.
    let mut e = Entity::new(EntityKind::Person, "Subject", 0.85, "s");
    e.tag(crate::core::tags::BREACH);
    e.add_evidence(Evidence::new("oathnet-pro", "aggregate").with_attr(
        "top_dbnames",
        "abrigo.com, bcdtravel.com, unknown, abrigo.com",
    ));
    let idx = assess(&[e], &[]);
    // Two distinct corpora (abrigo.com, bcdtravel.com) → 24.
    assert_eq!(component(&idx, "Breach exposure").score, 24);
}

#[test]
fn sensitive_pii_flags_score_once_per_category() {
    let mut gov = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    gov.add_evidence(Evidence::new("oathnet-pro", "rec").with_attr("tfn", "123456782"));
    let mut dob = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    dob.add_evidence(Evidence::new("oathnet-pro", "rec").with_attr("date_of_birth", "1990-01-01"));
    let secret = Entity::new(EntityKind::Password, "hunter2", 0.8, "s");

    let idx = assess(&[gov, dob, secret], &[]);
    let s = component(&idx, "Sensitive PII");
    // gov-ID 15 + cleartext credential 8 + DOB 7 = 30 (also the cap).
    assert_eq!(s.score, 30);
    assert!(s.detail.contains("government ID"));
    assert!(s.detail.contains("date of birth"));

    // A second gov-ID disclosure does NOT double-count the category.
    let mut gov2 = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    gov2.add_evidence(Evidence::new("oathnet-pro", "rec").with_attr("medicare", "2123456701"));
    let only_gov = assess(
        &[
            {
                let mut g = Entity::new(EntityKind::Person, "Dana", 0.8, "s");
                g.add_evidence(Evidence::new("o", "r").with_attr("tfn", "123456782"));
                g
            },
            gov2,
        ],
        &[],
    );
    assert_eq!(component(&only_gov, "Sensitive PII").score, 15);
}

#[test]
fn sensitive_pii_recognises_wikidata_birth_date_spelling() {
    // `wikidata::builder` stamps `birth_date` (its own canonical spelling),
    // distinct from `date_of_birth` (what the breach/stealer producers
    // normalise to). `DOB_KEYS`'s own doc comment says it tracks "the
    // canonical keys the breach/dossier producers stamp" — omitting a real
    // producer's spelling silently undercounted the disclosure.
    let mut dob = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    dob.add_evidence(Evidence::new("wikidata", "rec").with_attr("birth_date", "1990-01-01"));
    let idx = assess(&[dob], &[]);
    let s = component(&idx, "Sensitive PII");
    assert_eq!(
        s.score, 7,
        "a Wikidata birth_date must score as a DOB disclosure"
    );
    assert!(s.detail.contains("date of birth"));
}

#[test]
fn sensitive_pii_dob_gov_id_keys_are_single_sourced_from_breach_pii() {
    // Regression: `DOB_KEYS`/the gov-ID keys used to be separate local copies
    // that had drifted to a narrower subset of AU-073/AU-074's canonical
    // vocabularies in `core::correlator::rules::breach_pii` — undercounting
    // any breach record using one of the un-mirrored spellings. Both are now
    // single-sourced from that module, so a spelling AU-073/AU-074 already
    // recognise must score here too, with zero separate list to drift.
    //
    // `date_birth` — OathNet/SeekNow's own DOB field spelling (breach_pii's
    // own comment calls it "a major breach source that the older key list
    // missed") — was never in exposure's old 3-spelling DOB_KEYS.
    let mut dob = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    dob.add_evidence(Evidence::new("oathnet_pro", "rec").with_attr("date_birth", "1990-01-01"));
    let dob_idx = assess(&[dob], &[]);
    let s = component(&dob_idx, "Sensitive PII");
    assert_eq!(
        s.score, 7,
        "date_birth (OathNet/SeekNow's spelling) must score as a DOB disclosure"
    );

    // `tax_file_number` — one of AU-074's 4 TFN spellings — was never in
    // exposure's old 1-spelling-per-class GOV_ID_KEYS (only bare `tfn`).
    let mut gov = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    gov.add_evidence(Evidence::new("oathnet_pro", "rec").with_attr("tax_file_number", "123456782"));
    let gov_idx = assess(&[gov], &[]);
    let s = component(&gov_idx, "Sensitive PII");
    assert_eq!(
        s.score, 15,
        "tax_file_number must score as a government-ID disclosure"
    );
}

#[test]
fn sensitive_pii_bank_account_number_keys_are_single_sourced_from_breach_pii() {
    // Regression: exposure's Financial flag only recognised the bare
    // `bank_account` spelling — AU-104's own `BANK_ACCOUNT_KEYS` in
    // `breach_pii` has 4 more (`account_number`/`account_no`/`acct_number`/
    // `acct_no`) that were silently unmirrored, undercounting the exposure
    // score for a breach record using one of them instead.
    let mut fin = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    fin.add_evidence(Evidence::new("oathnet_pro", "rec").with_attr("account_number", "123456"));
    let fin_idx = assess(&[fin], &[]);
    let s = component(&fin_idx, "Sensitive PII");
    assert_eq!(
        s.score, 5,
        "account_number must score as a financial disclosure"
    );
}

#[test]
fn identifier_surface_counts_distinct_capped() {
    let ents = vec![
        Entity::new(EntityKind::Email, "a@x.com", 0.8, "s"),
        Entity::new(EntityKind::Email, "A@X.com", 0.8, "s"), // dup (case)
        Entity::new(EntityKind::Phone, "+61400000001", 0.8, "s"),
        Entity::new(EntityKind::Username, "alice", 0.8, "s"),
        Entity::new(
            EntityKind::Address,
            "12 Wattle St, Logan QLD 4114",
            0.8,
            "s",
        ),
        Entity::new(EntityKind::Domain, "x.com", 0.8, "s"), // not an identifier kind
    ];
    let idx = assess(&ents, &[]);
    // 4 distinct identifiers × 4 = 16.
    assert_eq!(component(&idx, "Identifier surface").score, 16);

    // Six distinct → capped at 20.
    let many: Vec<Entity> = (0..6)
        .map(|i| Entity::new(EntityKind::Username, format!("user{i}"), 0.8, "s"))
        .collect();
    assert_eq!(
        component(&assess(&many, &[]), "Identifier surface").score,
        MAX_IDENTIFIERS
    );
}

#[test]
fn correlations_weighted_by_severity_and_capped() {
    let cs = vec![
        corr(Severity::Critical), // 5
        corr(Severity::High),     // 2
        corr(Severity::Low),      // 0
        corr(Severity::Medium),   // 0
    ];
    assert_eq!(
        component(&assess(&[], &cs), "Correlation severity").score,
        7
    );

    // Four criticals = 20 → capped at 15.
    let crits = vec![corr(Severity::Critical); 4];
    assert_eq!(
        component(&assess(&[], &crits), "Correlation severity").score,
        MAX_CORRELATION
    );
}

#[test]
fn candidate_entities_are_excluded() {
    let mut quarantined = breach_entity(EntityKind::Email, "stranger@x.com", "AcmeLeak");
    quarantined.tag(crate::core::tags::CANDIDATE);
    // A quarantined breach row is not tied to the subject → contributes nothing.
    let idx = assess(&[quarantined], &[]);
    assert_eq!(idx.score, 0);
    assert_eq!(component(&idx, "Breach exposure").score, 0);
}

#[test]
fn candidate_stranger_batch_top_dbnames_do_not_inflate_breach_exposure() {
    // Real failure shape (debug bundle, scan 90b936dc... from a pre-`breach_parent_entity`
    // build): a broad full_name search returned a page of ~100 strangers, summarised
    // as a breach batch whose `top_dbnames` lists many corpora none of which are the
    // subject's. Current code demotes such a non-matching aggregate to `candidate`,
    // so it must contribute nothing. This locks in that the `top_dbnames` key — read
    // since the subject-breach fix — cannot let a quarantined stranger batch inflate
    // the subject's breach-corpus count (the count must reflect CONFIRMED hits only).
    let mut stranger_batch = Entity::new(EntityKind::Person, "Matthew Diegmann", 0.25, "s");
    stranger_batch.tag(crate::core::tags::BREACH);
    stranger_batch.tag(crate::core::tags::CANDIDATE);
    stranger_batch.add_evidence(
        Evidence::new("oathnet-pro", "OathNet: 100 breach record(s) — abrigo.com")
            .with_attr("hits", "100")
            .with_attr("top_dbnames", "abrigo.com, bcdtravel.com, heritage.org"),
    );
    // A genuine CONFIRMED subject corpus alongside the quarantined batch.
    let mut real = Entity::new(EntityKind::Email, "subj@x.com", 0.92, "s");
    real.tag(crate::core::tags::BREACH);
    real.add_evidence(Evidence::new("oathnet-pro", "match").with_attr("top_dbnames", "tldr.tech"));

    let idx = assess(&[stranger_batch, real], &[]);
    // Only the confirmed corpus (tldr.tech) counts → 12; the candidate batch's three
    // corpora are excluded, never reaching 48/35.
    assert_eq!(component(&idx, "Breach exposure").score, 12);
}

#[test]
fn speculative_low_confidence_findings_do_not_inflate_exposure() {
    // 30 name-permutation username GUESSES at 0.45 (bare single-source speculation,
    // c_effective < 0.5) must NOT count toward exposure — a real scan of a name
    // surfaced ~40 such guesses that wrongly maxed the identifier surface.
    let guesses: Vec<Entity> = (0..30)
        .map(|i| Entity::new(EntityKind::Username, format!("guess{i}"), 0.45, "s"))
        .collect();
    assert_eq!(
        component(&assess(&guesses, &[]), "Identifier surface").score,
        0
    );
    // A corroborated 0.8 identifier still counts.
    let real = vec![Entity::new(EntityKind::Email, "real@x.com", 0.8, "s")];
    assert_eq!(
        component(&assess(&real, &[]), "Identifier surface").score,
        4
    );
}

#[test]
fn assessment_is_order_independent() {
    let build = || {
        vec![
            breach_entity(EntityKind::Email, "a@x.com", "AcmeLeak"),
            breach_entity(EntityKind::Phone, "+61400000001", "BetaDump"),
            Entity::new(EntityKind::Username, "alice", 0.8, "s"),
        ]
    };
    let mut a = build();
    let mut b = build();
    b.reverse();
    let cs = vec![corr(Severity::Critical), corr(Severity::High)];
    a.rotate_left(1);
    assert_eq!(assess(&a, &cs).score, assess(&b, &cs).score);
}

#[test]
fn band_thresholds_are_contiguous() {
    assert_eq!(ExposureBand::from_score(0), ExposureBand::Minimal);
    assert_eq!(ExposureBand::from_score(19), ExposureBand::Minimal);
    assert_eq!(ExposureBand::from_score(20), ExposureBand::Low);
    assert_eq!(ExposureBand::from_score(40), ExposureBand::Moderate);
    assert_eq!(ExposureBand::from_score(60), ExposureBand::High);
    assert_eq!(ExposureBand::from_score(80), ExposureBand::Critical);
    assert_eq!(ExposureBand::from_score(100), ExposureBand::Critical);
}

#[test]
fn a_heavily_exposed_subject_reaches_critical() {
    // Multiple breaches + gov-ID + DOB + cleartext secret + identifiers + criticals.
    let mut ents = vec![
        breach_entity(EntityKind::Email, "dana@x.com", "AcmeLeak"),
        breach_entity(EntityKind::Email, "dana@y.com", "BetaDump"),
        breach_entity(EntityKind::Phone, "+61400000001", "GammaBreach"),
        Entity::new(EntityKind::Username, "danaw", 0.8, "s"),
        Entity::new(
            EntityKind::Address,
            "12 Wattle St, Logan QLD 4114",
            0.8,
            "s",
        ),
        Entity::new(EntityKind::Password, "hunter2", 0.8, "s"),
    ];
    let mut pii = Entity::new(EntityKind::Person, "Dana Whitlock", 0.8, "s");
    pii.add_evidence(
        Evidence::new("oathnet-pro", "rec")
            .with_attr("tfn", "123456782")
            .with_attr("date_of_birth", "1990-01-01"),
    );
    ents.push(pii);
    let cs = vec![
        corr(Severity::Critical),
        corr(Severity::Critical),
        corr(Severity::High),
    ];
    let idx = assess(&ents, &cs);
    assert!(
        idx.score >= 80,
        "heavily exposed subject must be Critical: {}",
        idx.score
    );
    assert_eq!(idx.band, ExposureBand::Critical);
}
