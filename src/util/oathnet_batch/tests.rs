use super::query_gen::generate;
use super::types::{BatchOptions, BatchQuery, Origin, Surface};
use crate::core::scan::TargetKind;
use crate::util::oathnet;

fn count_surface(qs: &[BatchQuery], s: Surface) -> usize {
    qs.iter().filter(|q| q.surface == s).count()
}

fn has(qs: &[BatchQuery], s: Surface, field: &str, value: &str) -> bool {
    qs.iter()
        .any(|q| q.surface == s && q.field == field && q.value == value)
}

#[test]
fn email_seed_fans_out_across_surfaces_fields_and_handles() {
    let qs = generate(
        TargetKind::Email,
        "john.doe@example.com",
        &BatchOptions::default(),
    );
    // Direct email on both surfaces.
    assert!(has(&qs, Surface::Breach, "email", "john.doe@example.com"));
    assert!(has(&qs, Surface::Stealer, "email", "john.doe@example.com"));
    // Local part as a username on both surfaces.
    assert!(has(&qs, Surface::Breach, "username", "john.doe"));
    assert!(has(&qs, Surface::Stealer, "username", "john.doe"));
    // Handle permutations from the local part.
    assert!(has(&qs, Surface::Breach, "username", "johndoe"));
    assert!(has(&qs, Surface::Breach, "username", "jdoe"));
    // Domain pivot (breach only).
    assert!(has(&qs, Surface::Breach, "domain", "example.com"));
    // A "large array": comfortably into the double digits.
    assert!(qs.len() >= 15, "expected a large batch, got {}", qs.len());
}

#[test]
fn freemail_domain_is_not_searched_as_a_domain() {
    let qs = generate(TargetKind::Email, "bob@gmail.com", &BatchOptions::default());
    assert!(
        !qs.iter().any(|q| q.field == "domain"),
        "gmail.com must not become a domain search"
    );
    // But the email + handle pivots still generate.
    assert!(has(&qs, Surface::Breach, "email", "bob@gmail.com"));
    assert!(has(&qs, Surface::Breach, "username", "bob"));
}

#[test]
fn name_seed_generates_q_plus_handles() {
    let qs = generate(TargetKind::FullName, "John Doe", &BatchOptions::default());
    // Free-text name search is breach-only.
    assert!(has(&qs, Surface::Breach, "q", "John Doe"));
    assert!(
        !qs.iter()
            .any(|q| q.surface == Surface::Stealer && q.field == "q")
    );
    // Handle permutations on both surfaces.
    assert!(has(&qs, Surface::Breach, "username", "john.doe"));
    assert!(has(&qs, Surface::Stealer, "username", "jdoe"));
    assert!(qs.len() >= 12, "expected a large batch, got {}", qs.len());
}

#[test]
fn middle_name_adds_blended_handles() {
    let qs = generate(
        TargetKind::FullName,
        "John Michael Doe",
        &BatchOptions::default(),
    );
    assert!(has(&qs, Surface::Breach, "username", "johnmichaeldoe"));
    assert!(has(&qs, Surface::Breach, "username", "jmdoe"));
}

#[test]
fn phone_seed_expands_distinct_formats_breach_only() {
    let qs = generate(
        TargetKind::Phone,
        "+61 412 345 678",
        &BatchOptions::default(),
    );
    // Raw, digits-only, and AU E.164 forms are all present and distinct.
    assert!(has(&qs, Surface::Breach, "phone", "+61 412 345 678"));
    assert!(has(&qs, Surface::Breach, "phone", "61412345678"));
    assert!(has(&qs, Surface::Breach, "phone", "+61412345678"));
    // Never stealer.
    assert_eq!(count_surface(&qs, Surface::Stealer), 0);
}

#[test]
fn domain_and_ip_seeds_are_breach_only_singletons_by_default() {
    let dom = generate(TargetKind::Domain, "Example.COM", &BatchOptions::default());
    assert_eq!(dom.len(), 1);
    assert!(has(&dom, Surface::Breach, "domain", "example.com")); // lowercased

    let ip = generate(TargetKind::IpAddress, "8.8.8.8", &BatchOptions::default());
    assert_eq!(ip.len(), 1);
    assert!(has(&ip, Surface::Breach, "ip", "8.8.8.8"));
}

#[test]
fn synthesize_emails_opt_crosses_handles_with_providers() {
    let opts = BatchOptions {
        synthesize_emails: true,
        ..BatchOptions::default()
    };
    let qs = generate(TargetKind::Domain, "acme.io", &opts);
    assert!(has(&qs, Surface::Breach, "email", "admin@acme.io"));
    assert!(has(&qs, Surface::Stealer, "email", "info@acme.io"));

    let names = generate(TargetKind::FullName, "John Doe", &opts);
    assert!(
        names
            .iter()
            .any(|q| q.field == "email" && q.value.ends_with("@gmail.com"))
    );
}

#[test]
fn include_stealer_false_drops_every_stealer_query() {
    let opts = BatchOptions {
        include_stealer: false,
        ..BatchOptions::default()
    };
    let qs = generate(TargetKind::Email, "john.doe@example.com", &opts);
    assert_eq!(count_surface(&qs, Surface::Stealer), 0);
    assert!(count_surface(&qs, Surface::Breach) > 0);
}

#[test]
fn no_permute_keeps_only_direct_selectors() {
    let opts = BatchOptions {
        permute_handles: false,
        ..BatchOptions::default()
    };
    let qs = generate(TargetKind::Email, "john.doe@example.com", &opts);
    // Direct email + local-part username (+ stealer) + domain, but no
    // permutation-origin handles.
    assert!(!qs.iter().any(|q| q.origin == Origin::Handle));
    assert!(has(&qs, Surface::Breach, "username", "john.doe"));
}

#[test]
fn max_queries_truncates_after_dedup_preserving_priority() {
    let opts = BatchOptions {
        max_queries: 5,
        ..BatchOptions::default()
    };
    let qs = generate(TargetKind::Email, "john.doe@example.com", &opts);
    assert_eq!(qs.len(), 5);
    // The seed's own email query is highest priority and survives the cap.
    assert_eq!(qs[0].origin, Origin::Seed);
    assert!(has(&qs, Surface::Breach, "email", "john.doe@example.com"));
}

#[test]
fn output_is_deterministic_and_duplicate_free() {
    use std::collections::HashSet;
    let a = generate(
        TargetKind::Email,
        "john.doe@example.com",
        &BatchOptions::default(),
    );
    let b = generate(
        TargetKind::Email,
        "john.doe@example.com",
        &BatchOptions::default(),
    );
    assert_eq!(a, b, "same input must yield identical output");
    // No exact (surface, field, value) duplicate survives.
    let mut seen = HashSet::new();
    for q in &a {
        assert!(
            seen.insert((q.surface, q.field, q.value.clone())),
            "duplicate query leaked: {q:?}"
        );
    }
}

#[test]
fn opaque_handle_does_not_spuriously_permute() {
    // A single atomic token can't be recombined — it yields just itself, so
    // the only username query is the seed (deduped against the permutation).
    let qs = generate(TargetKind::Username, "xz", &BatchOptions::default());
    let usernames: Vec<&str> = qs
        .iter()
        .filter(|q| q.surface == Surface::Breach && q.field == "username")
        .map(|q| q.value.as_str())
        .collect();
    assert_eq!(usernames, vec!["xz"]);
}

#[test]
fn blank_and_unindexed_kinds_yield_nothing() {
    assert!(generate(TargetKind::Email, "   ", &BatchOptions::default()).is_empty());
    assert!(generate(TargetKind::Url, "https://x.com", &BatchOptions::default()).is_empty());
}

#[test]
fn seed_field_matches_shared_selector_vocabulary() {
    // The seed query's field must come from the single-sourced
    // `oathnet::selector_field`, not a private re-encoding.
    for (kind, value) in [
        (TargetKind::Email, "a@b.com"),
        (TargetKind::Username, "alice"),
        (TargetKind::FullName, "John Doe"),
        (TargetKind::Phone, "+61412345678"),
        (TargetKind::IpAddress, "8.8.8.8"),
        (TargetKind::Domain, "acme.io"),
    ] {
        let qs = generate(kind, value, &BatchOptions::default());
        let seed = qs
            .iter()
            .find(|q| q.origin == Origin::Seed)
            .expect("every indexed kind emits a seed query");
        assert_eq!(Some(seed.field), oathnet::selector_field(kind));
    }
}

#[test]
fn surface_paths_match_oathnet_constants() {
    assert_eq!(Surface::Breach.path(), oathnet::paths::BREACH);
    assert_eq!(Surface::Stealer.path(), oathnet::paths::STEALER);
}

// ── Invariants the module docs promise, checked across every indexed kind ──

/// Every kind OathNet indexes, with a representative seed and the most
/// expansive options, so the structural invariants are exercised broadly.
fn all_kind_cases() -> [(TargetKind, &'static str); 6] {
    [
        (TargetKind::Email, "jane.doe@example.com"),
        (TargetKind::Username, "jane.doe"),
        (TargetKind::FullName, "Jane Q Doe"),
        (TargetKind::Phone, "+61 412 345 678"),
        (TargetKind::IpAddress, "8.8.8.8"),
        (TargetKind::Domain, "acme.io"),
    ]
}

#[test]
fn every_query_is_well_formed() {
    const FIELDS: &[&str] = &["email", "username", "phone", "domain", "ip", "q"];
    let opts = BatchOptions {
        synthesize_emails: true,
        ..BatchOptions::default()
    };
    for (kind, value) in all_kind_cases() {
        let qs = generate(kind, value, &opts);
        assert!(!qs.is_empty(), "{kind:?} produced no queries");
        for q in &qs {
            assert!(
                FIELDS.contains(&q.field),
                "{kind:?} produced an unknown field {:?}",
                q.field
            );
            assert_eq!(q.value, q.value.trim(), "value not trimmed: {:?}", q.value);
            assert!(!q.value.is_empty(), "empty value for {kind:?}");
        }
    }
}

#[test]
fn seed_queries_precede_every_derived_query() {
    for (kind, value) in all_kind_cases() {
        let qs = generate(kind, value, &BatchOptions::default());
        let last_seed = qs.iter().rposition(|q| q.origin == Origin::Seed);
        let first_derived = qs.iter().position(|q| q.origin != Origin::Seed);
        if let (Some(ls), Some(fd)) = (last_seed, first_derived) {
            assert!(ls < fd, "a seed query followed a derived one for {kind:?}");
        }
    }
}

#[test]
fn every_stealer_query_mirrors_a_breach_query() {
    // `add` always pushes breach first, then (when indexable) stealer — so a
    // stealer query must always have a breach twin on the same field+value.
    let opts = BatchOptions {
        synthesize_emails: true,
        ..BatchOptions::default()
    };
    for (kind, value) in all_kind_cases() {
        let qs = generate(kind, value, &opts);
        for s in qs.iter().filter(|q| q.surface == Surface::Stealer) {
            assert!(
                qs.iter().any(|b| b.surface == Surface::Breach
                    && b.field == s.field
                    && b.value == s.value),
                "stealer query without a breach twin: {s:?}"
            );
        }
    }
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn malformed_emails_do_not_panic_or_emit_junk_domains() {
    // No '@': only the email selector applies — no local/domain derivation.
    let q1 = generate(TargetKind::Email, "not-an-email", &BatchOptions::default());
    assert!(q1.iter().all(|q| q.field == "email"));

    // Double '@' leaves a stray '@' in the host — must NOT become a domain query.
    let q2 = generate(TargetKind::Email, "a@@b.com", &BatchOptions::default());
    assert!(
        q2.iter().all(|q| q.field != "domain"),
        "a stray-@ host must not be searched as a domain"
    );

    // Empty local part: no username derivation, no panic.
    let q3 = generate(TargetKind::Email, "@example.com", &BatchOptions::default());
    assert!(q3.iter().any(|q| q.field == "email"));

    // A host with no dot is not a real domain.
    let q4 = generate(TargetKind::Email, "x@localhost", &BatchOptions::default());
    assert!(q4.iter().all(|q| q.field != "domain"));
}

#[test]
fn non_ascii_name_yields_ascii_handles_only() {
    // Non-ASCII chars act as separators (handles are ASCII), so the name
    // still yields ASCII handle permutations — accents are dropped, not
    // transliterated (documented limitation), and nothing panics.
    let qs = generate(
        TargetKind::FullName,
        "Renée Dubois",
        &BatchOptions::default(),
    );
    assert!(qs.iter().any(|q| q.field == "username"));
    // Only the free-text `q` query may carry the original non-ASCII value.
    assert!(qs.iter().all(|q| q.field == "q" || q.value.is_ascii()));
}

#[test]
fn max_queries_boundaries() {
    let seed = "jane.doe@example.com";
    let n = generate(TargetKind::Email, seed, &BatchOptions::default()).len();
    let cap = |m| {
        generate(
            TargetKind::Email,
            seed,
            &BatchOptions {
                max_queries: m,
                ..BatchOptions::default()
            },
        )
    };
    assert_eq!(cap(0).len(), n, "0 means no cap");
    assert_eq!(
        cap(n + 100).len(),
        n,
        "a cap above the plan size is a no-op"
    );
    let one = cap(1);
    assert_eq!(one.len(), 1);
    assert_eq!(
        one[0].origin,
        Origin::Seed,
        "the survivor is the seed query"
    );
}

#[test]
fn leading_and_trailing_whitespace_is_trimmed() {
    let qs = generate(
        TargetKind::Email,
        "  jane@example.com  ",
        &BatchOptions::default(),
    );
    assert!(has(&qs, Surface::Breach, "email", "jane@example.com"));
    assert!(qs.iter().all(|q| q.value == q.value.trim()));
}

#[test]
fn origin_label_maps_each_variant_to_its_plan_string() {
    // These labels appear in the emitted batch plan (JSON/human), so lock the
    // exact string for every variant.
    assert_eq!(Origin::Seed.label(), "seed");
    assert_eq!(Origin::EmailLocalPart.label(), "email-local-part");
    assert_eq!(Origin::EmailDomain.label(), "email-domain");
    assert_eq!(Origin::Handle.label(), "handle-permutation");
    assert_eq!(Origin::PhoneFormat.label(), "phone-format");
    assert_eq!(Origin::EmailCandidate.label(), "email-candidate");
}
