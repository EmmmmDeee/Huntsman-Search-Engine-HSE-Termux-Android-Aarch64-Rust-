use crate::core::confidence;
use super::*;

#[test]
fn otx_confidence_graduates_with_pulse_corroboration() {
    // A lone OTX pulse (often self-published) must score LOWER than several
    // independent pulses, which in turn score lower than a broad consensus —
    // instead of every indicator carrying the same flat confidence.
    assert!(
        otx_confidence(1) < otx_confidence(3),
        "a single pulse is weaker than a few corroborating ones"
    );
    assert!(
        otx_confidence(3) < otx_confidence(50),
        "many corroborating pulses are stronger than a few"
    );
    assert!(
        (otx_confidence(1) - confidence::MEDIUM_HIGH).abs() < 1e-9,
        "a single pulse is a lead, not the former flat 0.72"
    );
    assert!(
        otx_confidence(50) <= confidence::HIGH_PLUSPLUS,
        "OTX pulse counts are not fully independent — the top tier stays bounded"
    );
}

#[test]
fn meaningful_tag_keeps_threat_categories_drops_noise() {
        // Signal — real threat categories from the scan's OTX dump.
        for ok in [
            "malware",
            "Mirai",
            "NSO Group",
            "Pegasus",
            "phishing",
            "FormBook",
        ] {
            assert!(is_meaningful_tag(ok), "{ok:?} should be kept");
        }
        // Noise — exactly the junk that flooded the old alphabetical blob.
        for junk in [
            ".cc",
            "0007",
            "0pgtwhu",
            "MD5 Hash: f8add7e7161460ea2b1970cf4ca535bf",
            "Imphash: 9698f46495ce9401c8bcaf9a2afe1598",
            "Compilation / Toolchain Compiler: Microsoft Visual C++ 2017",
            "Filename: b47266fef17ad4b2e4ca6ee1d06c39a7.virus",
            "cd3989830da99a69380901769fd78902efb3cd8ba",
            "a",
        ] {
            assert!(!is_meaningful_tag(junk), "{junk:?} should be dropped");
        }
    }

    #[test]
    fn accepts_ip_and_domain() {
        let m = IpReputation;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn rejects_email() {
        let m = IpReputation;
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }

    #[test]
    fn module_metadata() {
        let m = IpReputation;
        assert_eq!(m.name(), "ip_reputation");
        assert_eq!(m.priority(), 78);
        assert_eq!(m.max_timeout_ms(), 10_000);
    }

    #[test]
    fn meaningful_tag_minimum_length_boundary() {
        // Tags ≤ 2 chars are always noise regardless of content.
        assert!(!is_meaningful_tag("ab"));
        assert!(!is_meaningful_tag("a"));
        assert!(!is_meaningful_tag(""));
        // 3-char tags need to be all-uppercase (acronyms like "APT") to pass.
        assert!(is_meaningful_tag("APT"), "3-char uppercase acronym should pass");
    }

    #[test]
    fn meaningful_tag_hash_patterns_dropped() {
        // MD5/SHA hashes with their label prefixes are noise from the OTX dump.
        assert!(!is_meaningful_tag("MD5 Hash: abc123"));
        assert!(!is_meaningful_tag("Imphash: deadbeef"));
        // A long SHA hash-like prefix that starts with digits/hex and contains
        // none of the minimum meaningful tokens must be filtered.
        assert!(!is_meaningful_tag("cd3989830da99a69380901769fd78902efb3cd8ba"));
    }

    #[test]
    fn meaningful_tag_url_extension_noise_dropped() {
        // File extension fragments from OTX pulse noise.
        for noise in [".cc", ".exe", ".dll", ".bin", ".php"] {
            assert!(!is_meaningful_tag(noise), "{noise:?} should be noise");
        }
    }

    // ── T2.111: transport/parse failures must surface, not vanish ──────
    //
    // Before this fix, `run_otx`/`run_tor_check` discarded every `Err` with
    // a bare `return`, and `process()` always returned `Ok(result)` — a
    // total outage was indistinguishable from a clean "nothing found".
    // `process()` now folds `hard_failure` through the shared
    // `ModuleResult::or_hard_failure` (T2.114 centralised this exact
    // combinator out of this module so `niamonx` could reuse it instead of
    // duplicating it) — its decision-table regression tests now live beside
    // it in `core::module::tests`, not here.

    /// A one-shot local HTTP server that always answers with `status` and
    /// `body` — used to give `fetch_exit_set` a real (not mocked) transport
    /// to hit so its failure classification is exercised end to end.
    async fn serve_once(status: u16, body: &'static [u8]) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let reason = if status == 200 { "OK" } else { "Error" };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.flush().await;
        });
        addr
    }

    #[tokio::test]
    async fn fetch_exit_set_errors_on_non_success_status() {
        // Regression: previously a non-2xx status silently became `None`.
        let addr = serve_once(503, b"upstream down").await;
        let client = reqwest::Client::new();
        let res = fetch_exit_set(&client, &format!("http://{addr}/")).await;
        assert!(
            res.is_err(),
            "a 503 from the Tor exit-list host must propagate as an error"
        );
    }

    #[tokio::test]
    async fn fetch_exit_set_errors_on_empty_exit_list_body() {
        // Regression: an empty/garbage body (zero ExitAddress lines)
        // previously also silently became `None`, identical to a real
        // outage AND identical to "genuinely no exits" — now it errors
        // explicitly instead of masquerading as either.
        let addr = serve_once(200, b"not an exit list\n").await;
        let client = reqwest::Client::new();
        let res = fetch_exit_set(&client, &format!("http://{addr}/")).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fetch_exit_set_parses_real_shaped_body_on_success() {
        let body = b"ExitNode ABCDEF\nPublished 2026-07-14 00:00:00\nLastStatus 2026-07-14 00:00:00\nExitAddress 198.51.100.7 2026-07-14 00:00:00\n";
        let addr = serve_once(200, body).await;
        let client = reqwest::Client::new();
        let set = fetch_exit_set(&client, &format!("http://{addr}/"))
            .await
            .expect("a well-formed body must parse");
        assert!(set.contains("198.51.100.7"));
        assert_eq!(set.len(), 1);
    }

// ── OTX passive DNS ─────────────────────────────────────────────────

fn passive_rows(json: &str) -> Vec<PassiveDnsRow> {
    serde_json::from_str::<PassiveDnsResp>(json)
        .expect("should succeed")
        .passive_dns
}

#[test]
fn passive_dns_dedups_an_expanded_and_a_compressed_ipv6_spelling() {
    // Regression: see hudsonrock's identical fix for the general shape. A
    // real public address (Google Public DNS) is used, not an RFC 3849
    // documentation one, so `addr.parse::<IpAddr>().is_ok()`'s validity
    // check cannot mask the gap either way.
    let rows = passive_rows(
        r#"{"passive_dns":[
            {"hostname":"torproject.org","address":"2001:4860:4860:0000:0000:0000:0000:8888","record_type":"AAAA"},
            {"hostname":"torproject.org","address":"2001:4860:4860::8888","record_type":"AAAA"}
        ]}"#,
    );
    let out = passive_dns_entities(&rows, "torproject.org", "s");
    let ips: Vec<_> = out
        .iter()
        .filter(|e| e.kind == crate::core::entity::EntityKind::IpAddress)
        .collect();
    assert_eq!(
        ips.len(),
        1,
        "an expanded and a compressed spelling of the same IPv6 address must dedup to one entity: {ips:?}"
    );
}

#[test]
fn passive_dns_emits_historical_ips_and_subdomains() {
    // Verbatim OTX passive_dns record shape (captured live): hostname/address/
    // record_type/first/last. A domain query returns the domain + its subdomains
    // resolving to historical IPs.
    let rows = passive_rows(
        r#"{"passive_dns":[
            {"hostname":"torproject.org","address":"116.202.120.181","record_type":"A","first":"2024-01-02T00:00:00","last":"2026-07-14T00:00:00"},
            {"hostname":"check.torproject.org","address":"116.202.120.166","record_type":"A","first":"2023-05-01T00:00:00","last":"2026-07-10T00:00:00"},
            {"hostname":"blog.torproject.org","address":"2a01:4f8::1","record_type":"AAAA","first":"2022-01-01T00:00:00","last":"2025-01-01T00:00:00"}
        ]}"#,
    );
    let out = passive_dns_entities(&rows, "torproject.org", "s");

    // Historical IPs (v4 + v6) surface as IpAddress leads.
    let ips: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .map(|e| e.value.as_str())
        .collect();
    assert!(ips.contains(&"116.202.120.181") && ips.contains(&"116.202.120.166"));
    assert!(ips.iter().any(|i| i.contains(':')), "AAAA IP must surface too");
    let ip_ent = out
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("should succeed");
    assert!(ip_ent.has_tag("otx") && ip_ent.has_tag("passive-dns") && ip_ent.has_tag("historical"));

    // Subdomains surface as Domain entities; the apex is a Domain but NOT tagged
    // subdomain.
    let subs: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert!(subs.contains(&"check.torproject.org") && subs.contains(&"blog.torproject.org"));
    assert!(subs.contains(&"torproject.org"));
    let sub = out
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "check.torproject.org")
        .expect("should succeed");
    assert!(sub.has_tag(crate::core::tags::SUBDOMAIN) && sub.has_tag("passive-dns"));
}

#[test]
fn a_www_alias_of_the_target_is_not_tagged_a_subdomain_of_itself() {
    // Regression, mirroring the apex-itself case in the test above: a
    // passively-observed "www.<target>" row is a proper subdomain of the raw
    // target by string shape alone, even though `Entity::new` strips the
    // leading "www." label and collapses it onto the scan's own apex/subject
    // uid — before this was fixed, it was still tagged SUBDOMAIN via the raw
    // `host != base` check, surviving onto the merged apex entity via
    // `Entity::merge`'s tag-union.
    let rows = passive_rows(
        r#"{"passive_dns":[
            {"hostname":"www.torproject.org","address":"116.202.120.181","record_type":"A"}
        ]}"#,
    );
    let out = passive_dns_entities(&rows, "torproject.org", "s");
    let www = out
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "torproject.org")
        .expect("the www row still surfaces, collapsed onto the apex value");
    assert!(
        !www.has_tag(crate::core::tags::SUBDOMAIN),
        "a www-alias of the target must never tag the apex as its own subdomain"
    );
}

#[test]
fn passive_dns_gates_unrelated_hosts_and_invalid_ips() {
    // A record whose hostname is NOT the target or a subdomain of it (shared-IP
    // noise) must be dropped; a non-parseable address must not mint an IP.
    let rows = passive_rows(
        r#"{"passive_dns":[
            {"hostname":"evil-unrelated.com","address":"1.2.3.4","record_type":"A"},
            {"hostname":"notatorproject.org","address":"5.6.7.8","record_type":"A"},
            {"hostname":"ok.torproject.org","address":"not-an-ip","record_type":"A"}
        ]}"#,
    );
    let out = passive_dns_entities(&rows, "torproject.org", "s");
    // The unrelated hostnames are gated out as Domains…
    assert!(
        out.iter()
            .all(|e| e.kind != EntityKind::Domain || e.value == "ok.torproject.org"),
        "only in-scope hostnames survive"
    );
    // `ok.torproject.org` IS in scope and surfaces (its bad address is just skipped).
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "ok.torproject.org")
    );
    // Row-scope gate: the IPs 1.2.3.4 / 5.6.7.8 belong to the UNRELATED hosts, so
    // they must NOT be attributed to the subject domain (a shared-IP row can't
    // leak its IP into the subject's history); and "not-an-ip" never mints an IP.
    assert!(
        !out.iter().any(|e| e.kind == EntityKind::IpAddress),
        "no IP is attributed to the subject from out-of-scope or invalid rows"
    );
}

// ── OTX `adversary`: a threat actor's name, never a paragraph (REQ-ATTR-002) ──

fn pulse_naming(adversary: Option<&str>) -> Pulse {
    Pulse {
        name: Some("a pulse".to_string()),
        tags: Vec::new(),
        adversary: adversary.map(str::to_string),
        tlp: None,
        created: None,
    }
}

/// OTX's own 100-character cut of a community pulse's paragraph, captured
/// live 2026-09-15 for a Tor exit (one pulse of fifty) and minted by the
/// module as an `Organisation` "threat actor linked to" the address.
const CAPTURED_PARAGRAPH: &str =
    "Adversary Profile: Salt Typhoon Alignment The architectural gap identified by mudoSO mirrors the act";

#[test]
fn an_actor_name_is_short_and_never_a_sentence() {
    for name in [
        "Mirai",
        "NSO Group",
        "APT28 / Fancy Bear",
        "Lazarus Group",
        "TA505",
        // A real actor whose name merely CONTAINS a would-be placeholder word
        // is still a name — the placeholder gate is anchored, not a substring
        // match (REQ-ATTR-003): `Anonymous Sudan` is a real hacktivist group.
        "Anonymous Sudan",
        // A marker word AFTER another token is not a placeholder: the prefix is
        // anchored at the start of the label, so this name-shaped value (a
        // would-be `contains("unknown")` substring match) must still be
        // accepted. Guards the anchoring against a future substring regression —
        // `Anonymous Sudan` alone does not, since `anonymous` is no marker.
        "Cozy Unknown",
    ] {
        assert!(is_actor_name(name), "{name} is a threat actor's name");
    }
    for text in [
        CAPTURED_PARAGRAPH,
        "Adversary Profile: Salt Typhoon Alignment The architectural gap",
        "Salt Typhoon:",
        "the group behind the campaign observed last spring",
        "",
        "x",
        // Placeholder / non-attribution labels a pulse author types when the
        // activity is UNattributed. Name-shaped (short, no sentence
        // punctuation), so the shape gate accepted them and the module minted
        // one as a named `Organisation` "linked to" the address — a concrete
        // actor where the feed declared none (REQ-ATTR-003, observed live
        // 2026-09-16 on a mozilla.org scan: `Unknown APT Group`).
        "Unknown APT Group",
        "Unknown",
        "unknown",
        "Unknown Threat Actor",
        "Unattributed",
        "Unidentified",
        "N/A",
        "None",
        "Various",
        "Multiple",
        // The prefix boundary is any Unicode whitespace, not just a space:
        // `is_actor_name` tokenises with `split_whitespace()`, so a placeholder
        // separated by a tab, newline or NBSP is a name-shaped three-token
        // label there and must still be rejected (REQ-ATTR-003 — matching the
        // prefix only before a literal space let these through the same gate).
        "Unknown\tAPT Group",
        "Unknown\nAPT Group",
        "Unknown\u{a0}APT Group",
    ] {
        assert!(!is_actor_name(text), "{text:?} is not a name");
    }
}

#[test]
fn the_named_adversary_is_the_one_most_pulses_name_and_a_paragraph_is_never_one() {
    // The captured shape: one paragraph among pulses that name nothing.
    let pulses = vec![
        pulse_naming(None),
        pulse_naming(Some("")),
        pulse_naming(Some(CAPTURED_PARAGRAPH)),
        pulse_naming(None),
    ];
    assert_eq!(named_adversary(&pulses), None);

    // A placeholder is never an adversary even when several pulses corroborate
    // one (REQ-ATTR-003): a wave of non-attribution labels — differently spelled
    // and cased across these four pulses — is authors saying they could not
    // attribute it, not a named actor.
    let pulses = vec![
        pulse_naming(Some("Unknown APT Group")),
        pulse_naming(Some("unknown apt group")),
        pulse_naming(Some("Unknown")),
        pulse_naming(Some("Unattributed")),
    ];
    assert_eq!(named_adversary(&pulses), None);

    // Names are counted case-insensitively and the most-named wins; the
    // paragraph, listed first, never outranks them.
    let pulses = vec![
        pulse_naming(Some(CAPTURED_PARAGRAPH)),
        pulse_naming(Some("Emotet")),
        pulse_naming(Some("Mirai")),
        pulse_naming(Some(" mirai ")),
        pulse_naming(Some("Lazarus Group (a.k.a. Hidden Cobra)")),
        pulse_naming(Some("MIRAI")),
    ];
    assert_eq!(named_adversary(&pulses), Some(("Mirai".to_string(), 3)));

    // A tie goes to the first seen (OTX lists pulses newest first); a
    // parenthesised alias is trimmed to the lead name.
    let pulses = vec![
        pulse_naming(Some("Lazarus Group (a.k.a. Hidden Cobra)")),
        pulse_naming(Some("Emotet")),
    ];
    assert_eq!(
        named_adversary(&pulses),
        Some(("Lazarus Group".to_string(), 1))
    );
}

#[test]
fn an_actor_named_by_one_pulse_sits_below_one_named_by_two() {
    assert!((adversary_confidence(1) - confidence::LOW_MEDIUM).abs() < 0.01);
    assert!((adversary_confidence(2) - confidence::MEDIUM_SOLID).abs() < 0.01);
    assert!((adversary_confidence(40) - confidence::MEDIUM_SOLID).abs() < 0.01);
    assert!(adversary_confidence(1) < adversary_confidence(2));
}
