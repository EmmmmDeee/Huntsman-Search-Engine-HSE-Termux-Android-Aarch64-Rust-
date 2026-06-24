use super::*;

#[test]
fn accepts_domain_url_and_ip() {
    assert!(DohResolver.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(DohResolver.accepts(&Target::new(TargetKind::Url, "https://x.com")));
    assert!(DohResolver.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(!DohResolver.accepts(&Target::new(TargetKind::Email, "x@example.com")));
    assert!(!DohResolver.accepts(&Target::new(TargetKind::Phone, "+1555")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(
        DohResolver.cost(),
        crate::core::module::ModuleCost::Free
    ));
}

#[test]
fn doh_resp_deser() {
    let json = r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"93.184.216.34"}]}"#;
    let resp: DohResp = serde_json::from_str(json).unwrap();
    assert_eq!(resp.answer.len(), 1);
    assert_eq!(resp.answer[0].data, "93.184.216.34");
}

fn rec(data: &str) -> DohRecord {
    DohRecord {
        name: String::new(),
        rtype: 0,
        data: data.to_string(),
    }
}

fn run(rtype: &str, datas: &[&str]) -> Vec<Entity> {
    let records: Vec<DohRecord> = datas.iter().map(|d| rec(d)).collect();
    let mut seen = HashSet::new();
    records_for_type(rtype, &records, "example.com", &mut seen, "s")
}

#[test]
fn target_domain_reduces_url_and_trims() {
    assert_eq!(
        target_domain(TargetKind::Domain, "  Example.com "),
        Some("Example.com".into())
    );
    assert_eq!(
        target_domain(TargetKind::Url, "https://host.example.com/a?b=1"),
        Some("host.example.com".into())
    );
    assert_eq!(target_domain(TargetKind::Domain, "   "), None);
}

#[test]
fn a_and_aaaa_become_tagged_ip_entities() {
    let a = run("A", &["93.184.216.34"]);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].kind, EntityKind::IpAddress);
    assert!(a[0].has_tag("dns") && a[0].has_tag("ipv4"));
    assert_eq!(
        a[0].evidence[0]
            .attributes
            .get("record_type")
            .map(String::as_str),
        Some("A")
    );

    let aaaa = run("AAAA", &["2606:2800:220:1:248:1893:25c8:1946"]);
    assert!(aaaa[0].has_tag("ipv6"));
}

#[test]
fn mx_takes_last_field_and_requires_a_dot() {
    // Priority + host; only the host is kept, trailing dot stripped.
    let mx = run("MX", &["10 mail.example.com."]);
    assert_eq!(mx.len(), 1);
    assert_eq!(mx[0].kind, EntityKind::Domain);
    assert_eq!(mx[0].value, "mail.example.com");
    assert!(mx[0].has_tag("mx"));
    // A dotless MX host (e.g. "0 .") is rejected.
    assert!(run("MX", &["0 ."]).is_empty());
}

#[test]
fn spf_txt_extracts_ip4_ip6_and_includes_others_ignored() {
    let out = run(
        "TXT",
        &[
            "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.google.com -all",
            "some-unrelated-txt-record",
        ],
    );
    // IPv4 + IPv6 (both CIDR-stripped) + one include domain; non-SPF ignored.
    assert_eq!(out.len(), 3);
    let ips: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .map(|e| e.value.as_str())
        .collect();
    assert!(ips.contains(&"198.51.100.0"));
    // IPv6 member surfaced with its internal colons intact (CIDR removed).
    assert!(ips.contains(&"2001:db8::"));
    let first_ip = out
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .unwrap();
    assert!(first_ip.has_tag("spf"));
    let inc = out.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
    assert_eq!(inc.value, "_spf.google.com");
    assert!(inc.has_tag("spf-include"));
}

#[test]
fn unquote_txt_reconstructs_single_and_chunked_records() {
    // Bare (unquoted) single string — passthrough.
    assert_eq!(unquote_txt("v=spf1 -all"), "v=spf1 -all");
    // Single quoted string.
    assert_eq!(unquote_txt(r#""v=spf1 -all""#), "v=spf1 -all");
    // Two chunks: concatenated with NO separator (the space lives inside
    // chunk 1, at the operator's split point) — the stray `" "` is gone.
    assert_eq!(
        unquote_txt(r#""v=spf1 ip4:198.51.100.0/24 " "include:_spf.example.com -all""#),
        "v=spf1 ip4:198.51.100.0/24 include:_spf.example.com -all"
    );
    // A token split mid-word across the chunk boundary rejoins cleanly.
    assert_eq!(unquote_txt(r#""inclu" "de:x.com""#), "include:x.com");
    // Escaped quote inside a chunk is decoded to a literal.
    assert_eq!(unquote_txt(r#""a\"b""#), "a\"b");
}

#[test]
fn chunked_spf_record_parses_into_members() {
    // The whole point: a long SPF record split across two DoH chunks must
    // still yield its ip4 + include members (it would not with the old
    // trim_matches: the boundary tokens were mangled).
    let out = run(
        "TXT",
        &[r#""v=spf1 ip4:203.0.113.7 " "include:_spf.example.org -all""#],
    );
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::IpAddress && e.value == "203.0.113.7")
    );
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "_spf.example.org")
    );
}

#[test]
fn spf_redirect_surfaces_target_as_domain() {
    let out = run("TXT", &["v=spf1 redirect=_spf.example.net"]);
    let red = out.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
    assert_eq!(red.value, "_spf.example.net");
    assert!(red.has_tag("spf-redirect"));
}

#[test]
fn spf_skips_empty_ip4_and_dotless_or_empty_include() {
    // Bare `ip4:`, `ip4:/24`, dotless `include:`, and empty `include:` must
    // not produce blank/garbage entities.
    let out = run(
        "TXT",
        &["v=spf1 ip4: ip4:/24 include: include:localhost -all"],
    );
    assert!(out.is_empty());
}

#[test]
fn dedup_is_cross_type_and_prefixed() {
    // Same value as both an A record and an SPF ip4 → distinct (prefixed keys),
    // but a repeated A record within the run is deduped.
    let mut seen = HashSet::new();
    let a = records_for_type(
        "A",
        &[rec("1.2.3.4"), rec("1.2.3.4")],
        "example.com",
        &mut seen,
        "s",
    );
    assert_eq!(a.len(), 1); // intra-run dedup
    let spf = records_for_type(
        "TXT",
        &[rec("v=spf1 ip4:1.2.3.4 -all")],
        "example.com",
        &mut seen,
        "s",
    );
    // Different key prefix (spf: vs ip:) → still surfaced.
    assert_eq!(spf.len(), 1);
    assert!(spf[0].has_tag("spf"));
}

#[test]
fn ns_and_cname_strip_trailing_dot_and_need_a_dot() {
    assert_eq!(run("NS", &["ns1.example.com."])[0].value, "ns1.example.com");
    assert_eq!(
        run("CNAME", &["target.cdn.net."])[0].value,
        "target.cdn.net"
    );
    assert!(run("CNAME", &["localhost"]).is_empty());
}

fn rec_typed(rtype: u16, name: &str, data: &str) -> DohRecord {
    DohRecord {
        name: name.to_string(),
        rtype,
        data: data.to_string(),
    }
}

#[test]
fn rtype_name_maps_handled_types() {
    assert_eq!(rtype_name(1), Some("A"));
    assert_eq!(rtype_name(28), Some("AAAA"));
    assert_eq!(rtype_name(5), Some("CNAME"));
    assert_eq!(rtype_name(6), Some("SOA"));
    assert_eq!(rtype_name(12), Some("PTR"));
    assert_eq!(rtype_name(15), Some("MX"));
    assert_eq!(rtype_name(16), Some("TXT"));
    assert_eq!(rtype_name(2), Some("NS"));
    assert_eq!(rtype_name(257), Some("CAA"));
    assert_eq!(rtype_name(99), None); // unmapped → caller falls back to queried type
}

#[test]
fn answer_classified_by_actual_record_type_not_queried_type() {
    // An A query whose Answer is a CNAME chain: [CNAME www→cdn, A 1.2.3.4].
    // The CNAME must become a Domain (not parsed as an A/IP), the A an IP.
    let records = vec![
        rec_typed(5, "www.example.com.", "cdn.example.net."),
        rec_typed(1, "cdn.example.net.", "1.2.3.4"),
    ];
    let mut seen = HashSet::new();
    let out = records_for_type("A", &records, "www.example.com", &mut seen, "s");
    assert!(out.iter().any(|e| e.kind == EntityKind::Domain
        && e.value == "cdn.example.net"
        && e.has_tag("cname")));
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::IpAddress && e.value == "1.2.3.4")
    );
    // The owner name is surfaced as evidence on the CNAME finding.
    let cn = out.iter().find(|e| e.has_tag("cname")).unwrap();
    assert_eq!(
        cn.evidence[0]
            .attributes
            .get("record_name")
            .map(String::as_str),
        Some("www.example.com")
    );
}

#[test]
fn untyped_record_falls_back_to_queried_type() {
    // rtype 0 (test/hand-built) → dispatch on the queried type, preserving the
    // prior behaviour relied on by the rest of the suite.
    let records = vec![rec_typed(0, "", "5.6.7.8")];
    let mut seen = HashSet::new();
    let out = records_for_type("A", &records, "example.com", &mut seen, "s");
    assert!(
        out.iter()
            .any(|e| e.kind == EntityKind::IpAddress && e.value == "5.6.7.8")
    );
}

// ── New tests for SOA, CAA, PTR, DMARC, reverse-DNS ────────────────────────

#[test]
fn ip_to_reverse_dns_ipv4() {
    assert_eq!(
        ip_to_reverse_dns("1.2.3.4").as_deref(),
        Some("4.3.2.1.in-addr.arpa")
    );
    assert_eq!(
        ip_to_reverse_dns("8.8.8.8").as_deref(),
        Some("8.8.8.8.in-addr.arpa")
    );
    assert_eq!(
        ip_to_reverse_dns("192.168.1.100").as_deref(),
        Some("100.1.168.192.in-addr.arpa")
    );
}

#[test]
fn ip_to_reverse_dns_ipv6() {
    // ::1 (loopback) reverse
    assert_eq!(
        ip_to_reverse_dns("::1").as_deref(),
        Some("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")
    );
    // 2001:db8::1 reverse (documentation prefix)
    assert_eq!(
        ip_to_reverse_dns("2001:db8::1").as_deref(),
        Some("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
    );
}

#[test]
fn ip_to_reverse_dns_invalid() {
    assert!(ip_to_reverse_dns("not-an-ip").is_none());
    assert!(ip_to_reverse_dns("").is_none());
    assert!(ip_to_reverse_dns("999.999.999.999").is_none());
}

#[test]
fn parse_soa_fields_extracts_mname_and_rname() {
    let soa = "ns1.example.com. hostmaster.example.com. 2024060101 3600 900 604800 300";
    let (mname, email) = parse_soa_fields(soa).unwrap();
    assert_eq!(mname, "ns1.example.com");
    assert_eq!(email, "hostmaster@example.com");
}

#[test]
fn parse_soa_fields_dotted_local_part() {
    // local-part with a dot: `john.doe.example.com.` → `john@doe.example.com`
    // (only the first dot is the separator)
    let soa = "ns1.example.com. john.doe.example.com. 1 3600 900 604800 300";
    let (_, email) = parse_soa_fields(soa).unwrap();
    assert_eq!(email, "john@doe.example.com");
}

#[test]
fn parse_soa_fields_too_short_domain_returns_none() {
    // rname domain-part has no dot (e.g. "admin.tld") — not a valid address.
    let soa = "ns1.example.com. admin.com 1 3600 900 604800 300";
    assert!(parse_soa_fields(soa).is_none());
}

#[test]
fn soa_record_emits_mname_domain_and_email() {
    let out = run(
        "SOA",
        &["ns1.example.com. hostmaster.example.com. 2024060101 3600 900 604800 300"],
    );
    assert_eq!(out.len(), 2);
    let ns = out.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
    assert_eq!(ns.value, "ns1.example.com");
    assert!(ns.has_tag("ns-primary"));
    let mail = out.iter().find(|e| e.kind == EntityKind::Email).unwrap();
    assert_eq!(mail.value, "hostmaster@example.com");
    assert!(mail.has_tag("soa-contact"));
}

#[test]
fn parse_caa_issuer_extracts_issue_and_issuewild() {
    assert_eq!(
        parse_caa_issuer("0 issue \"letsencrypt.org\"").as_deref(),
        Some("letsencrypt.org")
    );
    assert_eq!(
        parse_caa_issuer("0 issuewild \"comodoca.com\"").as_deref(),
        Some("comodoca.com")
    );
}

#[test]
fn parse_caa_issuer_strips_parameters() {
    // CAA value may include ;param=val after the domain.
    assert_eq!(
        parse_caa_issuer("0 issue \"letsencrypt.org;validationmethods=dns-01\"").as_deref(),
        Some("letsencrypt.org")
    );
}

#[test]
fn parse_caa_issuer_prohibit_all_returns_none() {
    // ";" means no CA is authorised to issue — not a Domain entity.
    assert!(parse_caa_issuer("0 issue \";\"").is_none());
    assert!(parse_caa_issuer("0 issuewild \";\"").is_none());
}

#[test]
fn parse_caa_issuer_iodef_returns_none() {
    // iodef carries an incident-report URI, not a CA domain.
    assert!(parse_caa_issuer("0 iodef \"mailto:caa@example.com\"").is_none());
}

#[test]
fn caa_record_emits_ca_domain() {
    let out = run("CAA", &["0 issue \"letsencrypt.org\""]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EntityKind::Domain);
    assert_eq!(out[0].value, "letsencrypt.org");
    assert!(out[0].has_tag("caa-issuer"));
}

#[test]
fn caa_multiple_issuers_deduplicated() {
    let out = run(
        "CAA",
        &[
            "0 issue \"letsencrypt.org\"",
            "0 issuewild \"letsencrypt.org\"", // same CA — deduplicated
            "0 issue \"digicert.com\"",
        ],
    );
    assert_eq!(out.len(), 2);
    let vals: Vec<&str> = out.iter().map(|e| e.value.as_str()).collect();
    assert!(vals.contains(&"letsencrypt.org"));
    assert!(vals.contains(&"digicert.com"));
}

#[test]
fn ptr_record_emits_hostname_domain() {
    let out = run("PTR", &["mail.example.com."]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EntityKind::Domain);
    assert_eq!(out[0].value, "mail.example.com");
    assert!(out[0].has_tag("ptr"));
}

#[test]
fn ptr_dotless_result_rejected() {
    assert!(run("PTR", &["localhost"]).is_empty());
    assert!(run("PTR", &[""]).is_empty());
}

#[test]
fn dmarc_rua_emails_extracts_rua_and_ruf() {
    let txt = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:reports@example.org; ruf=mailto:forensic@example.com";
    let emails = dmarc_rua_emails(txt);
    assert!(emails.contains(&"dmarc@example.com".to_string()));
    assert!(emails.contains(&"reports@example.org".to_string()));
    assert!(emails.contains(&"forensic@example.com".to_string()));
}

#[test]
fn dmarc_rua_non_mailto_uris_ignored() {
    let txt = "v=DMARC1; p=quarantine; rua=https://example.com/dmarc,mailto:ok@example.com";
    let emails = dmarc_rua_emails(txt);
    assert_eq!(emails, vec!["ok@example.com".to_string()]);
}

#[test]
fn txt_dmarc_record_emits_email_entities() {
    let out = run(
        "TXT",
        &["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:ruf@example.com"],
    );
    assert_eq!(out.len(), 2);
    let addrs: Vec<&str> = out.iter().map(|e| e.value.as_str()).collect();
    assert!(addrs.contains(&"dmarc@example.com"));
    assert!(addrs.contains(&"ruf@example.com"));
    assert!(
        out.iter()
            .all(|e| e.kind == EntityKind::Email && e.has_tag("dmarc"))
    );
}

#[test]
fn txt_non_spf_non_dmarc_ignored() {
    // Generic TXT records (google site verification, etc.) produce no entities.
    let out = run("TXT", &["google-site-verification=abc123", "docusign=xyz"]);
    assert!(out.is_empty());
}

// ── RFC 3597 hex-encoded CAA (Cloudflare DoH format) ──────────────────────

#[test]
fn parse_caa_issuer_handles_cloudflare_hex_format() {
    // \# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d
    // = flags=0, tag_len=5, tag="issue", value="digicert.com"
    let hex = r"\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d";
    assert_eq!(parse_caa_issuer(hex).as_deref(), Some("digicert.com"));
}

#[test]
fn parse_caa_issuer_hex_issuewild() {
    // \# 23 00 09 69 73 73 75 65 77 69 6c 64 64 69 67 69 63 65 72 74 2e 63 6f 6d
    // = flags=0, tag_len=9, tag="issuewild", value="digicert.com"
    let hex = r"\# 23 00 09 69 73 73 75 65 77 69 6c 64 64 69 67 69 63 65 72 74 2e 63 6f 6d";
    assert_eq!(parse_caa_issuer(hex).as_deref(), Some("digicert.com"));
}

#[test]
fn caa_hex_record_emits_ca_domain() {
    let out = run(
        "CAA",
        &[r"\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d"],
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].value, "digicert.com");
    assert!(out[0].has_tag("caa-issuer"));
}

#[test]
fn caa_hex_and_text_formats_deduplicated() {
    // Same CA from Cloudflare hex format + Google text format — should dedup
    let hex = r"\# 19 00 05 69 73 73 75 65 64 69 67 69 63 65 72 74 2e 63 6f 6d"; // issue digicert.com
    let text = "0 issuewild \"digicert.com\"";
    let out = run("CAA", &[hex, text]);
    assert_eq!(out.len(), 1, "deduplicated to single entity");
    assert_eq!(out[0].value, "digicert.com");
}
