use super::*;

#[test]
fn accepts_domain_only() {
    assert!(DohResolver.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(!DohResolver.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
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
    let resp: DohResp = serde_json::from_str(json).expect("should succeed");
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
        .expect("should succeed");
    assert!(first_ip.has_tag("spf"));
    let inc = out.iter().find(|e| e.kind == EntityKind::Domain).expect("should succeed");
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
fn svcb_hints_from_friendly_presentation_string() {
    // dns.google's form.
    let out = parse_svcb_hints(
        "1 . alpn=h3,h2 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::6810:84e5",
    );
    assert_eq!(
        out,
        vec![
            "104.16.132.229".to_string(),
            "104.16.133.229".to_string(),
            "2606:4700::6810:84e5".to_string(),
        ]
    );
    // No hints present → empty.
    assert!(parse_svcb_hints("1 . alpn=h2").is_empty());
}

#[test]
fn svcb_hints_from_raw_rfc3597_wire_form() {
    // The EXACT bytes cloudflare-dns returned for cloudflare.com's HTTPS record
    // (captured live): priority 1, root target, alpn h3/h2, then ipv4hint (key 4)
    // = 104.16.132.229 / 104.16.133.229 and ipv6hint (key 6) = two v6 addresses.
    let data = r"\# 61 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68 10 84 e5 68 10 85 e5 00 06 00 20 26 06 47 00 00 00 00 00 00 00 00 00 68 10 84 e5 26 06 47 00 00 00 00 00 00 00 00 00 68 10 85 e5";
    let out = parse_svcb_hints(data);
    assert!(
        out.contains(&"104.16.132.229".to_string()) && out.contains(&"104.16.133.229".to_string()),
        "ipv4hint addresses must decode from the wire form: {out:?}"
    );
    assert!(
        out.iter().any(|ip| ip.starts_with("2606:4700")),
        "ipv6hint addresses must decode too: {out:?}"
    );
}

#[test]
fn svcb_wire_parser_is_panic_free_on_malformed_input() {
    // Truncated, non-hex, empty, and over-length-claimed inputs must all just
    // yield what parsed cleanly (or nothing) — never panic on the no-root target.
    assert!(parse_svcb_hints(r"\# 4 00 01").is_empty()); // priority only, no params
    assert!(parse_svcb_hints(r"\# 2 zz zz").is_empty()); // non-hex octets
    assert!(parse_svcb_hints(r"\#").is_empty()); // empty body
    assert!(parse_svcb_hints(r"\# 8 00 01 00 00 04 00 08 68").is_empty()); // vlen claims 8, only 1 byte
}

#[test]
fn https_record_emits_hint_ip_entities() {
    use crate::core::entity::EntityKind;
    let out = run(
        "HTTPS",
        &["1 . alpn=h3,h2 ipv4hint=198.51.100.7 ipv6hint=2001:db8::1"],
    );
    let v4 = out
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "198.51.100.7")
        .expect("ipv4hint → IpAddress entity");
    assert!(v4.has_tag("https-hint") && v4.has_tag("svcb") && v4.has_tag("ipv4"));
    let v6 = out
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress && e.value == "2001:db8::1")
        .expect("ipv6hint → IpAddress entity");
    assert!(v6.has_tag("https-hint") && v6.has_tag("ipv6"));
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
    let red = out.iter().find(|e| e.kind == EntityKind::Domain).expect("should succeed");
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
    assert_eq!(rtype_name(15), Some("MX"));
    assert_eq!(rtype_name(16), Some("TXT"));
    assert_eq!(rtype_name(2), Some("NS"));
    assert_eq!(rtype_name(65), Some("HTTPS"));
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
    let cn = out.iter().find(|e| e.has_tag("cname")).expect("should succeed");
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

#[test]
fn rtype_name_includes_soa() {
    assert_eq!(rtype_name(6), Some("SOA"));
}

#[test]
fn soa_rname_standard_hostmaster() {
    assert_eq!(
        soa_rname_to_email("hostmaster.example.com"),
        Some("hostmaster@example.com".to_string())
    );
}

#[test]
fn soa_rname_trailing_dot_stripped() {
    // Wire-format RNAME commonly carries a trailing dot.
    assert_eq!(
        soa_rname_to_email("hostmaster.example.com."),
        Some("hostmaster@example.com".to_string())
    );
}

#[test]
fn soa_rname_escaped_dot_in_local_part() {
    // `john\.doe.example.com` → local-part is `john.doe`, domain is `example.com`.
    assert_eq!(
        soa_rname_to_email("john\\.doe.example.com"),
        Some("john.doe@example.com".to_string())
    );
}

#[test]
fn soa_rname_single_label_returns_none() {
    // No boundary dot found → domain part is absent → None.
    assert_eq!(soa_rname_to_email("hostmaster"), None);
}

#[test]
fn soa_record_extracts_primary_ns_and_zone_admin_email() {
    // SOA RDATA: `mname rname serial refresh retry expire minimum`
    let data = "ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 300";
    let records = vec![rec_typed(6, "example.com.", data)];
    let mut seen = HashSet::new();
    let out = records_for_type("SOA", &records, "example.com", &mut seen, "s");
    assert_eq!(
        out.len(),
        2,
        "SOA must emit nameserver domain + zone-admin email"
    );
    let ns = out.iter().find(|e| e.kind == EntityKind::Domain).expect("should succeed");
    assert_eq!(ns.value, "ns1.example.com");
    assert!(ns.has_tag("soa") && ns.has_tag("nameserver"));
    let email = out.iter().find(|e| e.kind == EntityKind::Email).expect("should succeed");
    assert_eq!(email.value, "hostmaster@example.com");
    assert!(email.has_tag("soa") && email.has_tag("zone-admin"));
}

#[test]
fn dmarc_txt_extracts_rua_and_ruf_reporting_addresses() {
    let txt = "v=DMARC1; p=reject; rua=mailto:dmarc-rpts@example.com; ruf=mailto:dmarc-forensics@example.com";
    let out = run("TXT", &[txt]);
    let emails: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        emails.contains(&"dmarc-rpts@example.com"),
        "rua must be extracted"
    );
    assert!(
        emails.contains(&"dmarc-forensics@example.com"),
        "ruf must be extracted"
    );
    for e in out.iter().filter(|e| e.kind == EntityKind::Email) {
        assert!(e.has_tag("dmarc-reporting"));
    }
}

// ── CAA (RFC 8659, type 257) ────────────────────────────────────────────────
// The wire strings below are verbatim live captures: cloudflare-dns returns the
// raw RFC 3597 generic form, dns.google the presentation form.

#[test]
fn caa_parse_cloudflare_rfc3597_hex_issue_and_iodef() {
    // `\# 22 00 05 issue letsencrypt.org` — flags=00, taglen=05, tag="issue".
    let (tag, val) =
        parse_caa_rdata(r"\# 22 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67")
            .expect("valid issue record");
    assert_eq!(tag, "issue");
    assert_eq!(val, "letsencrypt.org");

    // `\# 38 00 05 iodef mailto:tls-abuse@cloudflare.com`.
    let (tag, val) = parse_caa_rdata(
        r"\# 38 00 05 69 6f 64 65 66 6d 61 69 6c 74 6f 3a 74 6c 73 2d 61 62 75 73 65 40 63 6c 6f 75 64 66 6c 61 72 65 2e 63 6f 6d",
    )
    .expect("valid iodef record");
    assert_eq!(tag, "iodef");
    assert_eq!(val, "mailto:tls-abuse@cloudflare.com");
}

#[test]
fn caa_parse_google_presentation_form() {
    assert_eq!(
        parse_caa_rdata(r#"0 issue "letsencrypt.org""#),
        Some(("issue".to_string(), "letsencrypt.org".to_string()))
    );
    assert_eq!(
        parse_caa_rdata(r#"0 iodef "mailto:tls-abuse@cloudflare.com""#),
        Some((
            "iodef".to_string(),
            "mailto:tls-abuse@cloudflare.com".to_string()
        ))
    );
    // Issuer parameters after `;` are retained in the value (parity with dns_intel).
    assert_eq!(
        parse_caa_rdata(r#"0 issue "digicert.com; cansignhttpexchanges=yes""#),
        Some((
            "issue".to_string(),
            "digicert.com; cansignhttpexchanges=yes".to_string()
        ))
    );
}

#[test]
fn caa_parse_rejects_malformed_and_non_caa() {
    assert_eq!(parse_caa_rdata(""), None);
    assert_eq!(parse_caa_rdata("0 issue"), None); // no value token
    assert_eq!(parse_caa_rdata("cdn.example.net."), None); // a stray CNAME answer
    assert_eq!(parse_caa_rdata(r"\# 1 00"), None); // truncated: taglen missing
    assert_eq!(parse_caa_rdata(r"\# 4 00 05 69 73"), None); // taglen 5 > available
}

#[test]
fn caa_entities_aggregate_policy_and_surface_iodef_security_contact() {
    // Mixed set across both wire forms — issue, issuewild, and an iodef mailto.
    let records = vec![
        rec(r#"0 issue "letsencrypt.org""#),
        rec(r#"0 issuewild "digicert.com""#),
        rec(
            r"\# 38 00 05 69 6f 64 65 66 6d 61 69 6c 74 6f 3a 74 6c 73 2d 61 62 75 73 65 40 63 6c 6f 75 64 66 6c 61 72 65 2e 63 6f 6d",
        ),
    ];
    let out = caa_entities(&records, "example.com", "s");

    // One aggregated CAA policy Domain entity for the queried domain.
    let policy = out
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "example.com")
        .expect("CAA policy entity");
    assert!(policy.has_tag("caa"));
    let a = &policy.evidence[0].attributes;
    assert_eq!(a.get("issue").map(String::as_str), Some("letsencrypt.org"));
    assert_eq!(a.get("issuewild").map(String::as_str), Some("digicert.com"));
    assert_eq!(
        a.get("iodef").map(String::as_str),
        Some("mailto:tls-abuse@cloudflare.com")
    );

    // The iodef mailto becomes a pivotable security-contact Email — the key
    // Termux-parity win (routed via the shared dns_intel extractor).
    let email = out
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("iodef security-contact email");
    assert_eq!(email.value, "tls-abuse@cloudflare.com");
    assert!(email.has_tag("security-contact"));
    assert!(email.has_tag("iodef"));
}

#[test]
fn caa_entities_empty_when_no_caa_records() {
    assert!(caa_entities(&[], "example.com", "s").is_empty());
    // Only unparseable answers → no policy entity fabricated.
    assert!(caa_entities(&[rec("cdn.example.net.")], "example.com", "s").is_empty());
}

// ── TLSRPT (RFC 8460, _smtp._tls.{domain} TXT) ──────────────────────────────

#[test]
fn tlsrpt_mailto_becomes_report_email() {
    // A non-infra reporting mailbox surfaces (real live records like google.com's
    // `sts-reports@google.com` sit on a provider domain and are gated below).
    let out = tlsrpt_entities(
        &[rec("v=TLSRPTv1;rua=mailto:tlsrpt@fabrikam.example")],
        "fabrikam.example",
        "s",
    );
    let email = out
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("TLSRPT rua mailto → Email");
    assert_eq!(email.value, "tlsrpt@fabrikam.example");
    assert!(email.has_tag("tlsrpt-report") && email.has_tag("dns"));
}

#[test]
fn tlsrpt_infrastructure_mailbox_is_gated() {
    // Parity with the dns_intel transport: a provider-domain reporting desk is
    // filtered so the two DNS paths surface the identical contact set.
    let out = tlsrpt_entities(
        &[rec("v=TLSRPTv1;rua=mailto:sts-reports@google.com")],
        "google.com",
        "s",
    );
    assert!(out.iter().all(|e| e.kind != EntityKind::Email));
}

#[test]
fn tlsrpt_https_endpoint_becomes_domain_lead() {
    // Verbatim live shape from microsoft.com's _smtp._tls record.
    let out = tlsrpt_entities(
        &[rec(
            "v=TLSRPTv1; rua=https://tlsrpt.azurewebsites.net/report",
        )],
        "microsoft.com",
        "s",
    );
    let dom = out
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("TLSRPT rua https → Domain host");
    assert_eq!(dom.value, "tlsrpt.azurewebsites.net");
    assert!(dom.has_tag("tlsrpt-report"));
}

#[test]
fn tlsrpt_ignores_non_tlsrpt_and_empty() {
    assert!(tlsrpt_entities(&[rec("v=spf1 -all")], "x.com", "s").is_empty());
    assert!(tlsrpt_entities(&[rec("v=TLSRPTv1;")], "x.com", "s").is_empty());
    assert!(tlsrpt_entities(&[], "x.com", "s").is_empty());
}
