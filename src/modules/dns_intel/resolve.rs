use hickory_resolver::proto::rr::{RData, RecordType};

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};
use crate::util::dns::shared_resolver;

use super::SRC;
use super::helpers::{soa_rname_to_email, verification_vendor};

/// A / AAAA / MX / NS / SOA / TXT / DMARC — run concurrently via `tokio::join!`.
///
/// DMARC records are published at `_dmarc.{domain}` (RFC 7489 §6.6.3), never at
/// the apex. The `_dmarc` lookup runs concurrently with the other record types so
/// it adds zero serial latency.
pub(super) async fn resolve_records(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let resolver = shared_resolver();
    let domain = target.value.as_str();
    let dmarc_name = format!("_dmarc.{domain}");
    // TLSRPT (RFC 8460) lives at `_smtp._tls.{domain}`, like DMARC at `_dmarc.`.
    let tlsrpt_name = format!("_smtp._tls.{domain}");
    let mut entities: Vec<Entity> = Vec::new();

    let (ips, mxs, nss, soa, txts, dmarc_txts, tlsrpt_txts) = tokio::join!(
        resolver.lookup_ip(domain),
        resolver.mx_lookup(domain),
        resolver.ns_lookup(domain),
        resolver.soa_lookup(domain),
        resolver.txt_lookup(domain),
        resolver.txt_lookup(dmarc_name.as_str()),
        resolver.txt_lookup(tlsrpt_name.as_str()),
    );

    // A + AAAA
    if let Ok(lookup) = ips {
        entities.extend(lookup.as_lookup().answers().iter().filter_map(|record| {
            let (ip_str, record_type, ip_version) = match &record.data {
                RData::A(a) => (a.0.to_string(), "A", "4"),
                RData::AAAA(aaaa) => (aaaa.0.to_string(), "AAAA", "6"),
                _ => return None,
            };
            let mut e = Entity::new(
                EntityKind::IpAddress,
                &ip_str,
                confidence::VERY_HIGH_PLUSPLUS,
                &ctx.scan_id,
            );
            e.tag(if record_type == "A" { "ipv4" } else { "ipv6" });
            e.add_evidence(
                Evidence::new(SRC, format!("{record_type} record for {domain}"))
                    .with_attr("record_type", record_type)
                    .with_attr("domain", domain)
                    .with_attr("ttl_secs", record.ttl.to_string())
                    .with_attr("ip_version", ip_version),
            );
            Some(e)
        }));
    }

    // MX records
    if let Ok(lookup) = mxs {
        entities.extend(lookup.answers().iter().filter_map(|record| {
            let RData::MX(mx) = &record.data else {
                return None;
            };
            let host = mx.exchange.to_ascii();
            let host = host.trim_end_matches('.').to_string();
            if host.is_empty() {
                return None;
            }
            let mut e = Entity::new(
                EntityKind::Domain,
                &host,
                confidence::HIGH_PLUSPLUS_PLUS,
                &ctx.scan_id,
            );
            e.tag("mx");
            e.add_evidence(
                Evidence::new(SRC, format!("MX record for {domain}"))
                    .with_attr("record_type", "MX")
                    .with_attr("priority", mx.preference.to_string())
                    .with_attr("parent_domain", domain)
                    .with_attr("ttl_secs", record.ttl.to_string()),
            );
            Some(e)
        }));
    }

    // NS records
    if let Ok(lookup) = nss {
        entities.extend(lookup.answers().iter().filter_map(|record| {
            let RData::NS(ns) = &record.data else {
                return None;
            };
            let host = ns.0.to_ascii();
            let host = host.trim_end_matches('.').to_string();
            if host.is_empty() {
                return None;
            }
            let mut e = Entity::new(EntityKind::Domain, &host, confidence::EXPERT, &ctx.scan_id);
            e.tag("ns");
            e.add_evidence(
                Evidence::new(SRC, format!("NS record for {domain}"))
                    .with_attr("record_type", "NS")
                    .with_attr("parent_domain", domain)
                    .with_attr("ttl_secs", record.ttl.to_string()),
            );
            Some(e)
        }));
    }

    // SOA
    if let Ok(lookup) = soa
        && let Some((dns_record, soa_data)) = lookup.answers().iter().find_map(|r| match &r.data {
            RData::SOA(s) => Some((r, s)),
            _ => None,
        })
    {
        let mname = soa_data.mname.to_ascii();
        let mname = mname.trim_end_matches('.');
        let rname_raw = soa_data.rname.to_ascii();
        let admin_email = soa_rname_to_email(rname_raw.trim_end_matches('.'));

        let mut e = Entity::new(EntityKind::Domain, domain, 0.92, &ctx.scan_id);
        e.tag("soa");
        let mut ev = Evidence::new(SRC, format!("SOA record for {domain}"))
            .with_attr("record_type", "SOA")
            .with_attr("primary_ns", mname)
            .with_attr("serial", soa_data.serial.to_string())
            .with_attr("refresh_secs", soa_data.refresh.to_string())
            .with_attr("retry_secs", soa_data.retry.to_string())
            .with_attr("expire_secs", soa_data.expire.to_string())
            .with_attr("minimum_ttl_secs", soa_data.minimum.to_string())
            .with_attr("ttl_secs", dns_record.ttl.to_string());
        if !admin_email.is_empty() {
            ev = ev.with_attr("admin_email", &admin_email);
        }
        e.add_evidence(ev);
        entities.push(e);

        // Emit the admin contact as a discrete Email entity when present — but
        // NOT when it's a role/provider mailbox (`hostmaster@`, `dns@`, an
        // infra-domain desk). The SOA RNAME is the zone's administrative contact,
        // never the subject's PII; a live domain-heavy scan surfaced dozens of
        // these (`dns@jomax.net`, `abuse@cloudflare.com`) treated as the person
        // and identity-clustered. Mirrors the whois/ripestat/search_engines gate;
        // a genuine personal admin (a real local-part on a non-infra domain) is
        // still kept.
        if admin_email.contains('@') && !crate::util::domains::is_infrastructure_email(&admin_email)
        {
            let mut em = Entity::new(
                EntityKind::Email,
                &admin_email,
                confidence::HIGH_PLUS,
                &ctx.scan_id,
            );
            em.tag("dns-admin");
            em.add_evidence(
                Evidence::new(SRC, format!("Zone admin for {domain}"))
                    .with_attr("source", "SOA RNAME")
                    .with_attr("parent_domain", domain),
            );
            entities.push(em);
        }
    }

    // TXT records
    if let Ok(lookup) = txts {
        let mut min_ttl: Option<u32> = None;
        let txts: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => {
                    min_ttl = Some(min_ttl.map_or(r.ttl, |prev| prev.min(r.ttl)));
                    Some(txt.to_string())
                }
                _ => None,
            })
            .collect();
        if !txts.is_empty() {
            let mut dom = Entity::new(
                EntityKind::Domain,
                domain,
                confidence::VERY_HIGH_PLUS,
                &ctx.scan_id,
            );
            for t in &txts {
                let t = t.trim_matches('"');
                let b = t.as_bytes();
                if crate::util::spf::is_spf(t) {
                    dom.tag("spf");
                    // Static SPF security analysis: tag the catch-all posture and
                    // every misconfiguration (open `+all`, >10 DNS lookups,
                    // deprecated `ptr`, macros, unreachable mechanisms, …) so a
                    // weak or broken sender policy surfaces as a queryable signal.
                    if let Some(spf) = crate::util::spf::parse(t) {
                        dom.tag(spf.all_policy().tag());
                        let issues = spf.issues();
                        for issue in &issues {
                            dom.tag(issue.tag());
                        }
                        if !issues.is_empty() {
                            let flags = issues
                                .iter()
                                .map(crate::util::spf::SpfIssue::tag)
                                .collect::<Vec<_>>()
                                .join(", ");
                            dom.add_evidence(Evidence::new(
                                SRC,
                                format!(
                                    "SPF posture {} — {} DNS-lookup term(s); flags: {flags}",
                                    spf.all_policy().tag(),
                                    spf.dns_lookup_count(),
                                ),
                            ));
                        }
                    }
                    for member in crate::util::spf::members(t) {
                        match member {
                            crate::util::spf::Member::Ip(ip) => {
                                let mut ie = Entity::new(
                                    EntityKind::IpAddress,
                                    ip,
                                    confidence::VERY_HIGH,
                                    &ctx.scan_id,
                                );
                                ie.tag("dns");
                                ie.tag("spf");
                                ie.add_evidence(
                                    Evidence::new(
                                        SRC,
                                        format!("SPF authorised sender for {domain}"),
                                    )
                                    // Structured, not just prose in the message: lets a
                                    // correlator rule (AU-111) match this IP back to the
                                    // domain that authorised it without parsing text.
                                    .with_attr("domain", domain),
                                );
                                entities.push(ie);
                            }
                            crate::util::spf::Member::Include(inc) => {
                                let mut de = Entity::new(
                                    EntityKind::Domain,
                                    inc,
                                    confidence::HIGH,
                                    &ctx.scan_id,
                                );
                                de.tag("dns");
                                de.tag("spf-include");
                                de.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF include for {domain}"),
                                ));
                                entities.push(de);
                            }
                            crate::util::spf::Member::Redirect(red) => {
                                let mut de = Entity::new(
                                    EntityKind::Domain,
                                    red,
                                    confidence::HIGH,
                                    &ctx.scan_id,
                                );
                                de.tag("dns");
                                de.tag("spf-redirect");
                                de.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF redirect for {domain}"),
                                ));
                                entities.push(de);
                            }
                            crate::util::spf::Member::A(a_dom) => {
                                let mut de = Entity::new(
                                    EntityKind::Domain,
                                    a_dom,
                                    confidence::HIGH,
                                    &ctx.scan_id,
                                );
                                de.tag("dns");
                                de.tag("spf-a");
                                de.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF a: mechanism for {domain}"),
                                ));
                                entities.push(de);
                            }
                            crate::util::spf::Member::Mx(mx_dom) => {
                                let mut de = Entity::new(
                                    EntityKind::Domain,
                                    mx_dom,
                                    confidence::HIGH,
                                    &ctx.scan_id,
                                );
                                de.tag("dns");
                                de.tag("spf-mx");
                                de.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF mx: mechanism for {domain}"),
                                ));
                                entities.push(de);
                            }
                        }
                    }
                } else if b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"v=dkim1") {
                    // A DKIM public-key record published at the apex is unusual
                    // (DKIM selector records live at `<selector>._domainkey.{domain}`)
                    // but parseable — tag its presence.
                    dom.tag("dkim");
                } else if let Some(vendor) = verification_vendor(t) {
                    // Domain-ownership verification record → discloses a SaaS
                    // vendor relationship (`verified:google`, `verified:atlassian`, …).
                    dom.tag(format!("verified:{vendor}"));
                }
            }
            for txt in &txts {
                crate::util::http::scan_for_api_keys_with_source(txt, "dns_txt");
            }
            let mut txt_ev = Evidence::new(SRC, format!("{} TXT records", txts.len()))
                .with_attr("txt_records", txts.join(" | "))
                .with_attr("txt_count", txts.len().to_string());
            if let Some(ttl) = min_ttl {
                txt_ev = txt_ev.with_attr("ttl_secs", ttl.to_string());
            }
            dom.add_evidence(txt_ev);
            entities.push(dom);
        }
    }

    // DMARC record at `_dmarc.{domain}` (RFC 7489 §6.6.3).
    // The apex TXT lookup above never contains DMARC records — they are
    // always published at the `_dmarc.` subdomain. This is the correct lookup.
    if let Ok(lookup) = dmarc_txts {
        for record in lookup.answers() {
            let RData::TXT(txt_data) = &record.data else {
                continue;
            };
            let txt = txt_data.to_string();
            let txt = txt.trim_matches('"');
            if !crate::util::dmarc::is_dmarc(txt) {
                continue;
            }
            let Some(dmarc) = crate::util::dmarc::parse(txt) else {
                continue;
            };

            // Tag the domain entity with the DMARC policy and any issues.
            let mut dom = Entity::new(
                EntityKind::Domain,
                domain,
                confidence::VERY_HIGH_PLUS,
                &ctx.scan_id,
            );
            dom.tag("dmarc");
            if let Some(p) = dmarc.policy {
                dom.tag(p.tag());
            }
            let issues = dmarc.issues();
            for issue in &issues {
                dom.tag(issue.tag());
            }

            let policy_str = dmarc
                .policy
                .map_or("dmarc:missing-policy", crate::util::dmarc::DmarcPolicy::tag);
            let sp_str = dmarc
                .sp
                .map_or("(inherited)", crate::util::dmarc::DmarcPolicy::tag);
            let mut ev = Evidence::new(
                SRC,
                format!(
                    "DMARC policy: {policy_str}; sp={sp_str}; pct={pct}",
                    pct = dmarc.pct
                ),
            )
            .with_attr("record_type", "DMARC")
            .with_attr("policy", policy_str)
            .with_attr("subdomain_policy", sp_str)
            .with_attr("pct", dmarc.pct.to_string())
            .with_attr(
                "adkim",
                if dmarc.adkim == crate::util::dmarc::AlignmentMode::Strict {
                    "s"
                } else {
                    "r"
                },
            )
            .with_attr(
                "aspf",
                if dmarc.aspf == crate::util::dmarc::AlignmentMode::Strict {
                    "s"
                } else {
                    "r"
                },
            )
            .with_attr("ttl_secs", record.ttl.to_string());
            if !issues.is_empty() {
                let flags = issues
                    .iter()
                    .map(crate::util::dmarc::DmarcIssue::tag)
                    .collect::<Vec<_>>()
                    .join(", ");
                ev = ev.with_attr("issues", flags);
            }
            if !dmarc.rua.is_empty() {
                ev = ev.with_attr("rua", dmarc.rua.join(", "));
            }
            if !dmarc.ruf.is_empty() {
                ev = ev.with_attr("ruf", dmarc.ruf.join(", "));
            }
            dom.add_evidence(ev);
            entities.push(dom);

            // `rua=` / `ruf=` report addresses are high-value OSINT: they
            // reveal where the organisation receives DMARC failure reports,
            // often exposing internal security-team inboxes or third-party
            // DMARC reporting services.
            for addr in dmarc.report_addresses() {
                if crate::util::domains::is_infrastructure_email(addr) {
                    continue;
                }
                let mut ee = Entity::new(EntityKind::Email, addr, 0.72, &ctx.scan_id);
                ee.tag("dmarc-report");
                ee.tag("dns");
                ee.add_evidence(
                    Evidence::new(SRC, format!("DMARC report address for {domain}"))
                        .with_attr("record_type", "DMARC")
                        .with_attr("parent_domain", domain),
                );
                entities.push(ee);
            }
            // Only one DMARC record is valid per domain (first `v=DMARC1` wins).
            break;
        }
    }

    // TLSRPT (RFC 8460) at `_smtp._tls.{domain}` — its `rua=` names a published
    // mail-security reporting contact (Email or https endpoint), the same class
    // of OSINT pivot as DMARC `rua`.
    if let Ok(lookup) = tlsrpt_txts {
        let txts: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt_data) => Some(txt_data.to_string()),
                _ => None,
            })
            .collect();
        entities.extend(tlsrpt_entities(&txts, domain, &ctx.scan_id));
    }

    Ok(entities)
}

/// Map `_smtp._tls` TXT record strings into TLSRPT reporting-contact entities.
/// `mailto:` destinations become `Email` entities tagged `tlsrpt-report`;
/// `http(s)://` collection endpoints become `Domain` leads for their host. A
/// domain has at most one valid TLSRPT record (first `v=TLSRPTv1` wins).
///
/// Shares the pure [`crate::util::tlsrpt`] parser with `doh_resolver` (one
/// definition, no drift) AND the same `is_infrastructure_email` gate, so both
/// DNS transports surface the identical contact set — a provider desk
/// (`sts-reports@google.com`) is dropped rather than clustered as the subject,
/// matching how this module already gates its DMARC/SOA email emission.
/// **Pure** (no network/IO), unit-tested directly.
pub(super) fn tlsrpt_entities(txts: &[String], domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for raw in txts {
        let txt = raw.trim_matches('"');
        let Some(parsed) = crate::util::tlsrpt::parse(txt) else {
            continue;
        };
        for addr in &parsed.emails {
            if crate::util::domains::is_infrastructure_email(addr) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Email, addr, 0.72, scan_id);
            e.tag("dns");
            e.tag("tlsrpt-report");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("TLSRPT (SMTP-TLS) report address for {domain}"),
                )
                .with_attr("record_type", "TLSRPT")
                .with_attr("parent_domain", domain),
            );
            out.push(e);
        }
        for url in &parsed.urls {
            if let Some(host) = crate::util::url_util::host_from_url(url)
                && host.contains('.')
                && host != domain
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.58, scan_id);
                d.tag("dns");
                d.tag("tlsrpt-report");
                d.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("TLSRPT (SMTP-TLS) reporting endpoint host for {domain}"),
                    )
                    .with_attr("record_type", "TLSRPT")
                    .with_attr("rua", url.as_str()),
                );
                out.push(d);
            }
        }
        // Only one TLSRPT record is valid per domain (first `v=TLSRPTv1` wins).
        break;
    }
    out
}

/// CAA record inspection (RFC 8659).
pub(super) async fn lookup_caa(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let domain = target.value.trim();
    if domain.is_empty() {
        return Ok(Vec::new());
    }
    let resolver = shared_resolver();

    let lookup = match resolver.lookup(domain, RecordType::CAA).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };

    let mut issuers: Vec<String> = Vec::new();
    let mut wildcards: Vec<String> = Vec::new();
    let mut iodefs: Vec<String> = Vec::new();

    for record in lookup.answers() {
        let RData::CAA(caa) = &record.data else {
            continue;
        };
        let value = String::from_utf8_lossy(&caa.value).into_owned();
        match caa.tag.to_ascii_lowercase().as_str() {
            "issue" => issuers.push(value),
            "issuewild" => wildcards.push(value),
            "iodef" => iodefs.push(value),
            _ => {}
        }
    }

    if issuers.is_empty() && wildcards.is_empty() && iodefs.is_empty() {
        return Ok(Vec::new());
    }

    let mut entity = Entity::new(
        EntityKind::Domain,
        domain,
        confidence::HIGH_PLUSPLUS_PLUS,
        &ctx.scan_id,
    );
    entity.tag("caa");
    let mut ev = Evidence::new(
        SRC,
        format!(
            "CAA policy published: {} issuer(s), {} wildcard issuer(s)",
            issuers.len(),
            wildcards.len()
        ),
    );
    if !issuers.is_empty() {
        ev = ev.with_attr("issue", issuers.join(","));
    }
    if !wildcards.is_empty() {
        ev = ev.with_attr("issuewild", wildcards.join(","));
    }
    if !iodefs.is_empty() {
        ev = ev.with_attr("iodef", iodefs.join(","));
    }
    entity.add_evidence(ev);

    // The `iodef` values (RFC 8659 §4.4) name WHERE certificate-issuance
    // violations for this domain should be reported — a `mailto:` address or an
    // `https://`/`http://` endpoint. That address is a real, published
    // security/abuse contact the domain operator controls; surface it as a
    // pivotable Email (and the reporting URL's host as a Domain lead) rather than
    // burying it in a joined-string attribute the recursion can't traverse.
    let mut out = vec![entity];
    for value in &iodefs {
        out.extend(iodef_entities(value, domain, &ctx.scan_id));
    }
    Ok(out)
}

/// Parse a CAA `iodef` property value into pivotable entities. `mailto:addr`
/// yields an Email (the domain's designated cert-violation-reporting contact);
/// an `http(s)://` value yields a Domain for the reporting endpoint's host (a
/// recursable lead — the raw URL itself is retained on the CAA entity's
/// evidence). Anything else (a bare URN, malformed value) yields nothing.
/// **Pure** — no I/O, independently unit-tested.
///
/// `pub(crate)` so the DoH resolver (`doh_resolver`) — the PRIMARY DNS transport
/// on Termux, where hickory's port-53 lookups are frequently blocked and this
/// module never runs — reuses the exact same iodef→entity mapping rather than
/// duplicating it, keeping CAA/iodef enumeration identical across both transports.
pub(crate) fn iodef_entities(value: &str, domain: &str, scan_id: &str) -> Vec<Entity> {
    let value = value.trim();
    if let Some(addr) = value.strip_prefix("mailto:") {
        let addr = addr.trim();
        // Minimal sanity: a single `@`, a dot in the domain part, no whitespace —
        // enough to reject a malformed value without duplicating a full validator.
        let looks_like_email = addr.split('@').count() == 2
            && !addr.chars().any(char::is_whitespace)
            && addr.rsplit('@').next().is_some_and(|d| d.contains('.'));
        if !looks_like_email {
            return Vec::new();
        }
        let mut e = Entity::new(EntityKind::Email, addr, confidence::VERY_HIGH, scan_id);
        e.tag("caa");
        e.tag("iodef");
        e.tag("security-contact");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("CAA iodef reporting contact for {domain} (RFC 8659)"),
            )
            .with_attr("iodef", value)
            .with_attr("role", "cert-issuance-violation-report"),
        );
        return vec![e];
    }
    if (value.starts_with("https://") || value.starts_with("http://"))
        && let Some(host) = crate::util::url_util::host_from_url(value)
        && host.contains('.')
        && host != domain
    {
        let mut d = Entity::new(EntityKind::Domain, &host, confidence::MEDIUM_PLUS, scan_id);
        d.tag("caa");
        d.tag("iodef");
        d.add_evidence(
            Evidence::new(
                SRC,
                format!("CAA iodef reporting endpoint host for {domain} (RFC 8659)"),
            )
            .with_attr("iodef", value)
            .with_attr("role", "cert-issuance-violation-report"),
        );
        return vec![d];
    }
    Vec::new()
}

/// PTR record lookup for IP → hostname mapping.
pub(super) async fn reverse_lookup(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    use std::net::IpAddr;

    let ip: IpAddr = match target.value.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(Vec::new()),
    };

    let resolver = shared_resolver();
    let lookup = match resolver.reverse_lookup(ip).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };

    let entities: Vec<Entity> = lookup
        .answers()
        .iter()
        .filter_map(|record| {
            let RData::PTR(ptr) = &record.data else {
                return None;
            };
            let host_raw = ptr.0.to_ascii();
            let host = host_raw.trim_end_matches('.');
            if host.is_empty() {
                return None;
            }
            let mut e = Entity::new(
                EntityKind::Domain,
                host,
                confidence::HIGH_PLUSPLUS_PLUS,
                &ctx.scan_id,
            );
            e.tag(crate::core::tags::PTR);
            e.add_evidence(
                Evidence::new(SRC, format!("PTR record for {ip}"))
                    .with_attr("record_type", "PTR")
                    .with_attr("ip", target.value.as_str())
                    .with_attr("ttl_secs", record.ttl.to_string()),
            );
            Some(e)
        })
        .collect();
    Ok(entities)
}

/// DNSBL reputation check against 8 blocklists.
pub(super) async fn blocklist_check(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    use super::constants::BLOCKLISTS;
    use super::helpers::reverse_ip;

    let ip = target.value.trim();
    if ip.is_empty() {
        return Ok(Vec::new());
    }

    let reversed = match reverse_ip(ip) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let resolver = shared_resolver();
    let mut listed_on: Vec<&str> = Vec::new();
    let mut checked = 0u32;

    for (zone, label) in BLOCKLISTS {
        if ctx.cancel.is_cancelled() {
            break;
        }
        let query = format!("{reversed}.{zone}");
        if resolver.lookup_ip(query.as_str()).await.is_ok() {
            listed_on.push(label);
        }
        checked += 1;
    }

    let mut entity = Entity::new(
        EntityKind::IpAddress,
        ip,
        confidence::VERY_HIGH_PLUS,
        &ctx.scan_id,
    );
    entity.tag("dnsbl-checked");

    if listed_on.is_empty() {
        entity.add_evidence(
            Evidence::new(SRC, format!("{ip} clean on {checked} blocklists"))
                .with_attr("listed_count", "0")
                .with_attr("checked_count", checked.to_string())
                .with_attr("status", "clean"),
        );
    } else {
        entity.tag("blocklisted");
        if listed_on.len() >= 3 {
            entity.tag("high-risk");
        }
        listed_on.sort_unstable();
        entity.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "{ip} listed on {} of {} blocklists",
                    listed_on.len(),
                    checked
                ),
            )
            .with_attr("listed_count", listed_on.len().to_string())
            .with_attr("checked_count", checked.to_string())
            .with_attr("listed_on", listed_on.join(", "))
            .with_attr("status", "listed"),
        );
    }

    Ok(vec![entity])
}
