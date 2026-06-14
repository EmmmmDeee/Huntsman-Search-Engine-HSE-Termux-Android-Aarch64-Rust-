use hickory_resolver::proto::rr::{RData, RecordType};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleContext,
    scan::Target,
};
use crate::util::dns::shared_resolver;

use super::SRC;
use super::helpers::{dmarc_report_addresses, soa_rname_to_email, verification_vendor};

/// A / AAAA / MX / NS / SOA / TXT — run concurrently via `tokio::join!`.
pub(super) async fn resolve_records(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let resolver = shared_resolver();
    let domain = target.value.as_str();
    let mut entities: Vec<Entity> = Vec::new();

    let (ips, mxs, nss, soa, txts) = tokio::join!(
        resolver.lookup_ip(domain),
        resolver.mx_lookup(domain),
        resolver.ns_lookup(domain),
        resolver.soa_lookup(domain),
        resolver.txt_lookup(domain),
    );

    // A + AAAA
    if let Ok(lookup) = ips {
        entities.extend(lookup.as_lookup().answers().iter().filter_map(|record| {
            let (ip_str, record_type, ip_version) = match &record.data {
                RData::A(a) => (a.0.to_string(), "A", "4"),
                RData::AAAA(aaaa) => (aaaa.0.to_string(), "AAAA", "6"),
                _ => return None,
            };
            let mut e = Entity::new(EntityKind::IpAddress, &ip_str, 0.95, &ctx.scan_id);
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
            let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
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
            let mut e = Entity::new(EntityKind::Domain, &host, 0.88, &ctx.scan_id);
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

        // Emit the admin contact as a discrete Email entity when present.
        if admin_email.contains('@') {
            let mut em = Entity::new(EntityKind::Email, &admin_email, 0.70, &ctx.scan_id);
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
            let mut dmarc_emails: Vec<Entity> = Vec::new();
            let mut dom = Entity::new(EntityKind::Domain, domain, 0.90, &ctx.scan_id);
            for t in &txts {
                let t = t.trim_matches('"');
                let b = t.as_bytes();
                if crate::util::spf::is_spf(t) {
                    dom.tag("spf");
                    for member in crate::util::spf::members(t) {
                        match member {
                            crate::util::spf::Member::Ip(ip) => {
                                let mut ie =
                                    Entity::new(EntityKind::IpAddress, ip, 0.75, &ctx.scan_id);
                                ie.tag("dns");
                                ie.tag("spf");
                                ie.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF authorised sender for {domain}"),
                                ));
                                entities.push(ie);
                            }
                            crate::util::spf::Member::Include(inc) => {
                                let mut de =
                                    Entity::new(EntityKind::Domain, inc, 0.65, &ctx.scan_id);
                                de.tag("dns");
                                de.tag("spf-include");
                                de.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF include for {domain}"),
                                ));
                                entities.push(de);
                            }
                            crate::util::spf::Member::Redirect(red) => {
                                let mut de =
                                    Entity::new(EntityKind::Domain, red, 0.65, &ctx.scan_id);
                                de.tag("dns");
                                de.tag("spf-redirect");
                                de.add_evidence(Evidence::new(
                                    SRC,
                                    format!("SPF redirect for {domain}"),
                                ));
                                entities.push(de);
                            }
                        }
                    }
                } else if b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"v=dkim1") {
                    dom.tag("dkim");
                } else if b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"v=dmarc1") {
                    dom.tag("dmarc");
                    let txt = String::from_utf8_lossy(b);
                    for email in dmarc_report_addresses(&txt) {
                        let mut ee = Entity::new(EntityKind::Email, email, 0.72, &ctx.scan_id);
                        ee.tag("dmarc-report");
                        ee.tag("dns");
                        ee.add_evidence(
                            Evidence::new(SRC, format!("DMARC report address for {domain}"))
                                .with_attr("record_type", "DMARC"),
                        );
                        dmarc_emails.push(ee);
                    }
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
            entities.extend(dmarc_emails);
        }
    }

    Ok(entities)
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

    let mut entity = Entity::new(EntityKind::Domain, domain, 0.85, &ctx.scan_id);
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

    Ok(vec![entity])
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
            let mut e = Entity::new(EntityKind::Domain, host, 0.85, &ctx.scan_id);
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

    let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, &ctx.scan_id);
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
