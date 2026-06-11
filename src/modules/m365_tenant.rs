//! Microsoft 365 / Entra ID (Azure AD) tenant-discovery module.
//!
//! Probes two unauthenticated Microsoft endpoints for a target domain:
//!
//!  1. **OpenID Connect discovery** — `login.microsoftonline.com/{domain}/.well-known/openid-configuration`
//!     Successful response means the domain has an active Entra ID / M365 tenant;
//!     the JSON body contains the tenant UUID in the `issuer` field and a
//!     `cloud_instance_name` that discloses the cloud region.
//!
//!  2. **UserRealm probe** — `login.microsoftonline.com/getuserrealm.srf?login=probe@{domain}&xml=1`
//!     Returns whether the tenant is `Managed` (Azure AD-native) or `Federated`
//!     (on-premises IdP bridged via ADFS / another SSO provider), and the
//!     federation provider brand name when federated.
//!
//! Emits an `Organisation` entity tagged with the tenant UUID and cloud region
//! (confidence 0.92 — the OIDC endpoint only resolves for genuine tenants).
//!
//! Technique: T1590.001 (Gather Victim Network Information: Domain Properties) —
//! tenant UUIDs expose cloud-infrastructure provider and region relationships.
//!
//! Free, no API key required. Pure HTTPS (rustls). No auth whatsoever.

use async_trait::async_trait;
use std::sync::OnceLock;

use regex::Regex;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::curl;

const SRC: &str = "m365_tenant";

pub struct M365Tenant;

#[async_trait]
impl Module for M365Tenant {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Discover Microsoft 365 / Entra ID tenant UUID and cloud region via OIDC probe"
    }

    fn priority(&self) -> u8 {
        88
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Email)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1590.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some(domain) = domain_for_target(target) else {
            return Ok(result);
        };

        let oidc_url = format!(
            "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
            domain
        );
        let body = match ctx
            .http
            .get(&oidc_url)
            .header(reqwest::header::USER_AGENT, curl::UA_DESKTOP)
            .timeout(std::time::Duration::from_millis(7_000))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r.text().await {
                Ok(b) if b.contains("tenant") => b,
                _ => return Ok(result),
            },
            _ => return Ok(result),
        };

        let Some(tenant_guid) = extract_tenant_guid(&body) else {
            return Ok(result);
        };

        let cloud_instance = extract_cloud_instance(&body);
        let region_code = cloud_instance.as_deref().unwrap_or("microsoftonline.com");
        let region_label = region_display(region_code);

        // UserRealm probe: Managed vs Federated
        let realm_url = format!(
            "https://login.microsoftonline.com/getuserrealm.srf?login=probe@{}&xml=1",
            domain
        );
        let (ns_type, federation_brand) = match ctx
            .http
            .get(&realm_url)
            .header(reqwest::header::USER_AGENT, curl::UA_DESKTOP)
            .timeout(std::time::Duration::from_millis(5_000))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let text = r.text().await.unwrap_or_default();
                let ns = extract_xml_tag(&text, "NameSpaceType").unwrap_or_default();
                let brand = extract_xml_tag(&text, "AuthURL")
                    .or_else(|| extract_xml_tag(&text, "FederationBrandName"));
                (ns, brand)
            }
            _ => (String::new(), None),
        };

        let org_label = format!("{} (M365 tenant)", domain);
        let mut e = Entity::new(EntityKind::Organisation, &org_label, 0.92, &ctx.scan_id);
        e.tag("m365");
        e.tag("cloud-infrastructure");
        e.tag(format!("m365-tenant:{}", tenant_guid));
        e.tag(format!("m365-region:{}", region_code));
        if !ns_type.is_empty() {
            e.tag(format!("m365-ns:{}", ns_type.to_lowercase()));
        }

        let mut ev = Evidence::new(
            SRC,
            format!("M365 tenant {} on domain {}", tenant_guid, domain),
        )
        .with_attr("tenant_guid", &tenant_guid)
        .with_attr("domain", &domain)
        .with_attr("region_code", region_code)
        .with_attr("region_label", region_label)
        .with_attr("source_url", &oidc_url);
        if !ns_type.is_empty() {
            ev = ev.with_attr("namespace_type", &ns_type);
        }
        if let Some(brand) = &federation_brand {
            ev = ev.with_attr("federation_brand", brand);
        }
        e.add_evidence(ev);
        result.push(e);

        Ok(result)
    }
}

fn domain_for_target(t: &Target) -> Option<String> {
    match t.kind {
        TargetKind::Email => t.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        TargetKind::Domain => Some(t.value.trim().to_lowercase()),
        _ => None,
    }
}

/// Extract the tenant UUID from the OIDC discovery JSON body.
///
/// The issuer field takes the form `"https://sts.windows.net/{uuid}/"` or
/// `"https://login.microsoftonline.com/{uuid}/v2.0"`. Either way the UUID
/// is a 36-char hex-plus-hyphens string.
fn extract_tenant_guid(body: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?:microsoftonline\.com|sts\.windows\.net)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/",
        )
        .unwrap()
    });
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_lowercase())
}

/// Extract the `cloud_instance_name` JSON field from the OIDC body.
fn extract_cloud_instance(body: &str) -> Option<String> {
    // JSON: "cloud_instance_name":"microsoftonline.com"
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#""cloud_instance_name"\s*:\s*"([^"]+)""#).unwrap());
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract a simple `<TagName>value</TagName>` from UserRealm XML.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let val = xml[start..end].trim().to_string();
    if val.is_empty() { None } else { Some(val) }
}

/// Map a `cloud_instance_name` value to a human-readable region label.
fn region_display(code: &str) -> &'static str {
    match code {
        "microsoftonline.com" => "Global",
        "microsoftonline.us" => "US Government",
        "chinacloudapi.cn" => "China",
        "microsoftonline.de" => "Germany (Legacy)",
        _ => "Global",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tenant_guid_from_sts_issuer() {
        let body = r#"{"issuer":"https://sts.windows.net/12345678-1234-1234-1234-123456789abc/","token_endpoint":"..."}"#;
        assert_eq!(
            extract_tenant_guid(body),
            Some("12345678-1234-1234-1234-123456789abc".to_string())
        );
    }

    #[test]
    fn extract_tenant_guid_from_microsoftonline_issuer() {
        let body = r#"{"issuer":"https://login.microsoftonline.com/abcdef12-abcd-abcd-abcd-abcdef123456/v2.0"}"#;
        assert_eq!(
            extract_tenant_guid(body),
            Some("abcdef12-abcd-abcd-abcd-abcdef123456".to_string())
        );
    }

    #[test]
    fn extract_tenant_guid_none_for_garbage() {
        assert_eq!(extract_tenant_guid("no uuid here"), None);
    }

    #[test]
    fn region_display_maps_correctly() {
        assert_eq!(region_display("microsoftonline.com"), "Global");
        assert_eq!(region_display("microsoftonline.us"), "US Government");
        assert_eq!(region_display("chinacloudapi.cn"), "China");
        assert_eq!(region_display("microsoftonline.de"), "Germany (Legacy)");
        assert_eq!(region_display("unknown.example"), "Global");
    }

    #[test]
    fn extract_cloud_instance_parses_json() {
        let body = r#"{"cloud_instance_name":"microsoftonline.us","token_endpoint":"..."}"#;
        assert_eq!(
            extract_cloud_instance(body),
            Some("microsoftonline.us".to_string())
        );
    }

    #[test]
    fn extract_xml_tag_parses_realm_response() {
        let xml = r#"<RealmInfo><NameSpaceType>Managed</NameSpaceType><DomainName>example.com</DomainName></RealmInfo>"#;
        assert_eq!(
            extract_xml_tag(xml, "NameSpaceType"),
            Some("Managed".to_string())
        );
        assert_eq!(
            extract_xml_tag(xml, "DomainName"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_xml_tag(xml, "Missing"), None);
    }
}
