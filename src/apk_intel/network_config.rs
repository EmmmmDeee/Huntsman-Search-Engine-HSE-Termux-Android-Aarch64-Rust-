//! Offline analysis of the exact compiled XML resource referenced by a manifest's
//! android:networkSecurityConfig attribute. All observations are declarations, not proof
//! of network behaviour, TLS validation, certificate ownership or app attribution.

use serde::Serialize;

use super::axml::{XmlNode, xml_nodes};

const MAX_RULES: usize = 128;
const MAX_ANCHORS: usize = 128;
const MAX_EXPIRATIONS: usize = 64;
pub const LIMITATIONS: &str = "Declared compiled Android network policy only. Missing values inherit platform/target-SDK defaults not inferred here. Debug overrides apply only to debuggable apps. Trust anchors, pin declarations and cleartext settings do not prove runtime network behaviour or certificate validation.";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DomainRule {
    pub domain: String,
    pub include_subdomains: Option<bool>,
    /// Explicit value on this domain-config or inherited from an ancestor/base-config.
    /// None means platform defaults apply; it is not equivalent to false.
    pub declared_cleartext_permitted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The configuration section that directly owns the trust-anchors element.
    pub scope: String,
    pub source: String,
    pub override_pins: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkPolicy {
    pub resource_id: u32,
    pub resource_path: String,
    pub base_cleartext_permitted: Option<bool>,
    pub domains: Vec<DomainRule>,
    pub domains_omitted: usize,
    pub trust_anchors: Vec<TrustAnchor>,
    pub trust_anchors_omitted: usize,
    pub debug_overrides_present: bool,
    pub pin_sets: usize,
    pub pin_count: usize,
    pub pin_expirations: Vec<String>,
    pub limitations: &'static str,
}

fn bool_attr(node: &XmlNode, name: &str) -> Option<bool> {
    node.attr(name).and_then(|value| value.parse::<bool>().ok())
}

fn ancestor<'a>(nodes: &'a [XmlNode], mut at: Option<usize>, wanted: &str) -> Option<&'a XmlNode> {
    while let Some(index) = at {
        let node = nodes.get(index)?;
        if node.name == wanted {
            return Some(node);
        }
        at = node.parent;
    }
    None
}

fn inherited_cleartext(
    nodes: &[XmlNode],
    mut at: Option<usize>,
    base: Option<bool>,
) -> Option<bool> {
    while let Some(index) = at {
        let node = nodes.get(index)?;
        if node.name == "domain-config" {
            if let Some(value) = bool_attr(node, "cleartextTrafficPermitted") {
                return Some(value);
            }
        }
        at = node.parent;
    }
    base
}

/// Parse a compiled network-security-config XML document from the exact ZIP member
/// resolved through the manifest reference and resources.arsc. No external requests.
///
/// # Errors
/// Refuses malformed XML or a document whose root is not network-security-config.
pub fn parse(data: &[u8], resource_id: u32, resource_path: &str) -> Result<NetworkPolicy, String> {
    let nodes = xml_nodes(data)?;
    if nodes.first().map(|node| node.name.as_str()) != Some("network-security-config")
        || nodes[0].parent.is_some()
    {
        return Err("resource is not a network-security-config document".to_owned());
    }
    let base = nodes
        .iter()
        .filter(|node| node.name == "base-config" && node.parent == Some(0))
        .find_map(|node| bool_attr(node, "cleartextTrafficPermitted"));
    let mut policy = NetworkPolicy {
        resource_id,
        resource_path: resource_path.to_owned(),
        base_cleartext_permitted: base,
        domains: Vec::new(),
        domains_omitted: 0,
        trust_anchors: Vec::new(),
        trust_anchors_omitted: 0,
        debug_overrides_present: false,
        pin_sets: 0,
        pin_count: 0,
        pin_expirations: Vec::new(),
        limitations: LIMITATIONS,
    };
    for node in nodes.iter().skip(1) {
        match node.name.as_str() {
            "debug-overrides" if node.parent == Some(0) => {
                policy.debug_overrides_present = true;
            }
            "domain" => {
                let Some(parent) = node.parent else { continue };
                if nodes[parent].name != "domain-config" {
                    continue;
                }
                let domain = node.text.trim();
                if domain.is_empty() || domain.len() > 253 {
                    continue;
                }
                if policy.domains.len() == MAX_RULES {
                    policy.domains_omitted += 1;
                    continue;
                }
                policy.domains.push(DomainRule {
                    domain: domain.to_owned(),
                    include_subdomains: bool_attr(node, "includeSubdomains"),
                    declared_cleartext_permitted: inherited_cleartext(&nodes, Some(parent), base),
                });
            }
            "certificates" => {
                let Some(parent) = node.parent else { continue };
                if nodes[parent].name != "trust-anchors" {
                    continue;
                }
                let Some(source) = node.attr("src") else {
                    continue;
                };
                let owner = nodes[parent].parent.and_then(|index| nodes.get(index));
                let scope = owner.map_or("unknown", |owner| owner.name.as_str());
                if policy.trust_anchors.len() == MAX_ANCHORS {
                    policy.trust_anchors_omitted += 1;
                    continue;
                }
                policy.trust_anchors.push(TrustAnchor {
                    scope: scope.to_owned(),
                    source: source.to_owned(),
                    override_pins: bool_attr(node, "overridePins"),
                });
            }
            "pin-set" if ancestor(&nodes, node.parent, "domain-config").is_some() => {
                policy.pin_sets = policy.pin_sets.saturating_add(1);
                if let Some(expiration) = node.attr("expiration") {
                    if policy.pin_expirations.len() < MAX_EXPIRATIONS {
                        policy.pin_expirations.push(expiration.to_owned());
                    }
                }
            }
            "pin" => {
                let Some(parent) = node.parent else { continue };
                if nodes[parent].name == "pin-set" {
                    policy.pin_count = policy.pin_count.saturating_add(1);
                }
            }
            _ => {}
        }
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apk_intel::axml::tests::{Axml, Val};

    fn sample() -> Vec<u8> {
        let mut xml = Axml::new(&[
            "cleartextTrafficPermitted",
            "includeSubdomains",
            "src",
            "overridePins",
            "expiration",
            "digest",
        ]);
        xml.start("network-security-config", &[])
            .start(
                "base-config",
                &[("cleartextTrafficPermitted", Val::Bool(false))],
            )
            .start("trust-anchors", &[])
            .start("certificates", &[("src", Val::Str("system"))])
            .end("certificates")
            .end("trust-anchors")
            .end("base-config")
            .start(
                "domain-config",
                &[("cleartextTrafficPermitted", Val::Bool(true))],
            )
            .start("domain", &[("includeSubdomains", Val::Bool(true))])
            .text("api.example.org")
            .end("domain")
            .start("domain-config", &[])
            .start("domain", &[])
            .text("internal.example.org")
            .end("domain")
            .start("pin-set", &[("expiration", Val::Str("2027-12-31"))])
            .start("pin", &[("digest", Val::Str("SHA-256"))])
            .text("AAAA")
            .end("pin")
            .end("pin-set")
            .end("domain-config")
            .end("domain-config")
            .start("debug-overrides", &[])
            .start("trust-anchors", &[])
            .start("certificates", &[("src", Val::Str("user"))])
            .end("certificates")
            .end("trust-anchors")
            .end("debug-overrides")
            .end("network-security-config");
        xml.build()
    }

    #[test]
    fn decodes_inherited_cleartext_and_scoped_anchors_without_runtime_claims() {
        let result = parse(&sample(), 0x7f0e_0002, "res/xml/policy.xml").unwrap();
        assert_eq!(result.base_cleartext_permitted, Some(false));
        assert_eq!(result.domains.len(), 2);
        assert_eq!(result.domains[0].domain, "api.example.org");
        assert_eq!(result.domains[0].include_subdomains, Some(true));
        assert_eq!(result.domains[0].declared_cleartext_permitted, Some(true));
        assert_eq!(result.domains[1].declared_cleartext_permitted, Some(true));
        assert_eq!(result.trust_anchors[0].scope, "base-config");
        assert_eq!(result.trust_anchors[1].scope, "debug-overrides");
        assert!(result.debug_overrides_present);
        assert_eq!(result.pin_sets, 1);
        assert_eq!(result.pin_count, 1);
        assert_eq!(result.pin_expirations, ["2027-12-31"]);
    }

    #[test]
    fn refuses_unrelated_or_truncated_compiled_xml() {
        let mut other = Axml::new(&[]);
        other.start("resources", &[]).end("resources");
        assert!(parse(&other.build(), 1, "res/xml/policy.xml").is_err());
        let bytes = sample();
        assert!(parse(&bytes[..bytes.len() - 1], 1, "res/xml/policy.xml").is_err());
        assert!(parse(b"<network-security-config/>", 1, "res/xml/policy.xml").is_err());
    }

    #[test]
    fn unspecified_values_remain_unknown_not_false() {
        let mut xml = Axml::new(&[]);
        xml.start("network-security-config", &[])
            .start("domain-config", &[])
            .start("domain", &[])
            .text("example.net")
            .end("domain")
            .end("domain-config")
            .end("network-security-config");
        let result = parse(&xml.build(), 2, "res/xml/net.xml").unwrap();
        assert_eq!(result.base_cleartext_permitted, None);
        assert_eq!(result.domains[0].declared_cleartext_permitted, None);
    }
}
