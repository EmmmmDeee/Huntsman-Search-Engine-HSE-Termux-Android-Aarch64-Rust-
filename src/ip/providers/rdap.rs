//! IANA-bootstrapped RDAP allocation provider.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::Value;

use crate::dependency::ModuleCategory;
use crate::http::{Request, Response, parse_http_uri};
use crate::module::{
    AccessClass, CachePolicy, CostModel, EscalationBand, HistoricalDepthClass, ProviderDescriptor,
    RateLimitPolicy, RecursiveUsePolicy,
};
use crate::timefmt::parse_timestamp;

use super::super::{
    IpCapability, IpObservation, IpObservationKind, IpProvider, IpProviderAction,
    IpProviderParseError, IpTarget,
};

pub const IANA_RDAP_IPV4_BOOTSTRAP: &str = "https://data.iana.org/rdap/ipv4.json";
pub const IANA_RDAP_IPV6_BOOTSTRAP: &str = "https://data.iana.org/rdap/ipv6.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkPrefix {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl NetworkPrefix {
    fn parse(raw: &str) -> Result<Self, IpProviderParseError> {
        let Some((address, prefix)) = raw.trim().split_once('/') else {
            return Err(IpProviderParseError::Schema(format!(
                "RDAP bootstrap prefix has no length: {raw}"
            )));
        };
        let address = address.parse::<IpAddr>().map_err(|_| {
            IpProviderParseError::Schema(format!("invalid RDAP bootstrap prefix: {raw}"))
        })?;
        let prefix = prefix.parse::<u8>().map_err(|_| {
            IpProviderParseError::Schema(format!("invalid RDAP bootstrap prefix length: {raw}"))
        })?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = mask_v4(prefix);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = mask_v6(prefix);
                Ok(Self::V6 {
                    network: u128::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V4(_) => Err(IpProviderParseError::Schema(format!(
                "IPv4 prefix length exceeds 32: {raw}"
            ))),
            IpAddr::V6(_) => Err(IpProviderParseError::Schema(format!(
                "IPv6 prefix length exceeds 128: {raw}"
            ))),
        }
    }

    const fn prefix_len(self) -> u8 {
        match self {
            Self::V4 { prefix, .. } | Self::V6 { prefix, .. } => prefix,
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                u32::from(address) & mask_v4(prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                u128::from(address) & mask_v6(prefix) == network
            }
            _ => false,
        }
    }
}

const fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapRoute {
    network: NetworkPrefix,
    base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdapBootstrap {
    routes: Vec<BootstrapRoute>,
}

impl RdapBootstrap {
    /// Parse an IANA RDAP bootstrap document into a longest-prefix-match table.
    pub fn parse(body: &[u8]) -> Result<Self, IpProviderParseError> {
        let value: Value = serde_json::from_slice(body)
            .map_err(|error| IpProviderParseError::Parse(error.to_string()))?;
        let services = value
            .get("services")
            .and_then(Value::as_array)
            .ok_or_else(|| IpProviderParseError::Schema("missing services array".into()))?;
        if services.is_empty() {
            return Err(IpProviderParseError::Schema(
                "RDAP bootstrap services array is empty".into(),
            ));
        }

        let mut routes = Vec::new();
        for service in services {
            let pair = service.as_array().ok_or_else(|| {
                IpProviderParseError::Schema("RDAP bootstrap service is not an array".into())
            })?;
            if pair.len() != 2 {
                return Err(IpProviderParseError::Schema(
                    "RDAP bootstrap service must contain prefixes and URLs".into(),
                ));
            }
            let prefixes = pair[0].as_array().ok_or_else(|| {
                IpProviderParseError::Schema("RDAP bootstrap prefixes are not an array".into())
            })?;
            let urls = pair[1].as_array().ok_or_else(|| {
                IpProviderParseError::Schema("RDAP bootstrap URLs are not an array".into())
            })?;
            let base_url = urls
                .iter()
                .filter_map(Value::as_str)
                .find(|url| url.starts_with("https://"))
                .ok_or_else(|| {
                    IpProviderParseError::Schema(
                        "RDAP bootstrap service has no HTTPS endpoint".into(),
                    )
                })?;
            for prefix in prefixes {
                let raw = prefix.as_str().ok_or_else(|| {
                    IpProviderParseError::Schema("RDAP bootstrap prefix is not a string".into())
                })?;
                routes.push(BootstrapRoute {
                    network: NetworkPrefix::parse(raw)?,
                    base_url: normalise_base_url(base_url),
                });
            }
        }
        if routes.is_empty() {
            return Err(IpProviderParseError::Schema(
                "RDAP bootstrap contains no usable routes".into(),
            ));
        }
        Ok(Self { routes })
    }

    #[must_use]
    pub fn base_url_for(&self, address: IpAddr) -> Option<&str> {
        self.routes
            .iter()
            .filter(|route| route.network.contains(address))
            .max_by_key(|route| route.network.prefix_len())
            .map(|route| route.base_url.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdapProvider {
    base_url: String,
    lineage_family: String,
}

impl RdapProvider {
    pub fn new(base_url: &str) -> Result<Self, IpProviderParseError> {
        let canonical = normalise_base_url(base_url);
        let uri = parse_http_uri(&canonical)
            .map_err(|error| IpProviderParseError::Schema(error.to_string()))?;
        if uri.scheme_str() != Some("https") {
            return Err(IpProviderParseError::Schema(
                "RDAP endpoint must use HTTPS".into(),
            ));
        }
        let lineage_family = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| IpProviderParseError::Schema("RDAP endpoint has no host".into()))?
            .to_ascii_lowercase();
        Ok(Self {
            base_url: canonical,
            lineage_family,
        })
    }
}

fn normalise_base_url(base_url: &str) -> String {
    format!("{}/", base_url.trim().trim_end_matches('/'))
}

const RDAP_CAPABILITIES: &[IpCapability] = &[IpCapability::Allocation];

impl IpProvider for RdapProvider {
    fn id(&self) -> &'static str {
        "rdap"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            provider_id: "rdap",
            module_id: "rdap",
            source_class: ModuleCategory::Infrastructure,
            supported_seed_types: vec!["ip_address"],
            access_class: AccessClass::Keyless,
            escalation_band: EscalationBand::L1FreePublic,
            requires_key: false,
            recursive_use_policy: RecursiveUsePolicy::Unrestricted,
            cache_policy: CachePolicy::TtlSeconds(86_400),
            rate_limit_policy: RateLimitPolicy::SharedHostCircuitBreaker,
            cost_model: CostModel::Free,
            cost_per_request: Some(0.0),
            quota_unit: None,
            historical_depth_class: HistoricalDepthClass::Live,
            provenance_quality_prior: 0.9,
            uniqueness_prior: 0.9,
            reliability_prior: 0.9,
            optionality_prior: 0.8,
        }
    }

    fn capabilities(&self) -> &'static [IpCapability] {
        RDAP_CAPABILITIES
    }

    fn lineage_family(&self) -> &'static str {
        "rir-rdap"
    }

    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction> {
        if !target.is_public() {
            return Vec::new();
        }
        vec![IpProviderAction {
            action_id: format!("rdap:{}", target.canonical()),
            capability: IpCapability::Allocation,
            request: Request::get(format!("{}ip/{}", self.base_url, target.canonical())),
            lineage_family: self.lineage_family.clone(),
        }]
    }

    fn parse(
        &self,
        action: &IpProviderAction,
        response: &Response,
        retrieved_at_unix: u64,
    ) -> Result<Vec<IpObservation>, IpProviderParseError> {
        let value: Value = serde_json::from_slice(&response.body)
            .map_err(|error| IpProviderParseError::Parse(error.to_string()))?;
        let object_class = value
            .get("objectClassName")
            .and_then(Value::as_str)
            .ok_or_else(|| IpProviderParseError::Schema("missing objectClassName".into()))?;
        if !object_class.eq_ignore_ascii_case("ip network") {
            return Err(IpProviderParseError::Schema(format!(
                "expected RDAP ip network object, got {object_class}"
            )));
        }

        let mut attributes = BTreeMap::new();
        copy_string(&value, "handle", "handle", &mut attributes);
        copy_string(&value, "startAddress", "start_address", &mut attributes);
        copy_string(&value, "endAddress", "end_address", &mut attributes);
        copy_string(&value, "ipVersion", "ip_version", &mut attributes);
        copy_string(&value, "name", "name", &mut attributes);
        copy_string(&value, "type", "type", &mut attributes);
        copy_string(&value, "country", "country", &mut attributes);
        copy_string(&value, "parentHandle", "parent_handle", &mut attributes);

        let events = event_strings(&value);
        if !events.is_empty() {
            attributes.insert("events".into(), events.join("; "));
        }
        let entities = entity_strings(&value);
        if !entities.is_empty() {
            attributes.insert("entities".into(), entities.join("; "));
        }
        let notices = notice_strings(&value);
        if !notices.is_empty() {
            attributes.insert("notices".into(), notices.join("; "));
        }

        let observed_at_unix = value
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|event| event.get("eventDate").and_then(Value::as_str))
            .filter_map(parse_timestamp)
            .filter_map(|timestamp| u64::try_from(timestamp).ok())
            .max();

        let summary = attributes
            .get("name")
            .or_else(|| attributes.get("handle"))
            .cloned()
            .or_else(|| {
                Some(format!(
                    "{} - {}",
                    attributes.get("start_address")?,
                    attributes.get("end_address")?
                ))
            })
            .unwrap_or_else(|| "RDAP IP allocation".into());

        Ok(vec![IpObservation {
            id: action.action_id.clone(),
            provider_id: self.id().into(),
            source_family: action.lineage_family.clone(),
            kind: IpObservationKind::Allocation,
            summary,
            attributes,
            observed_at_unix,
            retrieved_at_unix,
            raw_digest: None,
        }])
    }
}

fn copy_string(value: &Value, source: &str, target: &str, attributes: &mut BTreeMap<String, String>) {
    if let Some(text) = value
        .get(source)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        attributes.insert(target.into(), text.into());
    }
}

fn event_strings(value: &Value) -> Vec<String> {
    value
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| {
            let action = event.get("eventAction")?.as_str()?.trim();
            let date = event.get("eventDate")?.as_str()?.trim();
            (!action.is_empty() && !date.is_empty()).then(|| format!("{action}={date}"))
        })
        .collect()
}

fn entity_strings(value: &Value) -> Vec<String> {
    value
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entity| {
            let handle = entity.get("handle")?.as_str()?.trim();
            if handle.is_empty() {
                return None;
            }
            let roles: Vec<&str> = entity
                .get("roles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect();
            if roles.is_empty() {
                Some(handle.to_owned())
            } else {
                Some(format!("{handle} [{}]", roles.join(", ")))
            }
        })
        .collect()
}

fn notice_strings(value: &Value) -> Vec<String> {
    value
        .get("notices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|notice| {
            let title = notice.get("title").and_then(Value::as_str).unwrap_or("").trim();
            let descriptions: Vec<&str> = notice
                .get("description")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|description| !description.is_empty())
                .collect();
            match (title.is_empty(), descriptions.is_empty()) {
                (true, true) => None,
                (false, true) => Some(title.to_owned()),
                (true, false) => Some(descriptions.join(" | ")),
                (false, false) => Some(format!("{title}: {}", descriptions.join(" | "))),
            }
        })
        .collect()
}
