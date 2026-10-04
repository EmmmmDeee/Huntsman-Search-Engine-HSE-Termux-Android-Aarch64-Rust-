//! DNS-over-HTTPS PTR provider.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::Value;

use crate::dependency::ModuleCategory;
use crate::http::{Request, Response};
use crate::module::{
    AccessClass, CachePolicy, CostModel, EscalationBand, HistoricalDepthClass, ProviderDescriptor,
    RateLimitPolicy, RecursiveUsePolicy,
};

use super::super::{
    IpCapability, IpObservation, IpObservationKind, IpProvider, IpProviderAction,
    IpProviderParseError, IpTarget,
};

const CLOUDFLARE_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
const PTR_CAPABILITIES: &[IpCapability] = &[IpCapability::ReverseDns];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloudflarePtrProvider;

#[must_use]
pub fn reverse_dns_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(address) => {
            let hex = format!("{:032x}", u128::from(address));
            let reversed = hex
                .chars()
                .rev()
                .map(|nibble| nibble.to_string())
                .collect::<Vec<_>>()
                .join(".");
            format!("{reversed}.ip6.arpa")
        }
    }
}

impl IpProvider for CloudflarePtrProvider {
    fn id(&self) -> &'static str {
        "cloudflare_ptr"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            provider_id: "cloudflare_ptr",
            module_id: "cloudflare_ptr",
            source_class: ModuleCategory::Infrastructure,
            supported_seed_types: vec!["ip_address"],
            access_class: AccessClass::Keyless,
            escalation_band: EscalationBand::L1FreePublic,
            requires_key: false,
            recursive_use_policy: RecursiveUsePolicy::Unrestricted,
            cache_policy: CachePolicy::TtlSeconds(300),
            rate_limit_policy: RateLimitPolicy::SharedHostCircuitBreaker,
            cost_model: CostModel::Free,
            cost_per_request: Some(0.0),
            quota_unit: None,
            historical_depth_class: HistoricalDepthClass::Live,
            provenance_quality_prior: 0.8,
            uniqueness_prior: 0.7,
            reliability_prior: 0.9,
            optionality_prior: 0.8,
        }
    }

    fn capabilities(&self) -> &'static [IpCapability] {
        PTR_CAPABILITIES
    }

    fn lineage_family(&self) -> &'static str {
        "cloudflare-dns"
    }

    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction> {
        if !target.is_public() {
            return Vec::new();
        }
        let name = reverse_dns_name(target.address);
        let request = Request::get(format!("{CLOUDFLARE_DOH_URL}?name={name}&type=PTR"))
            .header("Accept", "application/dns-json");
        vec![IpProviderAction {
            action_id: format!("cloudflare-ptr:{}", target.canonical()),
            capability: IpCapability::ReverseDns,
            request,
            lineage_family: self.lineage_family().into(),
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
        let status = value
            .get("Status")
            .and_then(Value::as_u64)
            .ok_or_else(|| IpProviderParseError::Schema("missing DNS Status".into()))?;
        if status != 0 {
            return Ok(Vec::new());
        }

        let Some(answer_value) = value.get("Answer") else {
            return Ok(Vec::new());
        };
        let answers = answer_value
            .as_array()
            .ok_or_else(|| IpProviderParseError::Schema("DNS Answer is not an array".into()))?;

        let mut observations = Vec::new();
        for (index, answer) in answers.iter().enumerate() {
            let rr_type = answer.get("type").and_then(Value::as_u64).ok_or_else(|| {
                IpProviderParseError::Schema("DNS answer is missing numeric type".into())
            })?;
            if rr_type != 12 {
                continue;
            }
            let hostname = answer
                .get("data")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(|value| value.trim_end_matches('.'))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| IpProviderParseError::Schema("PTR answer has no hostname".into()))?;
            let ttl = answer
                .get("TTL")
                .and_then(Value::as_u64)
                .ok_or_else(|| IpProviderParseError::Schema("PTR answer has no numeric TTL".into()))?;

            let mut attributes = BTreeMap::new();
            attributes.insert("ttl".into(), ttl.to_string());
            if let Some(name) = answer
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                attributes.insert("query_name".into(), name.trim_end_matches('.').into());
            }

            observations.push(IpObservation {
                id: format!("{}:{index}", action.action_id),
                provider_id: self.id().into(),
                source_family: action.lineage_family.clone(),
                kind: IpObservationKind::ReverseDns,
                summary: hostname.into(),
                attributes,
                observed_at_unix: None,
                retrieved_at_unix,
                raw_digest: None,
            });
        }

        Ok(observations)
    }
}
