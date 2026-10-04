//! `RIPEstat` network-info routing provider.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::dependency::ModuleCategory;
use crate::http::{Request, Response, append_query_param};
use crate::module::{
    AccessClass, CachePolicy, CostModel, EscalationBand, HistoricalDepthClass, ProviderDescriptor,
    RateLimitPolicy, RecursiveUsePolicy,
};

use super::super::{
    IpCapability, IpObservation, IpObservationKind, IpProvider, IpProviderAction,
    IpProviderParseError, IpTarget,
};

const RIPESTAT_NETWORK_INFO_URL: &str = "https://stat.ripe.net/data/network-info/data.json";
const RIPESTAT_CAPABILITIES: &[IpCapability] = &[IpCapability::Routing];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RipeStatNetworkInfoProvider;

impl IpProvider for RipeStatNetworkInfoProvider {
    fn id(&self) -> &'static str {
        "ripestat_network_info"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            provider_id: "ripestat_network_info",
            module_id: "ripestat_network_info",
            source_class: ModuleCategory::Infrastructure,
            supported_seed_types: vec!["ip_address"],
            access_class: AccessClass::Keyless,
            escalation_band: EscalationBand::L1FreePublic,
            requires_key: false,
            recursive_use_policy: RecursiveUsePolicy::Unrestricted,
            cache_policy: CachePolicy::TtlSeconds(3_600),
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
        RIPESTAT_CAPABILITIES
    }

    fn lineage_family(&self) -> &'static str {
        "ripe-stat-network-info"
    }

    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction> {
        if !target.is_public() {
            return Vec::new();
        }
        let url = append_query_param(RIPESTAT_NETWORK_INFO_URL, "resource", &target.canonical());
        vec![IpProviderAction {
            action_id: format!("ripestat-network-info:{}", target.canonical()),
            capability: IpCapability::Routing,
            request: Request::get(url),
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
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| IpProviderParseError::Schema("missing RIPEstat status".into()))?;
        if status != "ok" {
            return Err(IpProviderParseError::Schema(format!(
                "unexpected RIPEstat status: {status}"
            )));
        }
        let data = value
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| IpProviderParseError::Schema("missing RIPEstat data object".into()))?;
        let prefix = data
            .get("prefix")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| IpProviderParseError::Schema("missing RIPEstat prefix".into()))?;

        let mut asns = Vec::new();
        if let Some(raw_asns) = data.get("asns") {
            let array = raw_asns.as_array().ok_or_else(|| {
                IpProviderParseError::Schema("RIPEstat asns is not an array".into())
            })?;
            for asn in array {
                asns.push(parse_asn(asn)?);
            }
        }

        let mut attributes = BTreeMap::new();
        attributes.insert("prefix".into(), prefix.into());
        if !asns.is_empty() {
            attributes.insert(
                "asns".into(),
                asns.iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }

        let summary = if asns.is_empty() {
            format!("routed prefix {prefix}")
        } else {
            format!(
                "routed prefix {prefix} via {}",
                asns.iter()
                    .map(|asn| format!("AS{asn}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        Ok(vec![IpObservation {
            id: action.action_id.clone(),
            provider_id: self.id().into(),
            source_family: action.lineage_family.clone(),
            kind: IpObservationKind::Routing,
            summary,
            attributes,
            observed_at_unix: None,
            retrieved_at_unix,
            raw_digest: None,
        }])
    }
}

fn parse_asn(value: &Value) -> Result<u64, IpProviderParseError> {
    let invalid = || IpProviderParseError::Schema("RIPEstat ASN is not an unsigned integer".into());
    match value {
        Value::Number(number) => number.as_u64().ok_or_else(invalid),
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            trimmed.parse::<u64>().map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
