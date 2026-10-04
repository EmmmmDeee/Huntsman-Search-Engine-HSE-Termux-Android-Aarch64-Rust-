use std::collections::BTreeMap;

use huntsman_recon::dependency::ModuleCategory;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip::orchestrator::{IpBudget, IpMode, run_investigation};
use huntsman_recon::ip::{
    IpCapability, IpObservation, IpObservationKind, IpProvider, IpProviderAction,
    IpProviderParseError, IpTarget,
};
use huntsman_recon::module::{
    AccessClass, CachePolicy, CostModel, EscalationBand, HistoricalDepthClass, ProviderDescriptor,
    RateLimitPolicy, RecursiveUsePolicy,
};

#[derive(Default)]
struct OkTransport;

impl Transport for OkTransport {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
            truncated: false,
        })
    }
}

struct Provider {
    id: &'static str,
    capability: IpCapability,
    kind: IpObservationKind,
    lineage: &'static str,
}

impl IpProvider for Provider {
    fn id(&self) -> &'static str {
        self.id
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            provider_id: self.id,
            module_id: self.id,
            source_class: ModuleCategory::Infrastructure,
            supported_seed_types: vec!["ip_address"],
            access_class: AccessClass::Keyless,
            escalation_band: EscalationBand::L1FreePublic,
            requires_key: false,
            recursive_use_policy: RecursiveUsePolicy::Unrestricted,
            cache_policy: CachePolicy::Disabled,
            rate_limit_policy: RateLimitPolicy::None,
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
        match self.capability {
            IpCapability::ReverseDns => &[IpCapability::ReverseDns],
            IpCapability::Certificate => &[IpCapability::Certificate],
            _ => &[],
        }
    }

    fn lineage_family(&self) -> &'static str {
        self.lineage
    }

    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction> {
        vec![IpProviderAction {
            action_id: format!("{}:{}", self.id, target.canonical()),
            capability: self.capability,
            request: Request::get(format!("https://example.test/{}", self.id)),
            lineage_family: self.lineage.into(),
        }]
    }

    fn parse(
        &self,
        action: &IpProviderAction,
        _response: &Response,
        retrieved_at_unix: u64,
    ) -> Result<Vec<IpObservation>, IpProviderParseError> {
        let mut attributes = BTreeMap::new();
        if self.kind == IpObservationKind::ReverseDns {
            attributes.insert("hostname".into(), "host.example".into());
        }
        Ok(vec![IpObservation {
            id: action.action_id.clone(),
            provider_id: self.id.into(),
            source_family: self.lineage.into(),
            kind: self.kind,
            summary: self.id.into(),
            attributes,
            observed_at_unix: None,
            retrieved_at_unix,
            raw_digest: None,
        }])
    }
}

#[test]
fn deep_pivot_blocked_by_depth_is_not_mislabeled_fixed_point() {
    let ptr = Provider {
        id: "ptr",
        capability: IpCapability::ReverseDns,
        kind: IpObservationKind::ReverseDns,
        lineage: "dns-ptr-authoritative",
    };
    let certificate = Provider {
        id: "certificate",
        capability: IpCapability::Certificate,
        kind: IpObservationKind::Certificate,
        lineage: "certificate-transparency",
    };
    let providers: [&dyn IpProvider; 2] = [&certificate, &ptr];

    let result = run_investigation(
        &OkTransport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        IpBudget {
            max_calls: 8,
            max_actions: 8,
            max_depth: 0,
        },
        1_000,
    );

    assert_eq!(result.budget_used.calls, 1);
    assert_eq!(result.budget_used.max_depth_reached, 0);
    assert_eq!(result.termination_reason.as_deref(), Some("max_depth"));
}
