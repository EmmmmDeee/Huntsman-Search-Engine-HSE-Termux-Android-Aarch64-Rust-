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

struct RankProvider {
    id: &'static str,
    capability: IpCapability,
    lineage: &'static str,
    reliability: f64,
    optionality: f64,
    historical: HistoricalDepthClass,
    access: AccessClass,
    escalation: EscalationBand,
    cost_model: CostModel,
    cost_per_request: Option<f64>,
}

impl IpProvider for RankProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            provider_id: self.id,
            module_id: self.id,
            source_class: ModuleCategory::Infrastructure,
            supported_seed_types: vec!["ip_address"],
            access_class: self.access,
            escalation_band: self.escalation,
            requires_key: self.access != AccessClass::Keyless,
            recursive_use_policy: RecursiveUsePolicy::Unrestricted,
            cache_policy: CachePolicy::Disabled,
            rate_limit_policy: RateLimitPolicy::None,
            cost_model: self.cost_model,
            cost_per_request: self.cost_per_request,
            quota_unit: None,
            historical_depth_class: self.historical,
            provenance_quality_prior: self.reliability,
            uniqueness_prior: 0.5,
            reliability_prior: self.reliability,
            optionality_prior: self.optionality,
        }
    }

    fn capabilities(&self) -> &'static [IpCapability] {
        match self.capability {
            IpCapability::Routing => &[IpCapability::Routing],
            IpCapability::HistoricalDns => &[IpCapability::HistoricalDns],
            IpCapability::Geolocation => &[IpCapability::Geolocation],
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
        let kind = match self.capability {
            IpCapability::Routing => {
                attributes.insert("prefix".into(), "1.1.1.0/24".into());
                attributes.insert("asns".into(), "13335".into());
                IpObservationKind::Routing
            }
            IpCapability::HistoricalDns => {
                attributes.insert("hostname".into(), "historical.example".into());
                IpObservationKind::HistoricalDns
            }
            IpCapability::Geolocation => {
                attributes.insert("country".into(), "AU".into());
                IpObservationKind::Geolocation
            }
            _ => unreachable!("test provider capability"),
        };
        Ok(vec![IpObservation {
            id: action.action_id.clone(),
            provider_id: self.id.into(),
            source_family: self.lineage.into(),
            kind,
            summary: self.id.into(),
            attributes,
            observed_at_unix: None,
            retrieved_at_unix,
            raw_digest: None,
        }])
    }
}

fn provider(
    id: &'static str,
    capability: IpCapability,
    lineage: &'static str,
) -> RankProvider {
    RankProvider {
        id,
        capability,
        lineage,
        reliability: 0.8,
        optionality: 0.5,
        historical: HistoricalDepthClass::Live,
        access: AccessClass::Keyless,
        escalation: EscalationBand::L1FreePublic,
        cost_model: CostModel::Free,
        cost_per_request: Some(0.0),
    }
}

fn run(providers: &[&dyn IpProvider]) -> huntsman_recon::ip::IpInvestigation {
    run_investigation(
        &OkTransport,
        IpTarget::parse("1.1.1.1").expect("target"),
        providers,
        IpMode::Deep,
        IpBudget {
            max_calls: 16,
            max_actions: 16,
            max_depth: 4,
        },
        1_000,
    )
}

fn executed_ids(result: &huntsman_recon::ip::IpInvestigation) -> Vec<&str> {
    result
        .actions_considered
        .iter()
        .filter(|action| action.executed)
        .map(|action| action.provider_id.as_str())
        .collect()
}

#[test]
fn independent_lineage_outranks_higher_reliability_duplicate_lineage_after_support() {
    let mut seed = provider("seed", IpCapability::Routing, "shared-root");
    seed.reliability = 1.0;
    let mut mirror = provider("mirror", IpCapability::Routing, "shared-root");
    mirror.reliability = 0.99;
    let mut independent = provider("independent", IpCapability::Routing, "independent-root");
    independent.reliability = 0.50;
    let providers: [&dyn IpProvider; 3] = [&mirror, &independent, &seed];

    let result = run(&providers);
    let executed = executed_ids(&result);

    assert_eq!(executed[0], "seed");
    assert_eq!(executed[1], "independent");
}

#[test]
fn deep_archive_wins_a_tie_for_historical_dns() {
    let live = provider("a-live", IpCapability::HistoricalDns, "live-root");
    let mut archive = provider("z-archive", IpCapability::HistoricalDns, "archive-root");
    archive.historical = HistoricalDepthClass::DeepArchive;
    let providers: [&dyn IpProvider; 2] = [&live, &archive];

    let result = run(&providers);

    assert_eq!(executed_ids(&result)[0], "z-archive");
}

#[test]
fn higher_optionality_breaks_an_otherwise_equal_tie() {
    let low = provider("a-low", IpCapability::Geolocation, "low-root");
    let mut high = provider("z-high", IpCapability::Geolocation, "high-root");
    high.optionality = 0.95;
    let providers: [&dyn IpProvider; 2] = [&low, &high];

    let result = run(&providers);

    assert_eq!(executed_ids(&result)[0], "z-high");
}

#[test]
fn lower_resource_burden_breaks_an_otherwise_equal_tie() {
    let mut paid = provider("a-paid", IpCapability::Geolocation, "paid-root");
    paid.access = AccessClass::Paid;
    paid.escalation = EscalationBand::L4Specialist;
    paid.cost_model = CostModel::Exact;
    paid.cost_per_request = Some(0.05);
    let free = provider("z-free", IpCapability::Geolocation, "free-root");
    let providers: [&dyn IpProvider; 2] = [&paid, &free];

    let result = run(&providers);

    assert_eq!(executed_ids(&result)[0], "z-free");
}
