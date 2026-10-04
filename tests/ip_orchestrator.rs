use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
use huntsman_recon::source_outcome::SourceOutcomeKind;

struct FakeTransport {
    script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    seen: RefCell<Vec<Request>>,
}

impl FakeTransport {
    fn successes(count: usize) -> Self {
        Self {
            script: RefCell::new(
                (0..count)
                    .map(|_| Ok(ok_response()))
                    .collect::<VecDeque<_>>(),
            ),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn scripted(script: Vec<Result<Response, TransportFailure>>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl Transport for FakeTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.script
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Ok(ok_response()))
    }
}

fn ok_response() -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: b"{}".to_vec(),
        truncated: false,
    }
}

#[derive(Clone, Copy)]
struct FakeProvider {
    id: &'static str,
    capability: IpCapability,
    lineage: &'static str,
    url: &'static str,
    reliability: f64,
}

impl IpProvider for FakeProvider {
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
            provenance_quality_prior: self.reliability,
            uniqueness_prior: self.reliability,
            reliability_prior: self.reliability,
            optionality_prior: 0.5,
        }
    }

    fn capabilities(&self) -> &'static [IpCapability] {
        match self.capability {
            IpCapability::Allocation => &[IpCapability::Allocation],
            IpCapability::Routing => &[IpCapability::Routing],
            IpCapability::ReverseDns => &[IpCapability::ReverseDns],
            IpCapability::HistoricalDns => &[IpCapability::HistoricalDns],
            IpCapability::Certificate => &[IpCapability::Certificate],
            IpCapability::Service => &[IpCapability::Service],
            IpCapability::Reputation => &[IpCapability::Reputation],
            IpCapability::Anonymization => &[IpCapability::Anonymization],
            IpCapability::Geolocation => &[IpCapability::Geolocation],
            IpCapability::InfrastructureClass => &[IpCapability::InfrastructureClass],
        }
    }

    fn lineage_family(&self) -> &'static str {
        self.lineage
    }

    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction> {
        vec![IpProviderAction {
            action_id: format!("{}:{}", self.id, target.canonical()),
            capability: self.capability,
            request: Request::get(self.url),
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
        match self.capability {
            IpCapability::Allocation => {
                attributes.insert("handle".into(), "NET-ONE".into());
            }
            IpCapability::Routing => {
                attributes.insert("prefix".into(), "1.1.1.0/24".into());
                attributes.insert("asns".into(), "13335".into());
            }
            IpCapability::ReverseDns => {
                attributes.insert("hostname".into(), "one.one.one.one".into());
            }
            IpCapability::Geolocation => {
                attributes.insert("country".into(), "AU".into());
            }
            _ => {}
        }
        Ok(vec![IpObservation {
            id: action.action_id.clone(),
            provider_id: self.id.into(),
            source_family: self.lineage.into(),
            kind: observation_kind(self.capability),
            summary: self.id.into(),
            attributes,
            observed_at_unix: None,
            retrieved_at_unix,
            raw_digest: None,
        }])
    }
}

const fn observation_kind(capability: IpCapability) -> IpObservationKind {
    match capability {
        IpCapability::Allocation => IpObservationKind::Allocation,
        IpCapability::Routing => IpObservationKind::Routing,
        IpCapability::ReverseDns => IpObservationKind::ReverseDns,
        IpCapability::HistoricalDns => IpObservationKind::HistoricalDns,
        IpCapability::Certificate => IpObservationKind::Certificate,
        IpCapability::Service => IpObservationKind::Service,
        IpCapability::Reputation => IpObservationKind::Reputation,
        IpCapability::Anonymization => IpObservationKind::Anonymization,
        IpCapability::Geolocation => IpObservationKind::Geolocation,
        IpCapability::InfrastructureClass => IpObservationKind::InfrastructureClass,
    }
}

fn provider(
    id: &'static str,
    capability: IpCapability,
    lineage: &'static str,
    url: &'static str,
    reliability: f64,
) -> FakeProvider {
    FakeProvider {
        id,
        capability,
        lineage,
        url,
        reliability,
    }
}

fn generous_budget() -> IpBudget {
    IpBudget {
        max_calls: 16,
        max_actions: 32,
        max_depth: 4,
    }
}

#[test]
fn base_mode_executes_all_available_mandatory_capabilities_within_budget() {
    let allocation = provider(
        "allocation",
        IpCapability::Allocation,
        "registry",
        "https://example.test/allocation",
        0.9,
    );
    let routing = provider(
        "routing",
        IpCapability::Routing,
        "routing",
        "https://example.test/routing",
        0.9,
    );
    let ptr = provider(
        "ptr",
        IpCapability::ReverseDns,
        "dns",
        "https://example.test/ptr",
        0.9,
    );
    let providers: [&dyn IpProvider; 3] = [&allocation, &routing, &ptr];
    let transport = FakeTransport::successes(3);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Base,
        generous_budget(),
        1_000,
    );

    let kinds = result
        .observations
        .iter()
        .map(|observation| observation.kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds,
        BTreeSet::from([
            IpObservationKind::Allocation,
            IpObservationKind::Routing,
            IpObservationKind::ReverseDns,
        ])
    );
    assert_eq!(transport.call_count(), 3);
    assert_eq!(result.budget_used.calls, 3);
}

#[test]
fn evidence_reorders_remaining_actions_toward_unresolved_capabilities() {
    let routing_best = provider(
        "routing-best",
        IpCapability::Routing,
        "routing-a",
        "https://example.test/routing-a",
        0.99,
    );
    let routing_second = provider(
        "routing-second",
        IpCapability::Routing,
        "routing-b",
        "https://example.test/routing-b",
        0.98,
    );
    let geo = provider(
        "geo",
        IpCapability::Geolocation,
        "geo-a",
        "https://example.test/geo",
        0.50,
    );
    let providers: [&dyn IpProvider; 3] = [&routing_second, &geo, &routing_best];
    let transport = FakeTransport::successes(3);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        generous_budget(),
        1_000,
    );

    let executed = result
        .actions_considered
        .iter()
        .filter(|action| action.executed)
        .map(|action| action.provider_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(executed[0], "routing-best");
    assert_eq!(executed[1], "geo");
}

#[test]
fn duplicate_upstream_target_action_is_suppressed() {
    let first = provider(
        "collector-a",
        IpCapability::Routing,
        "shared upstream",
        "https://example.test/same",
        0.9,
    );
    let second = provider(
        "collector-b",
        IpCapability::Routing,
        "  SHARED   UPSTREAM ",
        "https://example.test/same",
        0.8,
    );
    let providers: [&dyn IpProvider; 2] = [&first, &second];
    let transport = FakeTransport::successes(2);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        generous_budget(),
        1_000,
    );

    assert_eq!(transport.call_count(), 1);
    assert_eq!(
        result
            .actions_considered
            .iter()
            .filter(|action| action.executed)
            .count(),
        1
    );
}

#[test]
fn deep_mode_reaches_a_deterministic_fixed_point() {
    let routing = provider(
        "routing",
        IpCapability::Routing,
        "routing",
        "https://example.test/routing",
        0.9,
    );
    let providers: [&dyn IpProvider; 1] = [&routing];
    let transport = FakeTransport::successes(1);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        generous_budget(),
        1_000,
    );

    assert_eq!(transport.call_count(), 1);
    assert_eq!(result.termination_reason.as_deref(), Some("fixed_point"));
}

#[test]
fn call_budget_exhaustion_is_explicit_and_deterministic() {
    let routing = provider(
        "routing",
        IpCapability::Routing,
        "routing",
        "https://example.test/routing",
        0.9,
    );
    let geo = provider(
        "geo",
        IpCapability::Geolocation,
        "geo",
        "https://example.test/geo",
        0.8,
    );
    let providers: [&dyn IpProvider; 2] = [&routing, &geo];
    let transport = FakeTransport::successes(2);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        IpBudget {
            max_calls: 1,
            max_actions: 8,
            max_depth: 4,
        },
        1_000,
    );

    assert_eq!(transport.call_count(), 1);
    assert_eq!(result.budget_used.calls, 1);
    assert_eq!(result.termination_reason.as_deref(), Some("request_budget"));
}

#[test]
fn action_budget_exhaustion_is_explicit_and_deterministic() {
    let routing = provider(
        "routing",
        IpCapability::Routing,
        "routing",
        "https://example.test/routing",
        0.9,
    );
    let geo = provider(
        "geo",
        IpCapability::Geolocation,
        "geo",
        "https://example.test/geo",
        0.8,
    );
    let providers: [&dyn IpProvider; 2] = [&routing, &geo];
    let transport = FakeTransport::successes(2);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        IpBudget {
            max_calls: 8,
            max_actions: 1,
            max_depth: 4,
        },
        1_000,
    );

    assert_eq!(transport.call_count(), 1);
    assert_eq!(result.budget_used.actions, 1);
    assert_eq!(result.termination_reason.as_deref(), Some("action_budget"));
}

#[test]
fn provider_failure_does_not_stop_independent_remaining_actions() {
    let failing = provider(
        "failing",
        IpCapability::Routing,
        "routing-a",
        "https://example.test/failing",
        0.99,
    );
    let succeeding = provider(
        "succeeding",
        IpCapability::Geolocation,
        "geo-a",
        "https://example.test/succeeding",
        0.8,
    );
    let providers: [&dyn IpProvider; 2] = [&failing, &succeeding];
    let transport = FakeTransport::scripted(vec![
        Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "offline".into(),
            blocked: false,
        }),
        Ok(ok_response()),
    ]);

    let result = run_investigation(
        &transport,
        IpTarget::parse("1.1.1.1").expect("target"),
        &providers,
        IpMode::Deep,
        generous_budget(),
        1_000,
    );

    assert_eq!(transport.call_count(), 2);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.observations.len(), 1);
    assert_eq!(result.observations[0].provider_id, "succeeding");
}
