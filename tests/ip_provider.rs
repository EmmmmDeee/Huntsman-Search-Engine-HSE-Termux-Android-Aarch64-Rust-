use std::cell::RefCell;
use std::collections::BTreeMap;

use huntsman_recon::dependency::ModuleCategory;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::ip::{
    IpCapability, IpFailureKind, IpObservation, IpObservationKind, IpProvider, IpProviderAction,
    IpProviderParseError, IpTarget, execute_provider_action,
};
use huntsman_recon::module::{
    AccessClass, CachePolicy, CostModel, EscalationBand, HistoricalDepthClass, ProviderDescriptor,
    RateLimitPolicy, RecursiveUsePolicy,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

struct StubProvider;

impl IpProvider for StubProvider {
    fn id(&self) -> &'static str {
        "collector_x"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            provider_id: "collector_x",
            module_id: "collector_x",
            source_class: ModuleCategory::Infrastructure,
            supported_seed_types: vec!["ip_address"],
            access_class: AccessClass::Keyless,
            escalation_band: EscalationBand::L1FreePublic,
            requires_key: false,
            recursive_use_policy: RecursiveUsePolicy::Unrestricted,
            cache_policy: CachePolicy::Disabled,
            rate_limit_policy: RateLimitPolicy::SharedHostCircuitBreaker,
            cost_model: CostModel::Free,
            cost_per_request: Some(0.0),
            quota_unit: None,
            historical_depth_class: HistoricalDepthClass::Live,
            provenance_quality_prior: 0.8,
            uniqueness_prior: 0.8,
            reliability_prior: 0.8,
            optionality_prior: 0.5,
        }
    }

    fn capabilities(&self) -> &'static [IpCapability] {
        &[IpCapability::Routing]
    }

    fn lineage_family(&self) -> &'static str {
        "upstream_dataset_x"
    }

    fn plan(&self, target: &IpTarget) -> Vec<IpProviderAction> {
        vec![IpProviderAction {
            action_id: "routing".into(),
            capability: IpCapability::Routing,
            request: Request::get(format!("https://example.test/ip/{}", target.canonical())),
            lineage_family: self.lineage_family().into(),
        }]
    }

    fn parse(
        &self,
        _action: &IpProviderAction,
        response: &Response,
        retrieved_at_unix: u64,
    ) -> Result<Vec<IpObservation>, IpProviderParseError> {
        let value: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|error| IpProviderParseError::Parse(error.to_string()))?;
        let Some(rows) = value.get("rows").and_then(serde_json::Value::as_array) else {
            return Err(IpProviderParseError::Schema("missing rows array".into()));
        };
        Ok(rows
            .iter()
            .filter_map(serde_json::Value::as_str)
            .enumerate()
            .map(|(index, row)| IpObservation {
                id: format!("collector_x:{index}"),
                provider_id: self.id().into(),
                source_family: self.lineage_family().into(),
                kind: IpObservationKind::Routing,
                summary: row.into(),
                attributes: BTreeMap::new(),
                observed_at_unix: None,
                retrieved_at_unix,
                raw_digest: None,
            })
            .collect())
    }
}

struct OneShot {
    result: RefCell<Option<Result<Response, TransportFailure>>>,
}

impl OneShot {
    fn response(status: u16, body: &str, truncated: bool) -> Self {
        Self {
            result: RefCell::new(Some(Ok(Response {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                truncated,
            }))),
        }
    }

    fn failure(kind: SourceOutcomeKind) -> Self {
        Self {
            result: RefCell::new(Some(Err(TransportFailure {
                kind,
                detail: "fixture failure".into(),
                blocked: false,
            }))),
        }
    }
}

impl Transport for OneShot {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        self.result.borrow_mut().take().expect("one request")
    }
}

fn action() -> (StubProvider, IpProviderAction) {
    let provider = StubProvider;
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let action = provider.plan(&target).pop().expect("action");
    (provider, action)
}

#[test]
fn valid_200_rows_become_observations() {
    let (provider, action) = action();
    let transport = OneShot::response(200, r#"{"rows":["AS13335"]}"#.replace("\\\"", "\"").as_str(), false);
    let result = execute_provider_action(&transport, &provider, &action, 123);
    assert_eq!(result.observations.len(), 1);
    assert!(result.failures.is_empty(), "{:?}", result.failures);
    assert_eq!(result.observations[0].summary, "AS13335");
    assert_eq!(result.observations[0].retrieved_at_unix, 123);
}

#[test]
fn malformed_200_is_parse_failure_not_empty_evidence() {
    let (provider, action) = action();
    let transport = OneShot::response(200, "{broken", false);
    let result = execute_provider_action(&transport, &provider, &action, 123);
    assert!(result.observations.is_empty(), "{:?}", result.observations);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].kind, IpFailureKind::Parse);
}

#[test]
fn schema_drift_is_explicit_failure() {
    let (provider, action) = action();
    let transport = OneShot::response(200, r#"{"different":[]}"#.replace("\\\"", "\"").as_str(), false);
    let result = execute_provider_action(&transport, &provider, &action, 123);
    assert_eq!(result.failures[0].kind, IpFailureKind::Schema);
}

#[test]
fn truncated_200_cannot_become_clean_empty_evidence() {
    let (provider, action) = action();
    let transport = OneShot::response(200, r#"{"rows":[]}"#.replace("\\\"", "\"").as_str(), true);
    let result = execute_provider_action(&transport, &provider, &action, 123);
    assert!(result.observations.is_empty(), "{:?}", result.observations);
    assert_eq!(result.failures[0].kind, IpFailureKind::Partial);
}

#[test]
fn transport_failure_preserves_causal_outcome() {
    for kind in [
        SourceOutcomeKind::DnsFailure,
        SourceOutcomeKind::ConnectFailure,
        SourceOutcomeKind::TtfbTimeout,
    ] {
        let (provider, action) = action();
        let result = execute_provider_action(&OneShot::failure(kind), &provider, &action, 123);
        assert!(result.observations.is_empty(), "{:?}", result.observations);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].source_outcome, Some(kind));
    }
}

#[test]
fn auth_and_rate_limit_are_explicit_failures() {
    for (status, expected) in [
        (401, IpFailureKind::AuthRequired),
        (429, IpFailureKind::RateLimited),
    ] {
        let (provider, action) = action();
        let result = execute_provider_action(
            &OneShot::response(status, "{}", false),
            &provider,
            &action,
            123,
        );
        assert_eq!(result.failures[0].kind, expected, "status={status}");
    }
}

#[test]
fn action_records_upstream_lineage_not_collector_identity() {
    let (provider, action) = action();
    assert_eq!(provider.id(), "collector_x");
    assert_eq!(action.lineage_family, "upstream_dataset_x");
    assert_ne!(action.lineage_family, provider.id());
}
