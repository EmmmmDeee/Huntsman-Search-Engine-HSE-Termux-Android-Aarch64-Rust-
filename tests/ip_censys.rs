//! Censys v3 evidence contracts, exercised through the same indicator fold as IP lookups.
//! Fixtures follow <https://docs.censys.com/reference/v3-globaldata-asset-host.md>
//! (`OpenAPI` 1.0.156): `Routing.name` is an AS label; `Routing.organization` is its operator.
//! Service fields are optional; rows are objects and DNS names are strings.

use huntsman_recon::entity::EntityKind;
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::indicator_legs::{self, Legs};
use huntsman_recon::indicator_sources::Indicator;
use huntsman_recon::keys::Keys;
use huntsman_recon::source_outcome::SourceOutcomeKind;
use serde_json::{Value, json};

struct HostReply(Value);

impl Transport for HostReply {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        assert_eq!(
            request.url,
            "https://api.platform.censys.io/v3/global/asset/host/1.1.1.1"
        );
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: serde_json::to_vec(&json!({"result": {"resource": self.0, "extensions": {}}}))
                .expect("JSON"),
            truncated: false,
        })
    }

    fn runs_module(&self, module: &str) -> bool {
        module == "censys"
    }
}

fn lookup(host: Value) -> Legs {
    let keys = Keys::parse("HUNTSMAN_CENSYS_TOKEN=TEST_ONLY_CENSYS_TOKEN").expect("synthetic key");
    indicator_legs::run(
        &HostReply(host),
        &keys,
        Indicator::Ip("1.1.1.1"),
        "censys-contract",
        1_760_000_000,
    )
}

#[test]
fn organization_is_the_managing_organization_not_the_as_label() {
    let legs = lookup(json!({
        "ip": "1.1.1.1", "services": [],
        "autonomous_system": {"asn": 13335, "name": "AS-LABEL", "organization": "Actual Operator Ltd"}
    }));
    let organizations: Vec<_> = legs
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Organisation)
        .map(|entity| entity.value.as_str())
        .collect();
    assert_eq!(organizations, ["actual operator ltd"]);
    let address = legs
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::IpAddress)
        .expect("address evidence");
    assert_eq!(
        address.evidence[0]
            .attr_values("as_name")
            .collect::<Vec<_>>(),
        ["AS-LABEL"]
    );
    assert_eq!(
        address.evidence[0]
            .attr_values("as_organization")
            .collect::<Vec<_>>(),
        ["Actual Operator Ltd"]
    );
    assert!(
        legs.entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Asn && entity.value == "as13335")
    );
}

#[test]
fn absent_or_blank_organization_never_infers_an_organization_from_an_as_label() {
    for organization in [None, Some(json!("")), Some(json!("  ")), Some(Value::Null)] {
        let mut host =
            json!({"ip": "1.1.1.1", "autonomous_system": {"asn": 13335, "name": "AS-LABEL"}});
        if let Some(value) = organization {
            host["autonomous_system"]["organization"] = value;
        }
        let legs = lookup(host);
        assert_eq!(legs.outcomes[0].kind, SourceOutcomeKind::Success);
        assert!(
            !legs
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Organisation)
        );
    }
}

#[test]
fn malformed_consumed_rows_are_schema_drift_without_evidence() {
    let mut failures = Vec::new();
    for fields in [
        json!({"services": [null]}),
        json!({"services": [7]}),
        json!({"services": [{"port": "443"}]}),
        json!({"services": [{"port": -1}]}),
        json!({"services": [{"port": 65536}]}),
        json!({"services": [{"port": 443.5}]}),
        json!({"services": [{"port": 443, "transport_protocol": 7}]}),
        json!({"services": [{"port": 443, "protocol": false}]}),
        json!({"dns": {"names": [7]}}),
        json!({"dns": {"names": [null]}}),
        json!({"services": [{"port": 443}, null], "dns": {"names": ["example.org"]}}),
    ] {
        let mut host = fields;
        host["ip"] = json!("1.1.1.1");
        let legs = lookup(host.clone());
        assert_eq!(legs.outcomes.len(), 1, "{host}");
        if legs.outcomes[0].kind != SourceOutcomeKind::SchemaDrift || !legs.entities.is_empty() {
            failures.push(format!(
                "{host}: outcome={:?}, entities={}",
                legs.outcomes[0].kind,
                legs.entities.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "malformed responses accepted: {failures:#?}"
    );
}

#[test]
fn malformed_optional_objects_and_metadata_are_schema_drift() {
    let mut failures = Vec::new();
    for mut host in [
        json!({"dns": 7}),
        json!({"dns": "invalid"}),
        json!({"dns": []}),
        json!({"autonomous_system": 7}),
        json!({"autonomous_system": {"organization": 7}}),
        json!({"autonomous_system": {"name": []}}),
        json!({"autonomous_system": {"asn": "13335"}}),
        json!({"autonomous_system": {"asn": -1}}),
        json!({"autonomous_system": {"asn": 13335.5}}),
        json!({"location": 7}),
        json!({"location": {"country": 7}}),
        json!({"location": {"city": []}}),
    ] {
        host["ip"] = json!("1.1.1.1");
        let legs = lookup(host.clone());
        assert_eq!(legs.outcomes.len(), 1);
        if legs.outcomes[0].kind != SourceOutcomeKind::SchemaDrift || !legs.entities.is_empty() {
            failures.push(host);
        }
    }
    assert!(
        failures.is_empty(),
        "malformed metadata accepted: {failures:#?}"
    );
}

#[test]
fn documented_sparse_services_and_optional_collections_remain_answers() {
    for host in [
        json!({"ip": "1.1.1.1"}),
        json!({"ip": "1.1.1.1", "dns": null}),
        json!({"ip": "1.1.1.1", "autonomous_system": null, "location": null}),
        json!({"ip": "1.1.1.1", "autonomous_system": {}, "location": {}, "dns": {}}),
        json!({"ip": "1.1.1.1", "autonomous_system": {"name": null, "organization": null, "asn": null}, "location": {"city": null, "country": null}}),
        json!({"ip": "1.1.1.1", "services": null, "dns": {"names": null}}),
        json!({"ip": "1.1.1.1", "services": [], "dns": {"names": []}}),
        json!({"ip": "1.1.1.1", "services": [{}]}),
        json!({"ip": "1.1.1.1", "services": [{"port": null, "protocol": null, "transport_protocol": null}]}),
        json!({"ip": "1.1.1.1", "services": [{"port": 0}, {"port": 65535, "transport_protocol": "udp"}]}),
    ] {
        let legs = lookup(host.clone());
        assert_eq!(legs.outcomes.len(), 1, "{host}");
        assert_eq!(legs.outcomes[0].kind, SourceOutcomeKind::Success, "{host}");
        assert_eq!(legs.entities.len(), 1, "{host}");
    }
}
