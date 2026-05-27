//! Australian Business Number (ABN/ACN) lookup via the ABR JSON API.
//!
//! Consumes `Organisation` and `AbnAcn` target kinds (enabled by
//! Phase 0.3). Searches the Australian Business Register for matching
//! entities and emits `Person`, `Address`, `Domain`, `Organisation`
//! entities from the results.
//!
//! Free API — requires a GUID from https://abr.business.gov.au/Tools/WebServicesRegister
//! (instant, free registration). Set `HUNTSMAN_ABR_GUID` in the env file.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::process::Command;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "abn_lookup";

pub struct AbnLookup;

const KEY_ENV: &str = "HUNTSMAN_ABR_GUID";
const BASE_URL: &str = "https://abr.business.gov.au/json";

#[async_trait]
impl Module for AbnLookup {
    fn name(&self) -> &'static str {
        "abn_lookup"
    }

    fn description(&self) -> &'static str {
        "Australian Business Register ABN/ACN/name lookup"
    }

    fn priority(&self) -> u8 {
        80
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::AbnAcn | TargetKind::FullName
        )
    }

    fn is_passive(&self) -> bool {
        true
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let guid = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::AbnAcn => {
                let digits: String = value.chars().filter(char::is_ascii_digit).collect();
                if digits.len() == 11 {
                    if let Some(data) = fetch_abn(guid, &digits).await? {
                        parse_abn_result(&data, &ctx.scan_id, &mut result);
                    }
                } else if digits.len() == 9 {
                    if let Some(data) = fetch_acn(guid, &digits).await? {
                        parse_abn_result(&data, &ctx.scan_id, &mut result);
                    }
                } else {
                    return Err(Error::module(
                        "abn_lookup",
                        format!("'{value}' is not a valid ABN (11 digits) or ACN (9 digits)"),
                    ));
                }
            }
            TargetKind::Organisation | TargetKind::FullName => {
                if let Some(data) = fetch_name(guid, value).await? {
                    parse_name_results(&data, value, &ctx.scan_id, &mut result);
                }
            }
            _ => {}
        }

        Ok(result)
    }
}

async fn fetch_abn(guid: &str, abn: &str) -> Result<Option<Value>> {
    let url = format!("{BASE_URL}/AbnDetails.aspx?abn={abn}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

async fn fetch_acn(guid: &str, acn: &str) -> Result<Option<Value>> {
    let url = format!("{BASE_URL}/AcnDetails.aspx?acn={acn}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

async fn fetch_name(guid: &str, name: &str) -> Result<Option<Value>> {
    let encoded = crate::util::http::urlencode(name);
    let url = format!("{BASE_URL}/MatchingNames.aspx?name={encoded}&callback=cb&guid={guid}");
    fetch_jsonp(&url).await
}

async fn curl_with_status(url: &str, timeout_ms: u64) -> Option<(String, u16)> {
    let secs = (timeout_ms / 1000).max(3).to_string();
    let mut cmd = Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-A",
        crate::util::curl::UA_MOBILE,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/json",
        "-H",
        "Accept-Language: en-US,en;q=0.9",
        "-w",
        "\n%{http_code}",
        "-L",
        "--",
        url,
    ]);

    if let Ok(proxy) = std::env::var("HUNTSMAN_SEARCH_PROXY")
        && !proxy.is_empty()
    {
        cmd.args(["-x", &proxy]);
    }

    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8(output.stdout).ok()?;
    let (body, code_str) = raw.rsplit_once('\n')?;
    let code: u16 = code_str.trim().parse().unwrap_or(0);
    Some((body.to_string(), code))
}

fn parse_jsonp_body(body: &str) -> Option<Value> {
    let json_str = body.strip_prefix("cb(").and_then(|s| s.strip_suffix(')'))?;
    serde_json::from_str(json_str).ok()
}

async fn fetch_jsonp(url: &str) -> Result<Option<Value>> {
    let (body, status) = match curl_with_status(url, 10_000).await {
        Some(pair) => pair,
        None => return Ok(None),
    };

    if status == 429 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let (body, status) = match curl_with_status(url, 10_000).await {
            Some(pair) => pair,
            None => return Ok(None),
        };
        if status == 429 {
            return Err(Error::module(SRC, "rate-limited (429) after retry"));
        }
        if status == 401 || status == 403 {
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: unauthorized or forbidden"),
            ));
        }
        if status >= 400 {
            return Ok(None);
        }
        return Ok(parse_jsonp_body(&body));
    }

    if status == 401 || status == 403 {
        return Err(Error::module(
            SRC,
            format!("HTTP {status}: unauthorized or forbidden"),
        ));
    }

    if status >= 400 {
        return Ok(None);
    }

    Ok(parse_jsonp_body(&body))
}

fn parse_abn_result(data: &Value, scan_id: &str, result: &mut ModuleResult) {
    if data
        .get("Message")
        .and_then(|m| m.as_str())
        .is_some_and(|m| !m.is_empty())
    {
        return;
    }

    let abn = str_field(data, "Abn").unwrap_or_default();
    let entity_name = str_field(data, "EntityName").unwrap_or_default();
    let entity_type = str_field(data, "EntityTypeCode")
        .or_else(|| str_field(data, "EntityTypeName"))
        .unwrap_or_default();
    let status = str_field(data, "AbnStatus").unwrap_or_default();
    let state = str_field(data, "AddressState").unwrap_or_default();
    let postcode = str_field(data, "AddressPostcode").unwrap_or_default();
    let gst = str_field(data, "Gst").unwrap_or_default();

    if entity_name.is_empty() {
        return;
    }

    let mut org = Entity::new(EntityKind::Organisation, &entity_name, 0.90, scan_id);
    org.tag("abr");
    org.tag("australian");
    if status.to_lowercase().contains("active") {
        org.tag("active");
    }

    let mut ev = Evidence::new(SRC, format!("ABR: {entity_name} (ABN {abn})"))
        .with_attr("abn", &abn)
        .with_attr("entity_type", &entity_type)
        .with_attr("status", &status);

    if !state.is_empty() {
        ev = ev.with_attr("state", &state);
    }
    if !postcode.is_empty() {
        ev = ev.with_attr("postcode", &postcode);
    }
    if !gst.is_empty() {
        ev = ev.with_attr("gst_registered", &gst);
    }

    org.add_evidence(ev);
    result.push(org);

    if !abn.is_empty() {
        let mut abn_entity = Entity::new(EntityKind::AbnAcn, &abn, 0.95, scan_id);
        abn_entity.tag("abr");
        abn_entity.add_evidence(Evidence::new(
            "abn_lookup",
            format!("ABN {abn} → {entity_name}"),
        ));
        result.push(abn_entity);
    }

    if !state.is_empty() {
        let addr = if postcode.is_empty() {
            format!("{state}, Australia")
        } else {
            format!("{postcode}, {state}, Australia")
        };
        let mut addr_entity = Entity::new(EntityKind::Address, &addr, 0.75, scan_id);
        addr_entity.tag("abr");
        addr_entity.add_evidence(Evidence::new(
            "abn_lookup",
            format!("Business address for {entity_name}"),
        ));
        result.push(addr_entity);
    }

    if let Some(names) = data.get("BusinessName").and_then(|v| v.as_array()) {
        for bn in names.iter().take(5) {
            if let Some(name) = bn
                .as_str()
                .or_else(|| bn.get("Value").and_then(|v| v.as_str()))
                && !name.is_empty()
                && name != entity_name
            {
                let mut bn_entity = Entity::new(EntityKind::Organisation, name, 0.80, scan_id);
                bn_entity.tag("abr");
                bn_entity.tag("business-name");
                bn_entity.add_evidence(Evidence::new(
                    "abn_lookup",
                    format!("Trading name for ABN {abn}"),
                ));
                result.push(bn_entity);
            }
        }
    }

    if entity_type.contains("IND") || entity_type.contains("Individual") {
        let mut person = Entity::new(EntityKind::Person, &entity_name, 0.80, scan_id);
        person.tag("abr");
        person.tag("sole-trader");
        person.add_evidence(Evidence::new(
            "abn_lookup",
            format!("Individual/sole trader: ABN {abn}"),
        ));
        result.push(person);
    }
}

fn parse_name_results(data: &Value, query: &str, scan_id: &str, result: &mut ModuleResult) {
    let names = match data.get("Names").and_then(|v| v.as_array()) {
        Some(n) if !n.is_empty() => n,
        _ => return,
    };

    for entry in names.iter().take(10) {
        let abn = str_field(entry, "Abn").unwrap_or_default();
        let name = str_field(entry, "Name").unwrap_or_default();
        let name_type = str_field(entry, "NameType").unwrap_or_default();
        let state = str_field(entry, "State").unwrap_or_default();
        let postcode = str_field(entry, "Postcode").unwrap_or_default();
        let score = entry
            .get("Score")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        if name.is_empty() || abn.is_empty() {
            continue;
        }

        let conf = match score {
            90..=100 => 0.90,
            70..=89 => 0.80,
            50..=69 => 0.70,
            _ => 0.60,
        };

        let mut org = Entity::new(EntityKind::Organisation, &name, conf, scan_id);
        org.tag("abr");
        org.tag("australian");

        let mut ev = Evidence::new(
            "abn_lookup",
            format!("ABR name match for '{query}': {name} (ABN {abn})"),
        )
        .with_attr("abn", &abn)
        .with_attr("match_score", score.to_string())
        .with_attr("name_type", &name_type);
        if !state.is_empty() {
            ev = ev.with_attr("state", &state);
        }
        if !postcode.is_empty() {
            ev = ev.with_attr("postcode", &postcode);
        }
        org.add_evidence(ev);
        result.push(org);

        let mut abn_entity = Entity::new(EntityKind::AbnAcn, &abn, conf, scan_id);
        abn_entity.tag("abr");
        abn_entity.add_evidence(Evidence::new(
            "abn_lookup",
            format!("{name} (score {score})"),
        ));
        result.push(abn_entity);

        if !state.is_empty() {
            let addr = if postcode.is_empty() {
                format!("{state}, Australia")
            } else {
                format!("{postcode}, {state}, Australia")
            };
            let mut addr_entity = Entity::new(EntityKind::Address, &addr, 0.65, scan_id);
            addr_entity.tag("abr");
            addr_entity.add_evidence(Evidence::new(SRC, format!("Location for {name}")));
            result.push(addr_entity);
        }
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_org_and_abn() {
        let m = AbnLookup;
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "BHP")));
        assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "19415776361")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn parse_abn_response() {
        let data = serde_json::json!({
            "Abn": "19415776361",
            "EntityName": "BHP GROUP LIMITED",
            "EntityTypeCode": "PUB",
            "EntityTypeName": "Australian Public Company",
            "AbnStatus": "Active",
            "AddressState": "VIC",
            "AddressPostcode": "3000",
            "Gst": "2000-07-01",
            "BusinessName": ["BHP"]
        });

        let mut result = ModuleResult::new();
        parse_abn_result(&data, "test", &mut result);

        assert!(result.entities.len() >= 3);
        let org = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .unwrap();
        assert_eq!(org.value, "BHP GROUP LIMITED");
        assert!(org.tags.contains(&"abr".to_string()));
        assert!(org.tags.contains(&"active".to_string()));

        let abn = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::AbnAcn)
            .unwrap();
        assert_eq!(abn.value, "19415776361");

        let addr = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .unwrap();
        assert!(addr.value.contains("VIC"));
    }

    #[test]
    fn parse_name_search_response() {
        let data = serde_json::json!({
            "Names": [
                {
                    "Abn": "19415776361",
                    "Name": "BHP GROUP LIMITED",
                    "NameType": "Entity Name",
                    "State": "VIC",
                    "Postcode": "3000",
                    "Score": 100
                },
                {
                    "Abn": "49004028077",
                    "Name": "BHP BILLITON LIMITED",
                    "NameType": "Former Name",
                    "State": "VIC",
                    "Postcode": "3000",
                    "Score": 85
                }
            ]
        });

        let mut result = ModuleResult::new();
        parse_name_results(&data, "BHP", "test", &mut result);

        assert!(result.entities.len() >= 4);
        let orgs: Vec<_> = result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .collect();
        assert_eq!(orgs.len(), 2);
    }

    #[test]
    fn parse_empty_response() {
        let data = serde_json::json!({"Message": "No records found"});
        let mut result = ModuleResult::new();
        parse_abn_result(&data, "test", &mut result);
        assert!(result.entities.is_empty());
    }

    #[test]
    fn jsonp_strip() {
        let raw = r#"cb({"Abn":"123"})"#;
        let json_str = raw.strip_prefix("cb(").and_then(|s| s.strip_suffix(')'));
        assert_eq!(json_str, Some(r#"{"Abn":"123"}"#));
    }
}
