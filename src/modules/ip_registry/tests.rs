use crate::core::scan::{Target, TargetKind};

use super::{
    IpRegistry,
    types::{AsnResp, RdapResp},
};
use crate::core::module::Module;

#[test]
fn accepts_ip_and_asn() {
    let m = IpRegistry;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Asn, "AS15169")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[test]
fn priority_and_timeout() {
    let m = IpRegistry;
    assert_eq!(m.priority(), 23);
    assert_eq!(m.max_timeout_ms(), 8_000);
}

#[test]
fn parse_arin_rdap_response() {
    let raw = r#"{
      "handle":"NET-8-8-8-0-1",
      "name":"LVLT-GOGL-8-8-8",
      "country":"US",
      "startAddress":"8.8.8.0",
      "endAddress":"8.8.8.255",
      "ipVersion":"v4",
      "parentHandle":"NET-8-0-0-0-0",
      "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
      "events":[
        {"eventAction":"last changed","eventDate":"2014-03-14T16:52:05-04:00"},
        {"eventAction":"registration","eventDate":"2014-03-14T16:52:05-04:00"}
      ]
    }"#;
    let r: RdapResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.handle.as_deref(), Some("NET-8-8-8-0-1"));
    assert_eq!(r.country.as_deref(), Some("US"));
    assert_eq!(r.cidr0_cidrs.len(), 1);
    assert_eq!(r.events.len(), 2);
}

#[test]
fn parse_bgpview_asn_response() {
    let raw = r#"{
      "status": "ok",
      "data": {
        "name": "GOOGLE",
        "description_short": "Google LLC",
        "country_code": "US",
        "rir_allocation": {"rir_name": "ARIN", "date_allocated": "2000-03-30"},
        "email_contacts": ["noc@google.com"],
        "abuse_contacts": ["abuse@google.com"],
        "website": "https://about.google"
      }
    }"#;
    let r: AsnResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.status, "ok");
    let data = r.data.unwrap();
    assert_eq!(data.name.as_deref(), Some("GOOGLE"));
    assert_eq!(data.country_code.as_deref(), Some("US"));
}
