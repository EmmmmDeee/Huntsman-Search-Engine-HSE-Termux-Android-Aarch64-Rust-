use super::*;

#[test]
fn parse_exit_list_yields_plain_ips() {
    let body = "# Tor exit node list\n\
                \n\
                185.220.101.1\n\
                185.220.101.2\n\
                # another comment\n\
                192.42.116.16\n";
    let ips: Vec<&str> = parse_exit_list(body).collect();
    assert_eq!(ips, vec!["185.220.101.1", "185.220.101.2", "192.42.116.16"]);
}

#[test]
fn parse_exit_list_empty_body() {
    let ips: Vec<&str> = parse_exit_list("").collect();
    assert!(ips.is_empty());
}

#[test]
fn parse_exit_list_all_comments_and_blanks() {
    let body = "# comment 1\n\n# comment 2\n";
    let ips: Vec<&str> = parse_exit_list(body).collect();
    assert!(ips.is_empty());
}

#[test]
fn parse_exit_list_trims_whitespace() {
    let body = "  198.51.100.1  \n  198.51.100.2\n";
    let ips: Vec<&str> = parse_exit_list(body).collect();
    assert_eq!(ips, vec!["198.51.100.1", "198.51.100.2"]);
}

#[test]
fn module_metadata() {
    let m = TorExitRealtime;
    assert_eq!(m.name(), "tor_exit_realtime");
    assert_eq!(
        m.description(),
        "Check whether an IP is a current Tor exit node (live consensus)"
    );
    assert_eq!(m.priority(), 48);
    assert!(m.is_passive());
    assert!(matches!(m.cost(), ModuleCost::Free));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert_eq!(m.max_timeout_ms(), 8_000);
    assert!(matches!(m.category(), ModuleCategory::Threat));
    assert_eq!(m.attack_techniques(), &["T1090.003"]);
    assert_eq!(m.produces(), &[EntityKind::IpAddress]);
}
