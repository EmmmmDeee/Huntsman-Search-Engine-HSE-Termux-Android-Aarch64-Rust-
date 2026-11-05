//! Public, offline catalogue API smoke test. This staged diagnostic has no
//! production scan caller until catalogue importing is separately integrated.

use huntsman_recon::username_catalog::{
    AccountVerdict, ControlObservation, ProbeObservation, parse_catalogue, verdict,
};

#[test]
fn a_generic_profile_needs_explicit_negative_controls() {
    let catalogue = br#"[{"id":"example_site","url_template":"https://users.example.org/u/{username}","detection":{"kind":"html_markers","present":"account-profile-header","absent":"no-such-account-here"}}]"#;
    let sites = parse_catalogue(catalogue).expect("valid bounded catalogue");
    let site = &sites[0];
    let observed = site.observe("jack", 200, b"<h1>account-profile-header jack</h1>", false);
    assert_eq!(observed, ProbeObservation::Candidate);
    assert_eq!(verdict("jack", observed, &[]), AccountVerdict::Unconfirmed);
    let controls = ["xxxx", "abcdefgh", "zzzzzzzz"].map(|username| ControlObservation {
        username: username.into(),
        observation: ProbeObservation::Absent,
    });
    assert_eq!(verdict("jack", observed, &controls), AccountVerdict::Exists);
}
