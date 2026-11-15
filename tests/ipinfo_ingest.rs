//! Legacy IPinfo's production decoder keeps equivalent IPv6 forms and refuses other addresses.

use huntsman_recon::ipinfo::decode;

#[test]
fn expanded_echo_is_an_exact_match_but_another_address_or_malformed_echo_is_not() {
    let ip = "2606:4700:4700::1111";
    let canonical = br#"{"ip":"2606:4700:4700::1111","country":"AU"}"#;
    let expanded = br#"{"ip":"2606:4700:4700:0000:0000:0000:0000:1111","country":"AU"}"#;
    let different = br#"{"ip":"2606:4700:4700::1112","country":"AU","bogon":true}"#;
    assert_eq!(
        decode(expanded, ip).unwrap(),
        decode(canonical, ip).unwrap()
    );
    assert!(decode(different, ip).is_err());
    let malformed = br#"{"ip":"2606:4700:4700::1111%wlan0","country":"AU"}"#;
    assert!(decode(malformed, ip).is_err());
    assert!(decode(br#"{"ip":"invalid"}"#, "invalid").is_err());
}
