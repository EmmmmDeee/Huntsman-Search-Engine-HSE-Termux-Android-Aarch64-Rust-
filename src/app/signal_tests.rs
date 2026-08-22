// Tests for the `hse signal` presenter. The queries themselves are covered in
// `storage::signal`; what is worth pinning here is the formatting that must not
// mislead and the flag precedence.
//
// Plain `//` rather than `//!`: `include!`d into a `mod tests` block.

use super::*;

#[test]
fn a_missing_signal_reading_is_not_rendered_as_zero() {
    // 0 dBm is an implausibly strong signal — roughly touching the antenna.
    // Rendering "no reading" as 0 would put every unmeasured device at the top
    // of a strongest-first list and read as a measurement that never happened.
    assert_eq!(dbm(None), "—");
    assert_eq!(dbm(Some(-82.0)), "-82");
    assert_eq!(dbm(Some(-82.4)), "-82");
}

#[test]
fn address_labels_keep_randomised_and_unknown_distinct() {
    // Three genuinely different states: a followable hardware address, a
    // rotating privacy address, and an identifier that is not an address at
    // all. Collapsing any pair of them loses the AU-122 distinction.
    assert_eq!(address_label(Some(false)), "fixed");
    assert_eq!(address_label(Some(true)), "random");
    assert_eq!(address_label(None), "—");
}

#[test]
fn radio_labels_cover_every_variant() {
    assert_eq!(radio_label(RadioKind::Wifi), "wifi");
    assert_eq!(radio_label(RadioKind::Ble), "ble");
    assert_eq!(radio_label(RadioKind::BtClassic), "bt");
    assert_eq!(radio_label(RadioKind::Cellular), "cell");
}
