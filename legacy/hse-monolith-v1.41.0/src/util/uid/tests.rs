use super::*;

#[test]
fn scan_id_is_64_hex_chars() {
    let id = scan_id("email", "x@y.com");
    assert_eq!(id.len(), 64);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn scan_id_is_unique_per_call() {
    // scan_id mixes in a timestamp + monotonic counter — two calls with
    // identical inputs must produce distinct ids (collision-freedom).
    let a = scan_id("email", "x@y.com");
    let b = scan_id("email", "x@y.com");
    assert_ne!(a, b);
}

#[test]
fn scan_id_differs_across_distinct_inputs() {
    assert_ne!(scan_id("email", "a@b.com"), scan_id("username", "alice"));
    assert_ne!(scan_id("email", "a@b.com"), scan_id("email", "b@b.com"));
}
