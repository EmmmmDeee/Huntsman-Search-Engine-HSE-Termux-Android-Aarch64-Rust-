//! Stable scan-identifier helper rebuilt from `util/uid` for the offline crate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn scan_id(kind: &str, value: &str) -> String {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0u128, |duration| duration.as_nanos());
    let material = format!("huntsman-scan-id-v1\0{kind}\0{value}\0{now}\0{counter}");
    crate::sha256::hex32(&crate::sha256::sha256(material.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_id_shape_and_uniqueness_hold() {
        let first = scan_id("email", "x@y.com");
        let second = scan_id("email", "x@y.com");
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second);
        assert_ne!(scan_id("email", "a@b.com"), scan_id("username", "alice"));
    }
}
