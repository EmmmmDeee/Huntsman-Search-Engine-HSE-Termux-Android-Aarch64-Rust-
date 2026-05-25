use sha2::{Digest, Sha256};

use crate::core::entity::unix_now;

pub fn scan_id(kind: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(value.as_bytes());
    h.update(b":");
    h.update(unix_now().to_be_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_id_is_64_hex_chars() {
        let id = scan_id("email", "x@y.com");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
