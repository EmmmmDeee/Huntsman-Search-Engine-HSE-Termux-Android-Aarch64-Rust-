//! Utilities: HTTP client, DNS resolver, key loading, UID generation, Termux helpers.

pub mod curl;
pub mod dns;
pub mod freq;
pub mod http;
pub mod key_pool;
pub mod keys;
pub mod oathnet;
pub mod proxy;
pub mod termux;

pub mod uid {
    pub fn scan_id(kind: &str, value: &str) -> String {
        crate::core::entity::scan_id(kind, value)
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
}
