//! Utilities: HTTP client, DNS resolver, key loading, UID generation, Termux helpers.

pub mod curl;
pub mod freq;
pub mod http;
pub mod key_pool;
pub mod keys;
pub mod oathnet;
pub mod proxy;
pub mod termux;

pub mod dns {
    use std::sync::OnceLock;

    use hickory_resolver::{
        TokioResolver,
        config::{CLOUDFLARE, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };

    pub fn shared_resolver() -> &'static TokioResolver {
        static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
        RESOLVER.get_or_init(|| {
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            )
            .build()
            .expect("hardcoded Cloudflare resolver config must build")
        })
    }
}

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
