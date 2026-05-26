//! Utilities: HTTP client, DNS resolver, key loading, UID generation, Termux helpers.

pub mod curl;
pub mod http;
pub mod key_pool;
pub mod keys;
pub mod oathnet;
pub mod proxy;

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

pub mod termux {
    use std::time::Duration;

    use tokio::process::Command;
    use tokio::time::timeout;

    pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
        let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
        let output = timeout(Duration::from_millis(timeout_ms), fut)
            .await
            .ok()?
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(output.stdout)
    }
}

pub mod freq {
    use std::collections::BTreeMap;

    pub fn top_n<'a>(items: impl Iterator<Item = &'a str>, n: usize) -> String {
        let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
        for item in items {
            *counts.entry(item).or_insert(0) += 1;
        }
        let mut ranked: Vec<(&str, u32)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        ranked.truncate(n);
        ranked
            .iter()
            .map(|(k, v)| format!("{k}\u{00d7}{v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn top_n_ranks_by_frequency_descending() {
            let items = ["a", "b", "a", "c", "b", "a"];
            let result = top_n(items.iter().copied(), 3);
            assert_eq!(result, "a\u{00d7}3, b\u{00d7}2, c\u{00d7}1");
        }

        #[test]
        fn top_n_truncates() {
            let items = ["x", "y", "z", "x", "y", "x"];
            let result = top_n(items.iter().copied(), 2);
            assert_eq!(result, "x\u{00d7}3, y\u{00d7}2");
        }

        #[test]
        fn top_n_empty_input() {
            let result = top_n(std::iter::empty(), 5);
            assert!(result.is_empty());
        }

        #[test]
        fn top_n_tiebreaker_is_alphabetical() {
            let items = ["b", "a", "c"];
            let result = top_n(items.iter().copied(), 3);
            assert_eq!(result, "a\u{00d7}1, b\u{00d7}1, c\u{00d7}1");
        }
    }
}
