//! Single source of truth for per-endpoint value/cost signals.
//!
//! Every See-Know endpoint the engine can call is anchored here by its
//! **canonical API path** (`/{path}` from `EndpointCall::spec`, e.g.
//! `/network/email-check`), so the value scorer, cost analyzer, and the live
//! plan orderer all read the SAME metadata instead of maintaining divergent
//! copies. Credit cost is not duplicated — it delegates to
//! [`crate::util::see_know::config::get_endpoint_cost`], the one cost table.

use std::collections::HashMap;

/// 1-D per-endpoint signals (the target-type-dependent signals — hit rate and
/// coverage — legitimately vary by target and stay in the value scorer).
#[derive(Debug, Clone, Copy)]
pub struct EndpointMetadata {
    /// Distinct entity types the endpoint can return (drives diversity score).
    pub entity_type_count: usize,
    /// Downstream cascade/pivot potential (0-100).
    pub pivot_potential: f32,
    /// Typical wall-clock latency in seconds (planning hint).
    pub typical_latency_seconds: f32,
}

/// Registry of endpoint metadata, keyed by canonical API path.
pub struct EndpointRegistry {
    metadata: HashMap<&'static str, EndpointMetadata>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        // (path, entity_type_count, pivot_potential, typical_latency_seconds)
        //
        // Values are anchored to the real endpoint set (EndpointCall::spec plus
        // the separately-dispatched /search + /search/deep). Pivot potentials
        // reflect how many downstream identities a hit typically unlocks:
        // Discord IDs and emails fan out widely; leaf profile lookups do not.
        const ROWS: &[(&str, usize, f32, f32)] = &[
            // Universal search (dispatched directly by Module::process)
            ("/search", 17, 65.0, 10.0),
            ("/search/deep", 17, 65.0, 40.0),
            // Network
            ("/network/email-check", 3, 75.0, 10.0),
            ("/network/ip", 5, 40.0, 10.0),
            ("/network/phone", 2, 25.0, 10.0),
            // Username
            ("/username/social", 3, 70.0, 12.0),
            ("/username/github", 2, 50.0, 9.0),
            ("/username/twitter", 2, 50.0, 9.0),
            ("/username/reddit", 2, 25.0, 9.0),
            ("/username/tiktok", 2, 25.0, 9.0),
            ("/username/history", 3, 25.0, 12.0),
            // Gaming
            ("/gaming/roblox", 2, 25.0, 9.0),
            ("/gaming/xbox", 2, 25.0, 9.0),
            ("/gaming/minecraft", 2, 25.0, 9.0),
            ("/gaming/steam", 2, 35.0, 9.0),
            // Discord (Tier-1 pivots)
            ("/discord/user", 2, 80.0, 8.0),
            ("/discord/to-roblox", 2, 25.0, 8.0),
            // Domain
            ("/domain/intel", 4, 45.0, 11.0),
            ("/domain/whois", 3, 25.0, 11.0),
        ];
        let metadata = ROWS
            .iter()
            .map(|&(path, count, pivot, latency)| {
                (
                    path,
                    EndpointMetadata {
                        entity_type_count: count,
                        pivot_potential: pivot,
                        typical_latency_seconds: latency,
                    },
                )
            })
            .collect();
        Self { metadata }
    }

    pub fn get(&self, endpoint: &str) -> Option<&EndpointMetadata> {
        self.metadata.get(endpoint)
    }

    /// Distinct entity types (default 1 for unknown endpoints).
    pub fn entity_type_count(&self, endpoint: &str) -> usize {
        self.get(endpoint).map_or(1, |m| m.entity_type_count)
    }

    /// Pivot potential 0-100 (default 25 for unknown endpoints — the value
    /// scorer's historical floor for un-tabulated endpoints).
    pub fn pivot_potential(&self, endpoint: &str) -> f32 {
        self.get(endpoint).map_or(25.0, |m| m.pivot_potential)
    }

    /// Typical latency in seconds (default 12 for unknown endpoints).
    pub fn typical_latency_seconds(&self, endpoint: &str) -> f32 {
        self.get(endpoint).map_or(12.0, |m| m.typical_latency_seconds)
    }

    /// Direct credit cost — delegates to the one cost table so cost is never
    /// duplicated here.
    pub fn credit_cost(&self, endpoint: &str) -> f32 {
        crate::util::see_know::config::get_endpoint_cost(endpoint)
    }

    /// All registered canonical paths.
    pub fn all_endpoints(&self) -> Vec<&'static str> {
        self.metadata.keys().copied().collect()
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_uses_real_canonical_paths() {
        let r = EndpointRegistry::new();
        // Real paths present…
        assert_eq!(r.entity_type_count("/search"), 17);
        assert_eq!(r.entity_type_count("/discord/user"), 2);
        assert_eq!(r.pivot_potential("/discord/user"), 80.0);
        assert_eq!(r.pivot_potential("/network/email-check"), 75.0);
        // …and every EndpointCall path is covered (18 + deep = 19).
        assert!(r.all_endpoints().len() >= 19);
    }

    #[test]
    fn unknown_endpoint_falls_back_to_floor() {
        let r = EndpointRegistry::new();
        assert_eq!(r.entity_type_count("/does/not/exist"), 1);
        assert_eq!(r.pivot_potential("/does/not/exist"), 25.0);
    }

    #[test]
    fn credit_cost_delegates_to_config() {
        let r = EndpointRegistry::new();
        assert_eq!(r.credit_cost("/search"), 1.0);
        assert_eq!(r.credit_cost("/search/deep"), 3.0);
    }
}
