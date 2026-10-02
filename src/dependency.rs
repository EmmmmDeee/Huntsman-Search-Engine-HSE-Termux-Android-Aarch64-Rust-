use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::entity::EntityKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Email,
    Username,
    Phone,
    FullName,
    IpAddress,
    Domain,
    Url,
    Asn,
    Coordinates,
    Address,
    Organisation,
    AbnAcn,
    MacAddress,
    ApiKey,
    CryptoAddress,
    DeviceId,
    Ssid,
    TrackingId,
}

impl TargetKind {
    #[must_use]
    pub const fn canonical_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::FullName => "full_name",
            Self::IpAddress => "ip_address",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Asn => "asn",
            Self::Coordinates => "coordinates",
            Self::Address => "address",
            Self::Organisation => "organisation",
            Self::AbnAcn => "abn_acn",
            Self::MacAddress => "mac_address",
            Self::ApiKey => "api_key",
            Self::CryptoAddress => "crypto_address",
            Self::DeviceId => "device_id",
            Self::Ssid => "ssid",
            Self::TrackingId => "tracking_id",
        }
    }

    #[must_use]
    pub fn from_entity_kind(kind: &EntityKind) -> Option<Self> {
        match kind {
            EntityKind::Person => Some(Self::FullName),
            EntityKind::Organisation => Some(Self::Organisation),
            EntityKind::Email => Some(Self::Email),
            EntityKind::Phone => Some(Self::Phone),
            EntityKind::Username => Some(Self::Username),
            EntityKind::Domain => Some(Self::Domain),
            EntityKind::Url => Some(Self::Url),
            EntityKind::IpAddress => Some(Self::IpAddress),
            EntityKind::Coordinates => Some(Self::Coordinates),
            EntityKind::Address => Some(Self::Address),
            EntityKind::Credential | EntityKind::Document | EntityKind::Other => None,
            EntityKind::CryptoAddress => Some(Self::CryptoAddress),
            EntityKind::DeviceId => Some(Self::DeviceId),
            EntityKind::Ssid => Some(Self::Ssid),
            EntityKind::TrackingId => Some(Self::TrackingId),
            EntityKind::AbnAcn => Some(Self::AbnAcn),
            EntityKind::ApiKey => Some(Self::ApiKey),
            EntityKind::MacAddress => Some(Self::MacAddress),
            EntityKind::Asn => Some(Self::Asn),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

impl Target {
    #[must_use]
    pub fn new(kind: TargetKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCategory {
    DnsRecon,
    Breach,
    Infrastructure,
    Search,
    Social,
    Email,
    Phone,
    Corporate,
    Threat,
    Sensor,
    People,
    Web,
    Geo,
    Other,
}

impl ModuleCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DnsRecon => "dns_recon",
            Self::Breach => "breach",
            Self::Infrastructure => "infrastructure",
            Self::Search => "search",
            Self::Social => "social",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Corporate => "corporate",
            Self::Threat => "threat",
            Self::Sensor => "sensor",
            Self::People => "people",
            Self::Web => "web",
            Self::Geo => "geo",
            Self::Other => "other",
        }
    }
}

pub const ALL_TARGET_KINDS: &[TargetKind] = &[
    TargetKind::Email,
    TargetKind::Username,
    TargetKind::Phone,
    TargetKind::FullName,
    TargetKind::IpAddress,
    TargetKind::Domain,
    TargetKind::Url,
    TargetKind::Asn,
    TargetKind::Coordinates,
    TargetKind::Address,
    TargetKind::Organisation,
    TargetKind::AbnAcn,
    TargetKind::MacAddress,
    TargetKind::ApiKey,
    TargetKind::CryptoAddress,
    TargetKind::DeviceId,
    TargetKind::Ssid,
    TargetKind::TrackingId,
];

pub const PROBE_VALUE: &str = "huntsman-graph-probe-1.2.3.4@example.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCost {
    Free,
    KeyGated,
    Metered,
    Paid,
    Unknown,
}

impl ModuleCost {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::KeyGated => "key_gated",
            Self::Metered => "metered",
            Self::Paid => "paid",
            Self::Unknown => "unknown",
        }
    }
}

pub trait ModuleMeta {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8 {
        50
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn is_passive(&self) -> bool {
        true
    }
}

pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8 {
        50
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, target: &Target) -> bool;
    fn consumes(&self) -> Vec<TargetKind> {
        consumes_via_probe(self)
    }
    fn produces(&self) -> Vec<EntityKind>;
}

impl<T: Module + ?Sized> ModuleMeta for T {
    fn name(&self) -> &'static str {
        Module::name(self)
    }

    fn priority(&self) -> u8 {
        Module::priority(self)
    }

    fn category(&self) -> ModuleCategory {
        Module::category(self)
    }

    fn cost(&self) -> ModuleCost {
        Module::cost(self)
    }

    fn is_passive(&self) -> bool {
        Module::is_passive(self)
    }
}

#[must_use]
pub fn consumes_via_probe<M: Module + ?Sized>(module: &M) -> Vec<TargetKind> {
    ALL_TARGET_KINDS
        .iter()
        .copied()
        .filter(|kind| module.accepts(&Target::new(*kind, PROBE_VALUE)))
        .collect()
}

#[derive(Debug, Default, Clone)]
pub struct ModuleGraph {
    dispatch_index: BTreeMap<TargetKind, Vec<usize>>,
    convex_dispatch_index: BTreeMap<TargetKind, Vec<usize>>,
    consumer_count: BTreeMap<TargetKind, usize>,
    max_consumer_count: usize,
    producer_index: BTreeMap<EntityKind, Vec<usize>>,
}

fn module_cascade(produces: &[EntityKind], category: ModuleCategory) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let pivotable = produces
        .iter()
        .filter(|kind| TargetKind::from_entity_kind(kind).is_some())
        .count() as f64;
    let base = (pivotable / 4.0).clamp(0.0, 1.0);
    let bonus = match category {
        ModuleCategory::DnsRecon
        | ModuleCategory::Breach
        | ModuleCategory::Search
        | ModuleCategory::Social
        | ModuleCategory::Email
        | ModuleCategory::People => 0.25,
        ModuleCategory::Infrastructure
        | ModuleCategory::Corporate
        | ModuleCategory::Web
        | ModuleCategory::Geo
        | ModuleCategory::Sensor => 0.15,
        ModuleCategory::Threat | ModuleCategory::Phone | ModuleCategory::Other => 0.0,
    };
    (base + bonus).clamp(0.0, 1.0)
}

fn query_value(module: &dyn Module) -> f64 {
    let cost_score = match module.cost() {
        ModuleCost::Free => 1.0,
        ModuleCost::KeyGated | ModuleCost::Metered => 0.6,
        ModuleCost::Paid => 0.1,
        ModuleCost::Unknown => 0.3,
    };
    let passive_score = if module.is_passive() { 1.0 } else { 0.5 };
    passive_score + cost_score + module_cascade(&module.produces(), module.category())
}

impl ModuleGraph {
    #[must_use]
    pub fn build(modules: &[Arc<dyn Module>]) -> Self {
        let mut dispatch_index = BTreeMap::<TargetKind, Vec<usize>>::new();
        let mut consumer_count = BTreeMap::<TargetKind, usize>::new();
        let mut producer_index = BTreeMap::<EntityKind, Vec<usize>>::new();

        for (index, module) in modules.iter().enumerate() {
            let mut seen_consumes = BTreeSet::new();
            for kind in module.consumes() {
                if !seen_consumes.insert(kind) {
                    continue;
                }
                dispatch_index.entry(kind).or_default().push(index);
                *consumer_count.entry(kind).or_insert(0) += 1;
            }
            let mut seen_produces = BTreeSet::new();
            for kind in module.produces() {
                if seen_produces.insert(kind.clone()) {
                    producer_index.entry(kind).or_default().push(index);
                }
            }
        }

        for &kind in ALL_TARGET_KINDS {
            consumer_count.entry(kind).or_insert(0);
            dispatch_index.entry(kind).or_default();
        }

        let max_consumer_count = consumer_count.values().copied().max().unwrap_or(1).max(1);
        let mut convex_dispatch_index = dispatch_index.clone();
        for bucket in convex_dispatch_index.values_mut() {
            bucket.sort_by(|&left, &right| {
                query_value(modules[right].as_ref())
                    .total_cmp(&query_value(modules[left].as_ref()))
                    .then_with(|| modules[right].priority().cmp(&modules[left].priority()))
                    .then_with(|| modules[left].name().cmp(modules[right].name()))
            });
        }

        Self {
            dispatch_index,
            convex_dispatch_index,
            consumer_count,
            max_consumer_count,
            producer_index,
        }
    }

    #[must_use]
    pub fn modules_for(&self, kind: TargetKind) -> &[usize] {
        self.dispatch_index.get(&kind).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn convex_modules_for(&self, kind: TargetKind) -> &[usize] {
        self.convex_dispatch_index
            .get(&kind)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn dispatch_order_for(&self, kind: TargetKind, convex_budget: bool) -> &[usize] {
        if convex_budget {
            self.convex_modules_for(kind)
        } else {
            self.modules_for(kind)
        }
    }

    #[must_use]
    pub fn module_count_for(&self, kind: TargetKind) -> usize {
        self.consumer_count.get(&kind).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn richness_for(&self, kind: TargetKind) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let numerator = self.module_count_for(kind) as f64;
        #[allow(clippy::cast_precision_loss)]
        let denominator = self.max_consumer_count as f64;
        if denominator <= 0.0 {
            0.0
        } else {
            (numerator / denominator).clamp(0.0, 1.0)
        }
    }

    #[must_use]
    pub fn produced_kinds(&self) -> Vec<EntityKind> {
        let mut kinds: Vec<_> = self.producer_index.keys().cloned().collect();
        kinds.sort_by_key(ToString::to_string);
        kinds
    }

    #[must_use]
    pub fn to_summary(&self, modules: &[Arc<dyn Module>]) -> ModuleGraphSummary {
        let mut kinds: Vec<KindNode> = ALL_TARGET_KINDS
            .iter()
            .map(|kind| {
                let mut names: Vec<&'static str> = self
                    .modules_for(*kind)
                    .iter()
                    .filter_map(|&index| modules.get(index).map(|module| module.name()))
                    .collect();
                names.sort_unstable();
                KindNode {
                    kind: kind.canonical_str(),
                    module_count: self.module_count_for(*kind),
                    richness: self.richness_for(*kind),
                    modules: names,
                }
            })
            .collect();
        kinds.sort_by(|left, right| {
            right
                .module_count
                .cmp(&left.module_count)
                .then_with(|| left.kind.cmp(right.kind))
        });

        let edges: Vec<PivotEdge> = modules
            .iter()
            .map(|module| {
                let produces = module.produces();
                let mut pivots_to: Vec<&'static str> = produces
                    .iter()
                    .filter_map(TargetKind::from_entity_kind)
                    .map(TargetKind::canonical_str)
                    .collect();
                pivots_to.sort_unstable();
                pivots_to.dedup();
                PivotEdge {
                    module: module.name(),
                    category: module.category().as_str(),
                    cost: module.cost().as_str(),
                    passive: module.is_passive(),
                    consumes: module
                        .consumes()
                        .into_iter()
                        .map(TargetKind::canonical_str)
                        .collect(),
                    produces: produces.iter().map(ToString::to_string).collect(),
                    pivots_to,
                }
            })
            .collect();

        let mut terminal_kinds: Vec<String> = modules
            .iter()
            .flat_map(|module| module.produces().into_iter())
            .filter(|kind| TargetKind::from_entity_kind(kind).is_none())
            .map(|kind| kind.to_string())
            .collect();
        terminal_kinds.sort_unstable();
        terminal_kinds.dedup();

        ModuleGraphSummary {
            kinds,
            edges,
            terminal_kinds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KindNode {
    pub kind: &'static str,
    pub module_count: usize,
    pub richness: f64,
    pub modules: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PivotEdge {
    pub module: &'static str,
    pub category: &'static str,
    pub cost: &'static str,
    pub passive: bool,
    pub consumes: Vec<&'static str>,
    pub produces: Vec<String>,
    pub pivots_to: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModuleGraphSummary {
    pub kinds: Vec<KindNode>,
    pub edges: Vec<PivotEdge>,
    pub terminal_kinds: Vec<String>,
}

impl ModuleGraphSummary {
    #[must_use]
    pub fn produced_entity_kinds(&self) -> Vec<String> {
        let mut kinds = BTreeSet::new();
        for edge in &self.edges {
            for kind in &edge.produces {
                kinds.insert(kind.clone());
            }
        }
        kinds.into_iter().collect()
    }
}

#[must_use]
pub fn reachable_target_kinds(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
    seeds: &[TargetKind],
) -> BTreeSet<TargetKind> {
    let mut reachable: BTreeSet<TargetKind> = seeds.iter().copied().collect();
    loop {
        let mut added = false;
        let current: Vec<TargetKind> = reachable.iter().copied().collect();
        for kind in current {
            for &index in graph.modules_for(kind) {
                let Some(module) = modules.get(index) else {
                    continue;
                };
                for produced in module.produces() {
                    if let Some(new_kind) = TargetKind::from_entity_kind(&produced) {
                        if reachable.insert(new_kind) {
                            added = true;
                        }
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
    reachable
}

#[must_use]
pub fn reachable_modules(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
    seeds: &[TargetKind],
) -> Vec<usize> {
    let reachable_kinds = reachable_target_kinds(graph, modules, seeds);
    let mut out: Vec<usize> = (0..modules.len())
        .filter(|&index| {
            modules[index]
                .consumes()
                .iter()
                .any(|kind| reachable_kinds.contains(kind))
        })
        .collect();
    out.sort_unstable();
    out
}

#[must_use]
pub fn unreachable_modules<'a>(
    graph: &ModuleGraph,
    modules: &'a [Arc<dyn Module>],
    seeds: &[TargetKind],
) -> Vec<&'a str> {
    let reachable: BTreeSet<usize> = reachable_modules(graph, modules, seeds)
        .into_iter()
        .collect();
    let mut names: Vec<&str> = (0..modules.len())
        .filter(|index| !reachable.contains(index))
        .map(|index| modules[index].name())
        .collect();
    names.sort_unstable();
    names
}

#[must_use]
pub fn coverage_from(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
    seed: TargetKind,
) -> (usize, usize) {
    (
        reachable_modules(graph, modules, &[seed]).len(),
        modules.len(),
    )
}

#[must_use]
pub const fn seed_universe() -> &'static [TargetKind] {
    ALL_TARGET_KINDS
}

#[must_use]
pub const fn human_seed_kinds() -> &'static [TargetKind] {
    &[
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::Domain,
        TargetKind::IpAddress,
        TargetKind::Url,
        TargetKind::Address,
        TargetKind::Coordinates,
        TargetKind::Organisation,
        TargetKind::AbnAcn,
        TargetKind::MacAddress,
    ]
}

/// Returns the number of registered modules when every human seed kind reaches at least one
/// module path through the dependency graph.
///
/// # Errors
///
/// Returns the first human seed kind that cannot reach any module along with the unreachable
/// module names for that seed.
pub fn fully_wired(
    graph: &ModuleGraph,
    modules: &[Arc<dyn Module>],
) -> Result<usize, (TargetKind, Vec<String>)> {
    for &seed in human_seed_kinds() {
        let dead = unreachable_modules(graph, modules, &[seed]);
        if !dead.is_empty() {
            return Err((seed, dead.into_iter().map(ToString::to_string).collect()));
        }
    }
    Ok(modules.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmailToDomain;
    impl Module for EmailToDomain {
        fn name(&self) -> &'static str {
            "email_to_domain"
        }
        fn priority(&self) -> u8 {
            50
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Email)
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Domain]
        }
    }

    struct DomainToIp;
    impl Module for DomainToIp {
        fn name(&self) -> &'static str {
            "domain_to_ip"
        }
        fn priority(&self) -> u8 {
            40
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain | TargetKind::Url)
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::IpAddress]
        }
    }

    struct DuplicateKindModule;
    impl Module for DuplicateKindModule {
        fn name(&self) -> &'static str {
            "duplicate_kind"
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain)
        }
        fn consumes(&self) -> Vec<TargetKind> {
            vec![TargetKind::Domain, TargetKind::Domain]
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::IpAddress, EntityKind::IpAddress]
        }
    }

    struct ValueGatedNoOverride;
    impl Module for ValueGatedNoOverride {
        fn name(&self) -> &'static str {
            "value_gated_no_override"
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain) && target.value.ends_with(".gov.au")
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Organisation]
        }
    }

    struct ValueGatedWithOverride;
    impl Module for ValueGatedWithOverride {
        fn name(&self) -> &'static str {
            "value_gated_with_override"
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain) && target.value.ends_with(".gov.au")
        }
        fn consumes(&self) -> Vec<TargetKind> {
            vec![TargetKind::Domain]
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Organisation]
        }
    }

    struct PersonProducerModule;
    impl Module for PersonProducerModule {
        fn name(&self) -> &'static str {
            "person_producer"
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain)
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Person]
        }
    }

    struct CredentialModule;
    impl Module for CredentialModule {
        fn name(&self) -> &'static str {
            "credential_producer"
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain)
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Credential]
        }
    }

    struct CheapIdentityModule;
    impl Module for CheapIdentityModule {
        fn name(&self) -> &'static str {
            "cheap_identity"
        }
        fn priority(&self) -> u8 {
            10
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::Breach
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain)
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Email]
        }
    }

    struct PaidTerminalModule;
    impl Module for PaidTerminalModule {
        fn name(&self) -> &'static str {
            "paid_terminal"
        }
        fn priority(&self) -> u8 {
            90
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::Threat
        }
        fn cost(&self) -> ModuleCost {
            ModuleCost::Paid
        }
        fn accepts(&self, target: &Target) -> bool {
            matches!(target.kind, TargetKind::Domain)
        }
        fn produces(&self) -> Vec<EntityKind> {
            vec![EntityKind::Coordinates]
        }
    }

    fn registry() -> Vec<Arc<dyn Module>> {
        vec![
            Arc::new(EmailToDomain),
            Arc::new(DomainToIp),
            Arc::new(DomainToIp),
        ]
    }

    #[test]
    fn graph_indexes_consumers_and_producers() {
        let modules = registry();
        let graph = ModuleGraph::build(&modules);
        assert_eq!(graph.modules_for(TargetKind::Email).len(), 1);
        assert_eq!(graph.modules_for(TargetKind::Domain).len(), 2);
        assert_eq!(graph.modules_for(TargetKind::Url).len(), 2);
        let coordinate_modules = graph.modules_for(TargetKind::Coordinates);
        assert!(coordinate_modules.is_empty(), "{coordinate_modules:?}");
        assert_eq!(graph.module_count_for(TargetKind::Domain), 2);
        assert!((graph.richness_for(TargetKind::Domain) - 1.0).abs() < f64::EPSILON);
        assert!(graph.richness_for(TargetKind::Coordinates).abs() < f64::EPSILON);
        assert_eq!(
            graph.produced_kinds(),
            vec![EntityKind::Domain, EntityKind::IpAddress]
        );
    }

    #[test]
    fn repeated_kinds_are_deduped_per_module() {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(DuplicateKindModule)];
        let graph = ModuleGraph::build(&modules);
        assert_eq!(graph.modules_for(TargetKind::Domain), &[0]);
        assert_eq!(graph.module_count_for(TargetKind::Domain), 1);
        assert_eq!(graph.produced_kinds(), vec![EntityKind::IpAddress]);
    }

    #[test]
    fn probe_finds_kind_gates_and_exposes_value_gated_risk() {
        assert_eq!(consumes_via_probe(&EmailToDomain), vec![TargetKind::Email]);
        let kinds = consumes_via_probe(&DomainToIp);
        assert!(kinds.contains(&TargetKind::Domain));
        assert!(kinds.contains(&TargetKind::Url));
        assert!(ValueGatedNoOverride.accepts(&Target::new(TargetKind::Domain, "ato.gov.au")));
        let consumed = consumes_via_probe(&ValueGatedNoOverride);
        assert!(consumed.is_empty(), "{consumed:?}");
        assert_eq!(ValueGatedWithOverride.consumes(), vec![TargetKind::Domain]);
    }

    #[test]
    fn summary_exposes_joinable_edges_and_terminal_kinds() {
        let modules: Vec<Arc<dyn Module>> =
            vec![Arc::new(PersonProducerModule), Arc::new(CredentialModule)];
        let summary = ModuleGraph::build(&modules).to_summary(&modules);
        assert!(
            summary.edges[0]
                .produces
                .iter()
                .any(|kind| kind == "person")
        );
        assert!(summary.edges[0].pivots_to.contains(&"full_name"));
        assert!(
            summary
                .terminal_kinds
                .iter()
                .any(|kind| kind == "credential")
        );
        assert!(
            summary.edges[1].pivots_to.is_empty(),
            "{:?}",
            summary.edges[1].pivots_to
        );
    }

    #[test]
    fn convex_order_reorders_same_membership() {
        let modules: Vec<Arc<dyn Module>> =
            vec![Arc::new(PaidTerminalModule), Arc::new(CheapIdentityModule)];
        let graph = ModuleGraph::build(&modules);
        let plain: Vec<&str> = graph
            .modules_for(TargetKind::Domain)
            .iter()
            .map(|&index| modules[index].name())
            .collect();
        let convex: Vec<&str> = graph
            .convex_modules_for(TargetKind::Domain)
            .iter()
            .map(|&index| modules[index].name())
            .collect();
        assert_eq!(plain, vec!["paid_terminal", "cheap_identity"]);
        assert_eq!(convex, vec!["cheap_identity", "paid_terminal"]);
    }

    #[test]
    fn reachability_reports_transitive_module_coverage() {
        let modules = registry();
        let graph = ModuleGraph::build(&modules);
        let reachable = reachable_target_kinds(&graph, &modules, &[TargetKind::Email]);
        assert!(reachable.contains(&TargetKind::Email));
        assert!(reachable.contains(&TargetKind::Domain));
        assert!(reachable.contains(&TargetKind::IpAddress));
        let module_indexes = reachable_modules(&graph, &modules, &[TargetKind::Email]);
        assert_eq!(module_indexes, vec![0, 1, 2]);
        let unreachable = unreachable_modules(&graph, &modules, &[TargetKind::Email]);
        assert!(unreachable.is_empty(), "{unreachable:?}");
        assert_eq!(coverage_from(&graph, &modules, TargetKind::Email), (3, 3));
        assert_eq!(
            fully_wired(&graph, &modules),
            Err((
                TargetKind::Username,
                vec![
                    "domain_to_ip".to_string(),
                    "domain_to_ip".to_string(),
                    "email_to_domain".to_string()
                ]
            ))
        );
    }
}
