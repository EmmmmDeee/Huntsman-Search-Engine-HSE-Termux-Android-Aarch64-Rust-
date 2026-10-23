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
        // Every kind but `FullName` names an entity kind, so its text comes from the one table
        // `EntityKind::as_str` keeps. `from_entity_kind` pairs the two enums.
        match self {
            Self::FullName => "full_name",
            Self::Email => EntityKind::Email.as_str(),
            Self::Username => EntityKind::Username.as_str(),
            Self::Phone => EntityKind::Phone.as_str(),
            Self::IpAddress => EntityKind::IpAddress.as_str(),
            Self::Domain => EntityKind::Domain.as_str(),
            Self::Url => EntityKind::Url.as_str(),
            Self::Asn => EntityKind::Asn.as_str(),
            Self::Coordinates => EntityKind::Coordinates.as_str(),
            Self::Address => EntityKind::Address.as_str(),
            Self::Organisation => EntityKind::Organisation.as_str(),
            Self::AbnAcn => EntityKind::AbnAcn.as_str(),
            Self::MacAddress => EntityKind::MacAddress.as_str(),
            Self::ApiKey => EntityKind::ApiKey.as_str(),
            Self::CryptoAddress => EntityKind::CryptoAddress.as_str(),
            Self::DeviceId => EntityKind::DeviceId.as_str(),
            Self::Ssid => EntityKind::Ssid.as_str(),
            Self::TrackingId => EntityKind::TrackingId.as_str(),
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
            EntityKind::Credential
            | EntityKind::Document
            | EntityKind::Netblock
            | EntityKind::Other => None,
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

        for (index, module) in modules.iter().enumerate() {
            let mut seen_consumes = BTreeSet::new();
            for kind in module.consumes() {
                if !seen_consumes.insert(kind) {
                    continue;
                }
                dispatch_index.entry(kind).or_default().push(index);
            }
        }

        for &kind in ALL_TARGET_KINDS {
            dispatch_index.entry(kind).or_default();
        }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kind_names_are_the_pinned_wire_names() {
        // Planner, gap and benchmark outputs carry these names, so a change to one is a change to
        // the output format.
        let pinned = [
            (TargetKind::Email, "email"),
            (TargetKind::Username, "username"),
            (TargetKind::Phone, "phone"),
            (TargetKind::FullName, "full_name"),
            (TargetKind::IpAddress, "ip_address"),
            (TargetKind::Domain, "domain"),
            (TargetKind::Url, "url"),
            (TargetKind::Asn, "asn"),
            (TargetKind::Coordinates, "coordinates"),
            (TargetKind::Address, "address"),
            (TargetKind::Organisation, "organisation"),
            (TargetKind::AbnAcn, "abn_acn"),
            (TargetKind::MacAddress, "mac_address"),
            (TargetKind::ApiKey, "api_key"),
            (TargetKind::CryptoAddress, "crypto_address"),
            (TargetKind::DeviceId, "device_id"),
            (TargetKind::Ssid, "ssid"),
            (TargetKind::TrackingId, "tracking_id"),
        ];
        for (kind, name) in pinned {
            assert_eq!(kind.canonical_str(), name, "{kind:?}");
        }
    }

    #[test]
    fn target_kinds_name_the_entity_kind_they_come_from() {
        for kind in [
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Asn,
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::MacAddress,
            EntityKind::ApiKey,
            EntityKind::CryptoAddress,
            EntityKind::DeviceId,
            EntityKind::Ssid,
            EntityKind::TrackingId,
        ] {
            let target = TargetKind::from_entity_kind(&kind).expect("a target kind");
            assert_eq!(target.canonical_str(), kind.as_str(), "{kind:?}");
        }
    }

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
    }

    #[test]
    fn repeated_kinds_are_deduped_per_module() {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(DuplicateKindModule)];
        let graph = ModuleGraph::build(&modules);
        assert_eq!(graph.modules_for(TargetKind::Domain), &[0]);
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
}
