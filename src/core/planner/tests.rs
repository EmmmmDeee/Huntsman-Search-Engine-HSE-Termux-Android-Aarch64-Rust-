use super::*;
use crate::core::entity::{EntityKind, Evidence};
use crate::core::error::Result;
use crate::core::module::{ModuleContext, ModuleResult};
use crate::core::scan::Target;

/// A minimal in-test module: declares fixed accepted kinds, ATT&CK techniques,
/// cost, and passivity. `process` is a no-op — the planner only reads metadata.
struct MockMod {
    name: &'static str,
    kinds: Vec<TargetKind>,
    techs: &'static [&'static str],
    cost: ModuleCost,
    passive: bool,
}

#[async_trait::async_trait]
impl Module for MockMod {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, t: &Target) -> bool {
        self.kinds.contains(&t.kind)
    }
    fn consumes(&self) -> Vec<TargetKind> {
        self.kinds.clone()
    }
    fn cost(&self) -> ModuleCost {
        self.cost
    }
    fn is_passive(&self) -> bool {
        self.passive
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        self.techs
    }
    async fn process(&self, _t: &Target, _c: &ModuleContext) -> Result<ModuleResult> {
        Ok(ModuleResult::new())
    }
}

fn m(
    name: &'static str,
    kinds: &[TargetKind],
    techs: &'static [&'static str],
    cost: ModuleCost,
    passive: bool,
) -> Arc<dyn Module> {
    Arc::new(MockMod {
        name,
        kinds: kinds.to_vec(),
        techs,
        cost,
        passive,
    })
}

/// An entity whose evidence source is `source` (a non-registry name contributes
/// no coverage, so every catalogue technique is a gap — the clean test bed).
fn ent(kind: EntityKind, val: &str, source: &str) -> Entity {
    let mut e = Entity::new(kind, val, 0.8, "scan-test");
    e.add_evidence(Evidence::new(source, "found"));
    e
}

#[test]
fn gap_becomes_actionable_when_module_and_held_entity_exist() {
    let entities = [ent(EntityKind::Email, "a@b.com", "seed")];
    let mods = [m(
        "m_email",
        &[TargetKind::Email],
        &["T1589.002"],
        ModuleCost::Free,
        true,
    )];
    let p = plan(&entities, &mods);

    // T1589.002 (Email Addresses) is a gap (seed source contributes no coverage)
    // and the held Email makes it actionable via m_email.
    assert_eq!(p.actions.len(), 1);
    let a = &p.actions[0];
    assert_eq!(a.module, "m_email");
    assert_eq!(a.target_kind, TargetKind::Email);
    assert_eq!(a.held_targets, 1);
    assert!(a.closes.iter().any(|t| t.id == "T1589.002"));
    // A closable gap is not reported as unclosable.
    assert!(!p.unclosable.iter().any(|t| t.id == "T1589.002"));
}

#[test]
fn closing_more_gaps_outranks_a_cheaper_single_gap_action() {
    let entities = [ent(EntityKind::Email, "a@b.com", "seed")];
    let mods = [
        // Free + passive but closes only ONE gap.
        m(
            "m_one",
            &[TargetKind::Email],
            &["T1589.002"],
            ModuleCost::Free,
            true,
        ),
        // Paid, non-passive but closes TWO gaps — gap count dominates.
        m(
            "m_two",
            &[TargetKind::Email],
            &["T1589.002", "T1589.003"],
            ModuleCost::Paid,
            false,
        ),
    ];
    let p = plan(&entities, &mods);
    assert_eq!(p.actions[0].module, "m_two", "more gaps closed ranks first");
    assert_eq!(p.actions[0].closes.len(), 2);
}

#[test]
fn among_equal_gap_actions_cheaper_and_passive_ranks_higher() {
    let entities = [ent(EntityKind::Email, "a@b.com", "seed")];
    let mods = [
        m(
            "z_paid",
            &[TargetKind::Email],
            &["T1589.002"],
            ModuleCost::Paid,
            false,
        ),
        m(
            "a_free",
            &[TargetKind::Email],
            &["T1589.002"],
            ModuleCost::Free,
            true,
        ),
    ];
    let p = plan(&entities, &mods);
    // Same gaps + held count; free/passive wins on the economy tie-break despite
    // "z_paid" sorting first alphabetically.
    assert_eq!(p.actions[0].module, "a_free");
}

#[test]
fn credential_and_password_entities_are_never_tasked() {
    // Holding a leaked secret must never become collection tasking — those kinds
    // are not scannable open-source targets. Only the Email is actionable.
    let entities = [
        ent(EntityKind::Password, "hunter2", "leak"),
        ent(EntityKind::Credential, "user:pass", "leak"),
        ent(EntityKind::Email, "a@b.com", "seed"),
    ];
    let mods = [m(
        "m_email",
        &[TargetKind::Email],
        &["T1589.002"],
        ModuleCost::Free,
        true,
    )];
    let p = plan(&entities, &mods);
    assert_eq!(p.actions.len(), 1);
    assert_eq!(p.actions[0].target_kind, TargetKind::Email);
    assert_eq!(p.actions[0].held_targets, 1);
}

#[test]
fn distinct_values_drive_held_target_count() {
    let entities = [
        ent(EntityKind::Email, "a@b.com", "seed"),
        ent(EntityKind::Email, "c@d.com", "seed"),
        ent(EntityKind::Email, "a@b.com", "seed2"), // duplicate value → not double-counted
    ];
    let mods = [m(
        "m_email",
        &[TargetKind::Email],
        &["T1589.002"],
        ModuleCost::Free,
        true,
    )];
    let p = plan(&entities, &mods);
    assert_eq!(p.actions[0].held_targets, 2, "two distinct email values");
}

#[test]
fn gap_with_no_capable_module_is_unclosable() {
    let entities = [ent(EntityKind::Email, "a@b.com", "seed")];
    // Module closes T1589.002 only; every other Recon technique is unreachable
    // from the held Email.
    let mods = [m(
        "m_email",
        &[TargetKind::Email],
        &["T1589.002"],
        ModuleCost::Free,
        true,
    )];
    let p = plan(&entities, &mods);
    assert!(!p.unclosable.iter().any(|t| t.id == "T1589.002"));
    assert!(
        !p.unclosable.is_empty(),
        "most of the catalogue is unreachable from a lone email"
    );
    // covered + gaps partition the catalogue; unclosable ⊆ gaps.
    for u in &p.unclosable {
        assert!(p.gaps.iter().any(|g| g.id == u.id));
    }
}

#[test]
fn no_actions_when_nothing_held_is_scannable() {
    let entities = [ent(EntityKind::Password, "hunter2", "leak")];
    let mods = [m(
        "m_email",
        &[TargetKind::Email],
        &["T1589.002"],
        ModuleCost::Free,
        true,
    )];
    let p = plan(&entities, &mods);
    assert!(p.actions.is_empty());
    let brief = render_briefing(&p, 5);
    assert!(brief.contains("no actionable collection"));
}

#[test]
fn plan_is_deterministic() {
    let entities = [
        ent(EntityKind::Email, "a@b.com", "seed"),
        ent(EntityKind::Domain, "b.com", "seed"),
    ];
    let mods = [
        m(
            "m_email",
            &[TargetKind::Email],
            &["T1589.002"],
            ModuleCost::Free,
            true,
        ),
        m(
            "m_domain",
            &[TargetKind::Domain],
            &["T1589.003"],
            ModuleCost::KeyGated,
            false,
        ),
    ];
    let first: Vec<_> = plan(&entities, &mods)
        .actions
        .iter()
        .map(|a| (a.module, a.target_kind))
        .collect();
    let second: Vec<_> = plan(&entities, &mods)
        .actions
        .iter()
        .map(|a| (a.module, a.target_kind))
        .collect();
    assert_eq!(first, second);
}

#[test]
fn briefing_names_the_action_and_technique() {
    let entities = [ent(EntityKind::Email, "a@b.com", "seed")];
    let mods = [m(
        "m_email",
        &[TargetKind::Email],
        &["T1589.002"],
        ModuleCost::Free,
        true,
    )];
    let brief = render_briefing(&plan(&entities, &mods), 5);
    assert!(brief.contains("m_email"));
    assert!(brief.contains("T1589.002"));
    assert!(brief.contains("email"));
}
