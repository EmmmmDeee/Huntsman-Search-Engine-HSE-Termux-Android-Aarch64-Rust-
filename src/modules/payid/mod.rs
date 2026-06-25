//! PayID OSINT enrichment — recognise NPP PayID-eligible identifiers as
//! account-holder-name pivots.
//!
//! PayID (Australia's New Payments Platform) maps a memorable identifier — an
//! email address, a mobile/phone number, an ABN, or an Organisation ID — to a
//! bank account. Its OSINT value is the **confirm-payee** step: initiating an
//! NPP payment to a PayID returns the registered **account-holder name**, so a
//! single phone or email can pivot to a real legal name.
//!
//! There is **no public PayID resolution API**, so this module is deliberately
//! offline: it never contacts a bank/NPP endpoint and never auto-resolves a name
//! from a phone/email (that name only appears inside the operator's own banking
//! app, on a payment they initiate themselves). It performs the legitimate,
//! structural tradecraft instead —
//!   * recognise which discovered identifiers are PayID-eligible and of what
//!     type, normalise them to their canonical PayID form, and annotate them as
//!     confirm-payee pivots with the manual step the operator can take; and
//!   * for an **ABN** PayID, surface that the holder name is **lawfully and
//!     automatically** resolvable from the public business register (which the
//!     `abn_lookup` / `opencorporates` modules already fetch) — the one PayID
//!     type whose name does not require a banking app.
//!
//! `payid` is an [enrichment-only source](crate::core::entity::ENRICHMENT_ONLY_SOURCES):
//! eligibility is a property of the identifier's *shape*, not independent
//! corroboration that it belongs to the subject, so it annotates without ever
//! lifting the identifier's confidence tier.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "payid";

/// Annotation confidence — deliberately LOW. PayID-eligibility is a structural
/// fact about the identifier, not evidence it belongs to the subject; because
/// `payid` is enrichment-only it never raises the merged entity's tier, and the
/// floor only matters for an identifier this module is the first to surface.
const PAYID_CONF: f64 = 0.30;

/// PayID enrichment module. See the module docs for the scope/boundary.
pub struct PayId;

#[async_trait]
impl Module for PayId {
    fn name(&self) -> &'static str {
        "payid"
    }

    fn description(&self) -> &'static str {
        "Recognise PayID-eligible identifiers (email/phone/ABN) as NPP confirm-payee name pivots; the ABN PayID resolves to a name via the public register"
    }

    fn priority(&self) -> u8 {
        80
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Phone | TargetKind::AbnAcn
        )
    }

    fn category(&self) -> ModuleCategory {
        // People-centric enrichment: a payment identifier pivots to the
        // registered account-holder NAME (ATT&CK T1589.003 / T1591.004 via the
        // category default).
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Phone, EntityKind::AbnAcn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some(p) = recognise(target) else {
            return Ok(result);
        };

        // Re-emit the identifier annotated as a PayID pivot. It merges into the
        // existing identifier (same UID), contributing the tags + guidance but —
        // as an enrichment-only source — no corroboration.
        let mut e = Entity::new(p.kind, &target.value, PAYID_CONF, &ctx.scan_id);
        e.tag("payid");
        e.tag(format!("payid:{}", p.kind_label));

        let mut ev = Evidence::new(
            SRC,
            format!(
                "PayID-eligible {} — an NPP confirm-payee lookup reveals the registered account-holder name",
                p.kind_label
            ),
        )
        .with_attr("payid", &p.canonical)
        .with_attr("payid_type", p.kind_label)
        .with_attr("pivot", p.guidance);

        if p.registry_resolvable {
            // The ABN PayID's holder name is the registered entity name — a
            // lawful, automated resolution the ABN modules already perform.
            e.tag("payid:registry-resolvable");
            ev = ev.with_attr(
                "name_resolution",
                "public register — the PayID holder name equals the ABN's registered entity name",
            );
        }

        e.add_evidence(ev);
        result.push(e);
        Ok(result)
    }
}

/// A recognised PayID and how its holder name can be resolved.
struct Recognised {
    kind: EntityKind,
    /// Canonical NPP form of the PayID (lower-cased email, `+61…` E.164 phone,
    /// or the 11 ABN digits).
    canonical: String,
    /// Stable type label used in tags/attributes (`email` / `phone` / `abn`).
    kind_label: &'static str,
    /// The legitimate step that reveals the holder name.
    guidance: &'static str,
    /// True when the name is resolvable from a public register (ABN), false when
    /// it only appears inside a banking app's confirm-payee step (email/phone).
    registry_resolvable: bool,
}

/// Recognise a PayID-eligible identifier and its canonical NPP form, or `None`
/// when the value is not a valid PayID of its kind.
fn recognise(target: &Target) -> Option<Recognised> {
    match target.kind {
        // An email PayID is the address itself — require a `local@domain.tld`
        // shape so a fragment (`@gmail`, `matt@`) is not treated as a PayID.
        TargetKind::Email => {
            let v = target.value.trim();
            let (local, domain) = v.split_once('@')?;
            if local.is_empty() || !domain.contains('.') {
                return None;
            }
            Some(Recognised {
                kind: EntityKind::Email,
                canonical: v.to_ascii_lowercase(),
                kind_label: "email",
                guidance: "Initiate (then cancel before confirming) an NPP payment to this \
                           address in your own banking app to read the registered \
                           account-holder name.",
                registry_resolvable: false,
            })
        }
        // A phone PayID is the E.164 form of an AU number; reuse the shared
        // normaliser (returns `None` for anything that isn't a valid AU number).
        TargetKind::Phone => {
            let e164 = crate::util::address_au::normalise_phone(&target.value)?;
            Some(Recognised {
                kind: EntityKind::Phone,
                canonical: e164,
                kind_label: "phone",
                guidance: "Initiate (then cancel before confirming) an NPP payment to this \
                           number in your own banking app to read the registered \
                           account-holder name.",
                registry_resolvable: false,
            })
        }
        // An ABN PayID's name is the registered entity name — checksum-validate
        // the ABN and resolve via the public register, no banking app needed.
        TargetKind::AbnAcn => {
            if !crate::util::abn::is_valid_abn(&target.value) {
                return None;
            }
            let digits: String = target.value.chars().filter(char::is_ascii_digit).collect();
            Some(Recognised {
                kind: EntityKind::AbnAcn,
                canonical: digits,
                kind_label: "abn",
                guidance: "The PayID holder name equals the ABN's registered entity name — \
                           resolve it from the ABR / business register (no banking app needed).",
                registry_resolvable: true,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
