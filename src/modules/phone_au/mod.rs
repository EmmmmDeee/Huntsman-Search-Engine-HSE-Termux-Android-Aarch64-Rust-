//! Offline Australian phone line-type & geographic-region classifier.
//!
//! `phone_intl` resolves an E.164 number to its country (`+61` → Australia) but
//! stops there. This module takes over for AU numbers and decomposes the
//! national number per the ACMA Australian Numbering Plan — a fixed, public,
//! keyless mapping — into:
//!
//!   * **line type** — mobile (`04`), fixed-line geographic (`02/03/07/08`),
//!     freephone (`1800`), local-rate (`1300`/`13`), premium (`190x`) or VoIP
//!     (`05`). Distinguishes a personal mobile from a business freephone from a
//!     residential landline — a people-vs-organisation signal on its own.
//!   * **geographic region** — for a fixed line, the single-digit area code maps
//!     to one of the four AU geographic regions and the state(s)/territory it
//!     spans (`02` → Central East: NSW, ACT; `03` → South East: VIC, TAS;
//!     `07` → North East: QLD; `08` → Central & West: SA, WA, NT). A coarse but
//!     genuine locator for the line's region of allocation.
//!
//! The classification is re-emitted as tags + evidence on the **same canonical
//! `+61` Phone entity** `phone_intl` produces, so the two modules' attributions
//! merge onto one phone (country:AU ⊕ au-region ⊕ line-type) instead of
//! competing. No network, no key, < 1 ms — a pure lookup that is fully
//! deterministic and applies to the majority of Australian phone numbers in
//! breach / stealer / register data.
//!
//! Deliberately conservative: it does **not** emit an `Address`/`Coordinates`
//! entity (an area-code region spans a whole state-group — far too coarse to pin
//! a dwelling, and a fake centroid would risk fabricating co-location), and it
//! does **not** guess a mobile's carrier (number portability makes the allocated
//! carrier an unreliable signal). It reports only what the numbering plan states
//! with certainty.

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "phone_au";

pub struct PhoneAu;

/// A line's type per the AU Numbering Plan. `Display` gives the `line:<slug>`
/// tag value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineType {
    Mobile,
    FixedLine,
    Freephone,
    LocalRate,
    Premium,
    Voip,
    Unknown,
}

impl LineType {
    /// The tag slug (`line:<slug>`).
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::FixedLine => "fixed-line",
            Self::Freephone => "freephone",
            Self::LocalRate => "local-rate",
            Self::Premium => "premium",
            Self::Voip => "voip",
            Self::Unknown => "unknown",
        }
    }

    /// A short human description for evidence.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Mobile => "mobile (Australia-wide)",
            Self::FixedLine => "fixed-line (geographic)",
            Self::Freephone => "freephone / toll-free (non-geographic)",
            Self::LocalRate => "local-rate (non-geographic)",
            Self::Premium => "premium-rate (non-geographic)",
            Self::Voip => "VoIP / digital (non-geographic)",
            Self::Unknown => "unknown AU number",
        }
    }
}

/// The decoded AU number facts. `region`/`states`/`area_code` are `Some` only for
/// a fixed-line geographic number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuLine {
    pub line_type: LineType,
    /// Region slug, e.g. `central-east` (fixed lines only).
    pub region: Option<&'static str>,
    /// Human region name, e.g. `Central East` (fixed lines only).
    pub region_name: Option<&'static str>,
    /// State(s)/territory the region spans, e.g. `NSW, ACT` (fixed lines only).
    pub states: Option<&'static str>,
    /// The leading area-code digit, e.g. `2` (fixed lines only).
    pub area_code: Option<char>,
}

impl AuLine {
    fn simple(line_type: LineType) -> Self {
        Self {
            line_type,
            region: None,
            region_name: None,
            states: None,
            area_code: None,
        }
    }

    fn geographic(area: char) -> Self {
        // (slug, name, states) per the four AU geographic area codes.
        let (region, region_name, states) = match area {
            '2' => ("central-east", "Central East", "NSW, ACT"),
            '3' => ("south-east", "South East", "VIC, TAS"),
            '7' => ("north-east", "North East", "QLD"),
            '8' => ("central-west", "Central and West", "SA, WA, NT"),
            _ => unreachable!("geographic() called with non-area-code digit"),
        };
        Self {
            line_type: LineType::FixedLine,
            region: Some(region),
            region_name: Some(region_name),
            states: Some(states),
            area_code: Some(area),
        }
    }
}

/// Classify an AU **national** number string (digits only, country code `61`
/// already stripped, no leading trunk `0`) per the ACMA Numbering Plan. Returns
/// `None` if it is too short/long to be any valid AU number. Pure — unit-tested.
///
/// Prefix precedence matters: the multi-digit service prefixes (`1800`, `1300`,
/// `190x`) are tested before the single-digit area codes so a `1300…` number is
/// never misread as a `1`-prefixed nothing or a `13` shortcode.
#[must_use]
pub fn classify_au_phone(national: &str) -> Option<AuLine> {
    if national.len() < 6 || national.len() > 10 || !national.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    // Non-geographic service prefixes (longest first).
    if national.starts_with("1800") {
        return Some(AuLine::simple(LineType::Freephone));
    }
    if national.starts_with("1300") {
        return Some(AuLine::simple(LineType::LocalRate));
    }
    if national.starts_with("190") {
        // 1900/1901/1902… premium rate.
        return Some(AuLine::simple(LineType::Premium));
    }
    if national.starts_with("13") {
        // 13 XX XX local-rate shortcode (6 digits).
        return Some(AuLine::simple(LineType::LocalRate));
    }

    // Geographic / mobile / VoIP by leading digit (standard 9-digit national).
    match national.as_bytes()[0] {
        b'4' => Some(AuLine::simple(LineType::Mobile)),
        b'5' => Some(AuLine::simple(LineType::Voip)),
        b'2' | b'3' | b'7' | b'8' => Some(AuLine::geographic(national.as_bytes()[0] as char)),
        _ => Some(AuLine::simple(LineType::Unknown)),
    }
}

/// Reduce a target's phone value to its AU national number (country code and any
/// leading trunk `0` stripped), or `None` if it is not recognisably an
/// Australian number. Accepts the explicit international forms `phone_intl`
/// accepts (`+61…`, `0061…`) AND the AU-local forms `to_e164_au` canonicalises
/// (`04…`, `(02) …`), so a phone seeded in any common shape is covered.
fn au_national(raw: &str) -> Option<String> {
    // International form first (shares `phone_intl`'s honest-attribution gate).
    let intl =
        crate::modules::phone_intl::international_digits(raw).filter(|d| d.starts_with("61"));
    // Else an AU-local form that `to_e164_au` recognises and canonicalises.
    let digits = intl.or_else(|| {
        crate::core::validation::to_e164_au(raw)
            .map(|e| crate::util::str_util::ascii_digits(&e))
            .filter(|d| d.starts_with("61"))
    })?;

    // Strip the `61` country code, then a stray leading trunk `0` if a source
    // wrongly kept it (`+610412…`), leaving the bare national number.
    let national = digits[2..].trim_start_matches('0');
    (national.len() >= 6).then(|| national.to_string())
}

#[async_trait]
impl Module for PhoneAu {
    fn name(&self) -> &'static str {
        "phone_au"
    }

    fn description(&self) -> &'static str {
        "Offline Australian phone line-type & geographic-region classifier"
    }

    fn priority(&self) -> u8 {
        // Just below `phone_intl` (140): the country gate runs first, then this
        // adds AU-specific detail. Still well above any paid carrier lookup.
        138
    }

    fn is_passive(&self) -> bool {
        // Pure local computation — no network.
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Phone
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Phone];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let Some(national) = au_national(&target.value) else {
            return Ok(result);
        };
        let Some(line) = classify_au_phone(&national) else {
            return Ok(result);
        };

        // Re-emit the canonical +61 E.164 phone so this enrichment merges onto
        // the same Phone uid `phone_intl` produces.
        let canonical = format!("+61{national}");
        let mut entity = Entity::new(EntityKind::Phone, &canonical, 0.80, &ctx.scan_id);
        entity.tag("au-phone");
        entity.tag(format!("line:{}", line.line_type.slug()));

        let mut ev = Evidence::new(
            SRC,
            format!("AU {} — {}", line.line_type.label(), canonical),
        )
        .with_attr("line_type", line.line_type.slug())
        .with_attr("numbering_plan", "ACMA");

        if let (Some(region), Some(region_name), Some(states), Some(area)) =
            (line.region, line.region_name, line.states, line.area_code)
        {
            entity.tag(format!("au-region:{region}"));
            entity.tag("geographic");
            ev = ev
                .with_attr("au_region", region_name)
                .with_attr("au_region_states", states)
                .with_attr("area_code", format!("0{area}"));
        } else if line.line_type == LineType::Mobile {
            entity.tag("mobile");
            // Honest about portability: the number is geographic-independent and
            // the current carrier can't be inferred offline.
            ev = ev.with_attr(
                "note",
                "mobile is non-geographic; carrier not inferable offline",
            );
        } else if line.line_type != LineType::Unknown {
            // Freephone / local-rate / premium / VoIP are organisation-leaning,
            // non-geographic service numbers — a useful people-vs-org signal.
            entity.tag("non-geographic");
            ev = ev.with_attr(
                "note",
                "non-geographic service number (not a residential line)",
            );
        }

        entity.add_evidence(ev);
        result.push(entity);
        Ok(result)
    }
}
