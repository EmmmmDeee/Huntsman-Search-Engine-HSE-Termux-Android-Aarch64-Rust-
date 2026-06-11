//! Breach timestamp timezone inference — cluster entity observation
//! timestamps to infer the target's active timezone.
//!
//! Stealer logs and breach records carry timestamps. If 80%+ of a
//! target's activity falls within a consistent 14-hour window, the
//! midpoint of that window reveals the local timezone (±1 hour).
//!
//! **Australia-specific notes:**
//!   - UTC+10 (AEST) uniquely identifies Queensland: QLD is the only major
//!     AU population centre that does NOT observe daylight saving. A persistent
//!     UTC+10 cluster is a strong signal for QLD residency.
//!   - UTC+11 (AEDT) indicates NSW/VIC/TAS/ACT in summer (Oct–Apr). Absent
//!     DST switching, a UTC+11 cluster implies non-QLD eastern AU.
//!   - UTC+9.5 (ACST) → SA/NT. UTC+8 → WA.
//!
//! No network calls. Operates on evidence attributes already attached
//! to entities. Priority 7 — runs late so other modules have produced
//! timestamped evidence first.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "breach_timezone";
const MIN_TIMESTAMPS: usize = 5;
const MIN_CONCENTRATION: f64 = 0.70;

pub struct BreachTimezone;

#[async_trait]
impl Module for BreachTimezone {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Infer timezone from breach/stealer timestamp clustering"
    }
    fn priority(&self) -> u8 {
        7
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::Phone
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let hours = extract_hours_from_value(&target.value);
        if hours.len() < MIN_TIMESTAMPS {
            return Ok(result);
        }

        if let Some(tz) = infer_timezone(&hours) {
            let mut e = Entity::new(EntityKind::Address, tz.region, tz.confidence, &ctx.scan_id);
            e.tag("geoint");
            e.tag("coarse");
            e.tag("timezone-inferred");
            // AU-specific tagging: UTC+10 → QLD (no DST), UTC+11 → NSW/VIC/ACT.
            // Shared offset→region mapping in `util::geo` (see [`au_utc_offset_tags`]).
            for &tag in crate::util::geo::au_utc_offset_tags(tz.utc_offset) {
                e.tag(tag);
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Activity clustering suggests UTC{:+} ({})",
                        tz.utc_offset, tz.region
                    ),
                )
                .with_attr("utc_offset", tz.utc_offset.to_string())
                .with_attr("sample_count", hours.len().to_string())
                .with_attr("concentration", format!("{:.0}%", tz.concentration * 100.0)),
            );
            result.push(e);
        }

        Ok(result)
    }
}

struct TimezoneInference {
    utc_offset: i32,
    region: &'static str,
    confidence: f64,
    concentration: f64,
}

fn extract_hours_from_value(value: &str) -> Vec<u32> {
    let mut hours = Vec::new();
    let digits = crate::util::str_util::ascii_digits(value);
    // Extract plausible unix timestamps (10-digit sequences) from the value
    if digits.len() >= 10 {
        for chunk in digits.as_bytes().windows(10) {
            if let Ok(s) = std::str::from_utf8(chunk)
                && let Ok(ts) = s.parse::<u64>()
                && (1_000_000_000..2_000_000_000).contains(&ts)
            {
                let hour = ((ts % 86400) / 3600) as u32;
                hours.push(hour);
            }
        }
    }
    hours
}

fn infer_timezone(hours: &[u32]) -> Option<TimezoneInference> {
    if hours.len() < MIN_TIMESTAMPS {
        return None;
    }

    let mut histogram = [0u32; 24];
    for &h in hours {
        histogram[h as usize % 24] += 1;
    }
    let total = hours.len() as f64;

    let mut best_offset: i32 = 0;
    let mut best_count: u32 = 0;

    // Slide a 14-hour window and find the offset where most activity
    // falls between 08:00-22:00 local time
    for offset in -12_i32..=12 {
        let mut count = 0u32;
        for local_hour in 8_i32..22 {
            let utc_hour = (local_hour - offset).rem_euclid(24) as usize;
            count += histogram[utc_hour];
        }
        if count > best_count {
            best_count = count;
            best_offset = offset;
        }
    }

    let concentration = best_count as f64 / total;
    if concentration < MIN_CONCENTRATION {
        return None;
    }

    let confidence = 0.35 + (concentration - MIN_CONCENTRATION) * 0.5;
    let region = offset_to_region(best_offset);

    Some(TimezoneInference {
        utc_offset: best_offset,
        region,
        confidence: confidence.min(0.60),
        concentration,
    })
}

fn offset_to_region(offset: i32) -> &'static str {
    match offset {
        -12 => "UTC-12 (Baker / Howland Islands)",
        -11 => "Pacific/Niue",
        -10 => "US/Hawaii",
        -9 => "US/Alaska",
        -8 => "US/Pacific",
        -7 => "US/Mountain",
        -6 => "US/Central",
        -5 => "US/Eastern",
        -4 => "Atlantic (Canada / Venezuela)",
        -3 => "South America (Brazil/Argentina)",
        -2 => "Mid-Atlantic",
        -1 => "Azores",
        0 => "Western Europe (UK/Ireland)",
        1 => "Central Europe (France/Germany/Netherlands)",
        2 => "Eastern Europe (Finland/Greece/South Africa)",
        3 => "Middle East / Moscow / Kenya",
        4 => "Gulf / UAE / Mauritius",
        5 => "South Asia (Pakistan/Uzbekistan)",
        6 => "Bangladesh / Kazakhstan",
        7 => "SE Asia (Vietnam/Thailand/Indonesia West)",
        8 => "East Asia (China/Singapore/Taiwan) / Australia/WA",
        9 => "East Asia (Japan/Korea)",
        10 => "Australia/QLD (AEST — no daylight saving)",
        11 => "Australia Eastern Daylight (NSW/VIC/ACT/TAS summer) / Solomon Is.",
        12 => "Pacific (New Zealand / Fiji)",
        _ => "Unknown timezone region",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_us_eastern() {
        // Activity at UTC hours 13-23 = 08:00-18:00 at UTC-5 (US Eastern)
        let hours: Vec<u32> = vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
        let tz = infer_timezone(&hours).unwrap();
        assert_eq!(tz.utc_offset, -5);
        assert!(tz.region.contains("Eastern"));
    }

    #[test]
    fn too_few_timestamps_returns_none() {
        let hours = vec![10, 11, 12];
        assert!(infer_timezone(&hours).is_none());
    }

    #[test]
    fn uniform_distribution_returns_none() {
        // Activity evenly spread = no timezone signal
        let hours: Vec<u32> = (0..24).collect();
        assert!(infer_timezone(&hours).is_none());
    }

    #[test]
    fn offset_to_region_coverage() {
        assert!(offset_to_region(10).contains("QLD"), "UTC+10 must name QLD");
        assert!(offset_to_region(11).contains("NSW"), "UTC+11 must name NSW");
        assert!(offset_to_region(0).contains("UK"));
        assert!(offset_to_region(-5).contains("Eastern"));
    }

    #[test]
    fn histogram_aest_utc10() {
        // Queensland AEST: activity at UTC hours 22-11 = 08:00-21:00 at UTC+10
        let hours: Vec<u32> = vec![22, 23, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let tz = infer_timezone(&hours).unwrap();
        assert_eq!(tz.utc_offset, 10, "should infer UTC+10 (AEST/QLD)");
        assert!(tz.region.contains("QLD"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = BreachTimezone;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    }
}
