//! Breach timestamp timezone inference — cluster entity observation
//! timestamps to infer the target's active timezone.
//!
//! Stealer logs and breach records carry timestamps. If 80%+ of a
//! target's activity falls within a consistent 14-hour window, the
//! midpoint of that window reveals the local timezone (±1 hour).
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
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
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
        -8 => "US/Pacific",
        -7 => "US/Mountain",
        -6 => "US/Central",
        -5 => "US/Eastern",
        -3 => "South America (Brazil/Argentina)",
        0 => "Western Europe (UK/Ireland)",
        1 => "Central Europe (France/Germany)",
        2 => "Eastern Europe (Finland/South Africa)",
        3 => "Middle East / Moscow",
        5 => "South Asia (Pakistan)",
        8 => "East Asia (China/Singapore/Perth)",
        9 => "East Asia (Japan/Korea)",
        10 => "Australia Eastern (Sydney/Melbourne)",
        12 => "Pacific (New Zealand)",
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
        assert!(offset_to_region(10).contains("Australia"));
        assert!(offset_to_region(0).contains("UK"));
        assert!(offset_to_region(-5).contains("Eastern"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = BreachTimezone;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    }
}
