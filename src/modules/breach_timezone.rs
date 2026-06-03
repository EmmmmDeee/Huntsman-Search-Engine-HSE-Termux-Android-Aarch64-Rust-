//! Breach timestamp timezone inference — cluster entity observation
//! timestamps to infer the target's active timezone.
//!
//! Stealer logs and breach records carry timestamps. If a target's activity
//! clusters in a consistent ~14-hour "awake" window — *significantly more than
//! the ~58% any 14-hour window catches by chance* — the midpoint of that window
//! reveals the local timezone (±1 hour). The significance test (a Wilson lower
//! bound on the concentration vs. the chance baseline) is what keeps a few
//! random login times from manufacturing a spurious timezone.
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
use crate::util::stats::{wilson_lower_bound, Z_95};

const SRC: &str = "breach_timezone";
const MIN_TIMESTAMPS: usize = 5;
/// Local "awake" window `[WAKE_START, WAKE_END)` (hours) where a real
/// timezone's activity is expected to concentrate.
const WAKE_START: i32 = 8;
const WAKE_END: i32 = 22;
/// Width of the awake window (hours). A window this wide captures
/// `WINDOW_HOURS / 24` of *any* activity by pure chance.
const WINDOW_HOURS: i32 = WAKE_END - WAKE_START;
/// Chance baseline — the fraction of uniformly-random activity that falls in
/// any fixed `WINDOW_HOURS`-wide window. The inferred concentration must clear
/// this (with confidence) to be signal rather than noise.
const CHANCE_BASELINE: f64 = WINDOW_HOURS as f64 / 24.0;

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

    // Slide the awake-hours window and find the offset where most activity
    // falls between WAKE_START and WAKE_END local time.
    for offset in -12_i32..=12 {
        let mut count = 0u32;
        for local_hour in WAKE_START..WAKE_END {
            let utc_hour = (local_hour - offset).rem_euclid(24) as usize;
            count += histogram[utc_hour];
        }
        if count > best_count {
            best_count = count;
            best_offset = offset;
        }
    }

    let concentration = best_count as f64 / total;
    // The selected offset is the argmax over 25 candidate windows, so its raw
    // concentration is a max-statistic that sits above CHANCE_BASELINE even for
    // random activity (a WINDOW_HOURS-wide window holds that fraction of *any*
    // activity). Require the 95% Wilson lower bound on the concentration to
    // clear the baseline: only then are we confident the activity is genuinely
    // more clustered than randomness — not just lucky over a handful of
    // timestamps. This is what stops random login times manufacturing a
    // timezone (a 4/5 = 0.80 sample bounds to ≈0.38, well under chance).
    let lower_bound = wilson_lower_bound(u64::from(best_count), hours.len() as u64, Z_95);
    if lower_bound <= CHANCE_BASELINE {
        return None;
    }

    // Confidence scales with how far the sample-size-adjusted lower bound clears
    // chance, mapped into this module's [0.35, 0.60] envelope.
    let excess = (lower_bound - CHANCE_BASELINE) / (1.0 - CHANCE_BASELINE);
    let confidence = (0.35 + excess * 0.25).min(0.60);
    let region = offset_to_region(best_offset);

    Some(TimezoneInference {
        utc_offset: best_offset,
        region,
        confidence,
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
    fn small_noisy_sample_does_not_manufacture_a_timezone() {
        // 5 timestamps with 4 in one offset's window is a raw concentration of
        // 0.80 — which the old fixed-threshold gate (>=0.70) accepted. But 4/5
        // is far too few to beat the ~58% any 14-hour window catches by chance:
        // its Wilson lower bound (~0.38) is below the baseline, so no inference.
        let hours = vec![14, 15, 16, 17, 3];
        assert!(
            infer_timezone(&hours).is_none(),
            "a noisy 4/5 sample must not infer a timezone"
        );
    }

    #[test]
    fn strong_large_sample_clears_chance_baseline() {
        // 20 timestamps tightly inside the US-Eastern awake window: a large,
        // genuinely-concentrated sample whose lower bound clears chance.
        let hours: Vec<u32> = (0..20).map(|i| 13 + (i % 10)).collect(); // UTC 13-22
        let tz = infer_timezone(&hours).expect("strong concentration should infer");
        assert!(tz.confidence >= 0.35 && tz.confidence <= 0.60);
        assert!(tz.region.contains("Eastern") || tz.region.contains("Central"));
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
