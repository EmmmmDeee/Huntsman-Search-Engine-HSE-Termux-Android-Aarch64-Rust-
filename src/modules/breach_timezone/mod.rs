//! Breach timestamp timezone inference — cluster entity observation
//! timestamps to infer the target's active timezone.
//!
//! Stealer logs and breach records carry timestamps. If 70%+ of a
//! target's activity falls within a consistent 14-hour window, the
//! midpoint of that window reveals the local timezone (±1 hour).
//!
//! No network calls. Operates on evidence attributes already attached
//! to entities. Priority 7 — runs late so other modules have produced
//! timestamped evidence first.

use async_trait::async_trait;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "breach_timezone";
const MIN_TIMESTAMPS: usize = 5;
const MIN_CONCENTRATION: f64 = confidence::HIGH_PLUS;

pub struct BreachTimezone;

#[async_trait]
impl Module for BreachTimezone {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Timezone triangulation — infers a target's timezone from clustering of breach/stealer timestamps"
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
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Coordinates];
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
            e.tag(crate::core::tags::COARSE);
            e.tag("timezone-inferred");
            // Tag AU timezones so AU-056 jurisdiction cross-check can use them.
            match tz.utc_offset {
                10 | 11 => {
                    e.tag("country:AU");
                    e.tag("au-state:AU");
                }
                8 if tz.region.contains("Perth") => {
                    e.tag("country:AU");
                    e.tag("au-state:WA");
                }
                9 if tz.region.contains("Darwin") => {
                    e.tag("country:AU");
                    e.tag("au-state:NT");
                }
                12 if tz.region.contains("New Zealand") => {
                    e.tag("country:NZ");
                }
                _ => {}
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
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(tz.region) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    tz.confidence - 0.10,
                    &ctx.scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("timezone-inferred");
                c.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Geocode of timezone-inferred region '{}'", tz.region),
                    )
                    .with_attr("utc_offset", tz.utc_offset.to_string()),
                );
                result.push(c);
            }
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
    // Each 10-digit window that parses as a plausible unix timestamp
    // (2001–2033) is reduced to its UTC hour-of-day. `windows(10)` on a
    // shorter digit string yields nothing, so no length guard is needed.
    crate::util::str_util::ascii_digits(value)
        .as_bytes()
        .windows(10)
        .filter_map(|chunk| {
            let ts = std::str::from_utf8(chunk).ok()?.parse::<u64>().ok()?;
            (1_000_000_000..2_000_000_000)
                .contains(&ts)
                .then_some(((ts % 86400) / 3600) as u32)
        })
        .collect()
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

    // Slide a 14-hour window; first-wins on ties (equiv. to original `>`).
    let (best_offset, best_count) = (-12_i32..=12)
        .map(|offset| {
            let count: u32 = (8_i32..22)
                .map(|h| histogram[(h - offset).rem_euclid(24) as usize])
                .sum();
            (offset, count)
        })
        .fold((0_i32, 0_u32), |(best_off, best_cnt), (off, cnt)| {
            if cnt > best_cnt {
                (off, cnt)
            } else {
                (best_off, best_cnt)
            }
        });

    let concentration = best_count as f64 / total;
    if concentration < MIN_CONCENTRATION {
        return None;
    }

    let confidence = 0.35 + (concentration - MIN_CONCENTRATION) * 0.5;
    let region = offset_to_region(best_offset);

    Some(TimezoneInference {
        utc_offset: best_offset,
        region,
        confidence: confidence.min(confidence::MEDIUM_PLUS),
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
    include!("tests.rs");
}
