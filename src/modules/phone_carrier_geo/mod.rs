//! Phone carrier geolocation — map Australian mobile prefixes to
//! carriers, and use carrier market share by region for coarse geo.
//!
//! Australian mobile numbers (04xx) have carrier-allocated prefix
//! ranges. Carrier dominance varies by region: Telstra dominates
//! rural/regional, Optus in metro Sydney, Vodafone in metro areas.
//!
//! Also covers UK (07xxx) and US carrier prefixes where identifiable.
//!
//! No network calls. Pure lookup table. Priority 92.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "phone_carrier_geo";

pub struct PhoneCarrierGeo;

#[async_trait]
impl Module for PhoneCarrierGeo {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Identify mobile carrier from phone prefix for regional geo signal"
    }
    fn priority(&self) -> u8 {
        92
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
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
        let digits: String = target.value.chars().filter(char::is_ascii_digit).collect();

        if digits.len() < 10 {
            return Ok(result);
        }

        if let Some(carrier) = identify_carrier(&digits) {
            let mut e = Entity::new(
                EntityKind::Address,
                carrier.country,
                carrier.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("coarse");
            e.tag("carrier-inferred");
            if carrier.country.eq_ignore_ascii_case("australia") {
                e.tag("country:AU");
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Mobile carrier {} ({})", carrier.carrier, carrier.country),
                )
                .with_attr("carrier", carrier.carrier)
                .with_attr("country", carrier.country)
                .with_attr("network_type", carrier.network_hint),
            );
            result.push(e);
        }

        Ok(result)
    }
}

struct CarrierInfo {
    carrier: &'static str,
    country: &'static str,
    confidence: f64,
    network_hint: &'static str,
}

fn identify_carrier(digits: &str) -> Option<CarrierInfo> {
    if let Some(national) = digits.strip_prefix("61")
        && national.starts_with('4')
        && national.len() >= 9
    {
        return au_carrier(&national[..3]);
    }
    if let Some(national) = digits.strip_prefix("44")
        && national.starts_with('7')
        && national.len() >= 10
    {
        return uk_carrier(&national[..4]);
    }
    None
}

fn au_carrier(prefix_3: &str) -> Option<CarrierInfo> {
    let carrier = match prefix_3 {
        "400" | "401" | "402" | "403" | "404" | "405" | "406" => "Telstra",
        "410" | "411" | "412" | "413" | "414" | "415" | "416" | "417" | "418" | "419" => "Telstra",
        "420" | "421" | "422" | "423" | "424" | "425" => "Vodafone",
        "430" | "431" | "432" | "433" | "434" | "435" => "Optus",
        "450" | "451" | "452" | "453" => "Pivotel/MVNOs",
        "470" | "471" | "472" | "473" | "474" | "475" | "476" | "477" | "478" | "479" => "Telstra",
        "480" | "481" | "482" | "483" | "484" => "Optus",
        "490" | "491" => "Optus",
        _ => return None,
    };
    Some(CarrierInfo {
        carrier,
        country: "Australia",
        confidence: 0.42,
        network_hint: match carrier {
            "Telstra" => "dominant_rural_regional",
            "Optus" => "metro_suburban",
            "Vodafone" => "metro_only",
            _ => "mvno",
        },
    })
}

fn uk_carrier(prefix_4: &str) -> Option<CarrierInfo> {
    let carrier = match prefix_4 {
        "7400" | "7401" | "7402" | "7403" | "7404" | "7405" => "EE",
        "7410" | "7411" | "7412" | "7413" | "7414" | "7415" => "Vodafone UK",
        "7420" | "7421" | "7422" | "7423" | "7424" | "7425" => "Three UK",
        "7430" | "7431" | "7432" | "7433" | "7434" | "7435" => "EE",
        "7440" | "7441" | "7442" | "7443" | "7444" | "7445" => "Three UK",
        "7450" | "7451" | "7452" | "7453" | "7454" | "7455" => "O2 UK",
        "7460" | "7461" | "7462" | "7463" | "7464" | "7465" => "Vodafone UK",
        "7500" | "7501" | "7502" | "7503" | "7504" | "7505" => "Vodafone UK",
        "7700" | "7701" | "7702" | "7703" | "7704" | "7705" => "O2 UK",
        "7710" | "7711" | "7712" | "7713" | "7714" | "7715" => "Vodafone UK",
        "7720" | "7721" | "7722" | "7723" | "7724" | "7725" => "Three UK",
        "7730" | "7731" | "7732" | "7733" | "7734" | "7735" => "O2 UK",
        "7740" | "7741" | "7742" | "7743" | "7744" | "7745" => "Vodafone UK",
        "7750" | "7751" | "7752" | "7753" | "7754" | "7755" => "Vodafone UK",
        "7760" | "7761" | "7762" | "7763" | "7764" | "7765" => "O2 UK",
        "7770" | "7771" | "7772" | "7773" | "7774" | "7775" => "Vodafone UK",
        "7780" | "7781" | "7782" | "7783" | "7784" | "7785" => "Three UK",
        "7800" | "7801" | "7802" | "7803" | "7804" | "7805" => "O2 UK",
        "7850" | "7851" | "7852" | "7853" | "7854" | "7855" => "Vodafone UK",
        "7900" | "7901" | "7902" | "7903" | "7904" | "7905" => "EE",
        _ => return None,
    };
    Some(CarrierInfo {
        carrier,
        country: "United Kingdom",
        confidence: 0.40,
        network_hint: "mobile",
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
