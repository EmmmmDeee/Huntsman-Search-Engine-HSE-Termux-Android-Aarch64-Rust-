//! ACMA phone number intelligence: Australian carrier and service classification.
//!
//! Classifies Australian phone numbers by type (mobile, landline, VoIP, service) and
//! identifies carrier allocation based on ACMA National Number Plan prefixes.
//! Pattern-based intelligence without external API calls.
//!
//! No Deadline or Transport required: pure pattern matching on local data.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneType {
    /// Mobile number (04xx)
    Mobile,
    /// Landline number (02, 03, 07, 08)
    Landline,
    /// VoIP/Internet number (1300, 1800, 1900, 13)
    VoIP,
    /// Service number (1xx)
    Service,
    /// Other or unknown
    Unknown,
}

impl PhoneType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::Landline => "landline",
            Self::VoIP => "voip",
            Self::Service => "service",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneClassification {
    pub number: String,
    pub phone_type: PhoneType,
    pub area_code: Option<String>,
    pub carrier_hint: Option<&'static str>,
    pub state_hint: Option<&'static str>,
}

/// Classify an Australian phone number by prefix pattern and state area code.
/// Handles landline, mobile, VoIP, and service numbers.
#[must_use]
pub fn classify_australian_phone(number: &str) -> PhoneClassification {
    // Reject inputs with alphabetic characters (invalid phone numbers)
    if number.chars().any(|c| c.is_alphabetic()) {
        return PhoneClassification {
            number: number.to_string(),
            phone_type: PhoneType::Unknown,
            area_code: None,
            carrier_hint: None,
            state_hint: None,
        };
    }

    // Normalize: remove spaces, hyphens, parentheses.
    let normalized = number
        .chars()
        .filter(|c| c.is_numeric() || *c == '+')
        .collect::<String>();

    // Strip international code if present.
    let digits = if normalized.starts_with("+61") {
        normalized[3..].to_string()
    } else if normalized.starts_with("61") && normalized.len() > 2 {
        normalized[2..].to_string()
    } else {
        normalized.clone()
    };

    let (phone_type, area_code, carrier, state) = if (digits.starts_with("04")
        && digits.len() == 10)
        || (digits.starts_with("4") && digits.len() == 9)
    {
        // Mobile: 04xx xxx xxx (10 digits domestic) or 4xx xxx xxx (9 digits international)
        let prefix = if digits.starts_with("04") {
            digits[0..4].to_string()
        } else {
            // International format: prepend "0" for carrier lookup (4xx → 04xx)
            format!("0{}", &digits[0..3])
        };
        let carrier_name = classify_mobile_carrier(&prefix);
        (PhoneType::Mobile, Some(prefix), carrier_name, None)
    } else if digits.starts_with("1300") || digits.starts_with("1800") || digits.starts_with("1900")
    {
        // VoIP: 1300/1800/1900 prefixed numbers
        let prefix = &digits[0..4];
        let carrier_name = classify_voip_carrier(prefix);
        (
            PhoneType::VoIP,
            Some(prefix.to_string()),
            carrier_name,
            None,
        )
    } else if digits.starts_with("13") && digits.len() == 4 {
        // VoIP: 13xx (4 digits exactly)
        let prefix = &digits[0..2];
        let carrier_name = classify_voip_carrier(prefix);
        (
            PhoneType::VoIP,
            Some(prefix.to_string()),
            carrier_name,
            None,
        )
    } else if digits.starts_with("0") && digits.len() >= 8 && digits.len() <= 10 {
        // Landline: 0x xxxx xxxx (8-10 digits starting with 0)
        let area = &digits[0..2];
        let state = classify_state_by_area(area);
        (PhoneType::Landline, Some(area.to_string()), None, state)
    } else if digits.len() >= 3 && digits.len() <= 4 {
        // Service number (short codes: 000, 100, 101, 1234, etc. - 3-4 digits)
        let area_code = digits.clone();
        (
            PhoneType::Service,
            Some(area_code.clone()),
            classify_service_number(&area_code),
            None,
        )
    } else {
        (PhoneType::Unknown, None, None, None)
    };

    PhoneClassification {
        number: number.to_string(),
        phone_type,
        area_code,
        carrier_hint: carrier,
        state_hint: state,
    }
}

/// Classify mobile carrier by 04xx prefix.
fn classify_mobile_carrier(prefix: &str) -> Option<&'static str> {
    match prefix {
        "0400" | "0401" | "0402" | "0403" | "0404" | "0405" => Some("Telstra"),
        "0410" | "0411" | "0412" | "0413" | "0414" | "0415" | "0416" | "0417" | "0418" | "0419" => {
            Some("Vodafone")
        }
        "0420" | "0421" | "0422" | "0423" | "0424" | "0425" | "0426" | "0427" | "0428" | "0429" => {
            Some("Optus")
        }
        "0430" | "0431" | "0432" | "0433" | "0434" | "0435" | "0436" | "0437" | "0438" | "0439" => {
            Some("Virgin Mobile")
        }
        "0450" | "0451" | "0452" | "0453" | "0454" | "0455" | "0456" | "0457" | "0458" | "0459" => {
            Some("Telstra")
        }
        "0460" | "0461" | "0462" | "0463" | "0464" | "0465" | "0466" | "0467" | "0468" | "0469" => {
            Some("Vodafone")
        }
        "0470" | "0471" | "0472" | "0473" | "0474" | "0475" | "0476" | "0477" | "0478" | "0479" => {
            Some("Optus")
        }
        "0480" | "0481" | "0482" | "0483" | "0484" | "0485" | "0486" | "0487" | "0488" | "0489" => {
            Some("Three")
        }
        "0490" | "0491" | "0492" | "0493" | "0494" | "0495" | "0496" | "0497" | "0498" | "0499" => {
            Some("Other")
        }
        _ => None,
    }
}

/// Classify landline state by area code.
fn classify_state_by_area(area: &str) -> Option<&'static str> {
    match area {
        "02" => Some("NSW/ACT"),
        "03" => Some("VIC/TAS"),
        "07" => Some("QLD"),
        "08" => Some("WA/SA/NT"),
        _ => None,
    }
}

/// Classify VoIP/service carrier by prefix.
fn classify_voip_carrier(prefix: &str) -> Option<&'static str> {
    match prefix {
        "1300" | "1800" => Some("Multi-provider"),
        "1900" => Some("Premium"),
        "13" => Some("Directory/Service"),
        _ => None,
    }
}

/// Classify special service numbers.
fn classify_service_number(prefix: &str) -> Option<&'static str> {
    match prefix {
        "000" => Some("Emergency"),
        "100" => Some("Directory assistance"),
        "101" => Some("Complaints"),
        "102" => Some("Fraud"),
        "103" => Some("Repair service"),
        "104" => Some("Account query"),
        "105" => Some("Network monitoring"),
        "112" => Some("Emergency (GSM)"),
        "1234" => Some("Time"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_number_classification() {
        let telstra = classify_australian_phone("0400 123 456");
        assert_eq!(telstra.phone_type, PhoneType::Mobile);
        assert_eq!(telstra.carrier_hint, Some("Telstra"));
        assert_eq!(telstra.area_code, Some("0400".to_string()));

        let vodafone = classify_australian_phone("0410123456");
        assert_eq!(vodafone.phone_type, PhoneType::Mobile);
        assert_eq!(vodafone.carrier_hint, Some("Vodafone"));

        let optus = classify_australian_phone("(0420) 123-456");
        assert_eq!(optus.phone_type, PhoneType::Mobile);
        assert_eq!(optus.carrier_hint, Some("Optus"));
    }

    #[test]
    fn landline_number_classification() {
        let nsw = classify_australian_phone("02 1234 5678");
        assert_eq!(nsw.phone_type, PhoneType::Landline);
        assert_eq!(nsw.area_code, Some("02".to_string()));
        assert_eq!(nsw.state_hint, Some("NSW/ACT"));

        let vic = classify_australian_phone("0312345678");
        assert_eq!(vic.state_hint, Some("VIC/TAS"));

        let qld = classify_australian_phone("07-1234-5678");
        assert_eq!(qld.state_hint, Some("QLD"));

        let wa = classify_australian_phone("08 1234 5678");
        assert_eq!(wa.state_hint, Some("WA/SA/NT"));
    }

    #[test]
    fn voip_number_classification() {
        let toll_free = classify_australian_phone("1800 123 456");
        assert_eq!(toll_free.phone_type, PhoneType::VoIP);

        let local_rate = classify_australian_phone("1300123456");
        assert_eq!(local_rate.phone_type, PhoneType::VoIP);

        let premium = classify_australian_phone("1900 123 456");
        assert_eq!(premium.phone_type, PhoneType::VoIP);
    }

    #[test]
    fn service_number_classification() {
        let emergency = classify_australian_phone("000");
        assert_eq!(emergency.phone_type, PhoneType::Service);
        assert_eq!(emergency.carrier_hint, Some("Emergency"));

        let directory = classify_australian_phone("100");
        assert_eq!(directory.carrier_hint, Some("Directory assistance"));

        let time = classify_australian_phone("1234");
        assert_eq!(time.carrier_hint, Some("Time"));
    }

    #[test]
    fn international_format_normalization() {
        let au_prefix = classify_australian_phone("+61400123456");
        let zero_prefix = classify_australian_phone("0400123456");
        assert_eq!(au_prefix.phone_type, zero_prefix.phone_type);
        assert_eq!(au_prefix.carrier_hint, zero_prefix.carrier_hint);
    }

    #[test]
    fn phone_type_strings() {
        assert_eq!(PhoneType::Mobile.as_str(), "mobile");
        assert_eq!(PhoneType::Landline.as_str(), "landline");
        assert_eq!(PhoneType::VoIP.as_str(), "voip");
        assert_eq!(PhoneType::Service.as_str(), "service");
    }

    #[test]
    fn invalid_number_handling() {
        let invalid = classify_australian_phone("abc123");
        assert_eq!(invalid.phone_type, PhoneType::Unknown);

        let short = classify_australian_phone("01");
        assert_eq!(short.phone_type, PhoneType::Unknown);
    }
}
