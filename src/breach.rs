//! Pure breach/intel helpers rebuilt from the legacy tree.

use serde::{Deserialize, Serialize};

pub const BREACH_SOCIAL_PLATFORMS: &[&str] = &[
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
    "github",
    "tiktok",
    "reddit",
];

const REAL_ESTATE: &[&str] = &[
    "realestate",
    "realty",
    "realtor",
    "property",
    "rentberry",
    "1form",
    "flatmates",
    "propertytree",
    "harcourts",
    "ljhooker",
    "raywhite",
    "century21",
    "raineandhorne",
    "onthehouse",
    "allhomes",
    "domain.com.au",
    "pexa",
    "corelogic",
    "rpdata",
    "zillow",
    "redfin",
    "conveyanc",
];
const KNOWN_SOURCE_SECTORS: &[(&str, &str)] = &[
    ("zynga", "gaming"),
    ("neopets", "gaming"),
    ("tunngle", "gaming"),
    ("r2games", "gaming"),
    ("steam", "gaming"),
    ("dlh", "gaming"),
    ("tumblr", "social"),
    ("linkedin", "tech"),
    ("deezer", "media"),
    ("edmodo", "education"),
    ("jefit", "health"),
    ("fling", "adult"),
    ("paypal", "finance"),
    ("airbnb", "travel"),
    ("optus", "telecom"),
    ("medibank", "health"),
    ("latitudefinancial", "finance"),
];
const BREACH_DESCRIPTORS: &[&str] = &[
    "scrape",
    "combo",
    "dump",
    "leak",
    "breach",
    "database",
    "db",
    "hack",
    "exposed",
    "collection",
    "data",
    "hacked",
    "stolen",
    "combolists",
    "lists",
    "list",
    "free",
    "full",
];

fn token_denotes_brand(token: &str, needle: &str) -> bool {
    if token == needle {
        return true;
    }
    if token.len() <= needle.len() {
        return false;
    }
    if let Some(rest) = token.strip_prefix(needle) {
        if BREACH_DESCRIPTORS.contains(&rest) {
            return true;
        }
    }
    if let Some(rest) = token.strip_suffix(needle) {
        if BREACH_DESCRIPTORS.contains(&rest) {
            return true;
        }
    }
    false
}

fn known_brand_sector(lower: &str) -> Option<&'static str> {
    let tokens: Vec<&str> = lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
        .collect();
    KNOWN_SOURCE_SECTORS
        .iter()
        .find(|(needle, _)| {
            tokens
                .iter()
                .any(|token| token_denotes_brand(token, needle))
        })
        .map(|(_, sector)| *sector)
}

fn structured_category(lower: &str) -> Option<&'static str> {
    let parts: Vec<&str> = lower.split('_').collect();
    if parts.len() < 3 {
        return None;
    }
    let last = parts[parts.len() - 1];
    let looks_like_date =
        (4..=8).contains(&last.len()) && last.bytes().all(|byte| byte.is_ascii_digit());
    if !looks_like_date {
        return None;
    }
    match parts[parts.len() - 2] {
        "realestate" | "real-estate" | "property" | "housing" | "rental" | "rentals" => {
            Some("real-estate")
        }
        "gaming" | "games" | "game" | "gambling" => Some("gaming"),
        "tech" | "technology" | "it" | "software" | "saas" => Some("tech"),
        "finance" | "financial" | "banking" | "bank" | "crypto" | "fintech" => Some("finance"),
        "health" | "medical" | "healthcare" | "pharma" => Some("health"),
        "gov" | "government" | "military" | "defence" | "defense" => Some("government"),
        "retail" | "ecommerce" | "shopping" | "commerce" => Some("retail"),
        "social" | "dating" | "forum" | "forums" => Some("social"),
        "media" | "music" | "streaming" | "entertainment" => Some("media"),
        "adult" | "porn" | "xxx" => Some("adult"),
        "education" | "edu" | "academic" | "university" => Some("education"),
        "travel" | "hospitality" | "airline" | "hotel" => Some("travel"),
        "telecom" | "telco" | "isp" | "mobile" => Some("telecom"),
        "auto" | "automotive" | "vehicle" => Some("automotive"),
        _ => None,
    }
}

#[must_use]
pub fn source_sector(dbname: &str) -> Option<&'static str> {
    let trimmed = dbname.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if REAL_ESTATE.iter().any(|needle| lower.contains(needle)) {
        return Some("real-estate");
    }
    structured_category(&lower).or_else(|| known_brand_sector(&lower))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBroker {
    pub domain: &'static str,
    pub name: &'static str,
}

pub const BROKERS: &[DataBroker] = &[
    DataBroker {
        domain: "anywho.com",
        name: "AnyWho",
    },
    DataBroker {
        domain: "beenverified.com",
        name: "BeenVerified",
    },
    DataBroker {
        domain: "idcrawl.com",
        name: "IDCrawl",
    },
    DataBroker {
        domain: "intelius.com",
        name: "Intelius",
    },
    DataBroker {
        domain: "mylife.com",
        name: "MyLife",
    },
    DataBroker {
        domain: "nuwber.com",
        name: "Nuwber",
    },
    DataBroker {
        domain: "peekyou.com",
        name: "PeekYou",
    },
    DataBroker {
        domain: "pipl.com",
        name: "Pipl",
    },
    DataBroker {
        domain: "spokeo.com",
        name: "Spokeo",
    },
    DataBroker {
        domain: "truepeoplesearch.com",
        name: "TruePeopleSearch",
    },
    DataBroker {
        domain: "whitepages.com",
        name: "Whitepages",
    },
    DataBroker {
        domain: "zabasearch.com",
        name: "ZabaSearch",
    },
];

#[must_use]
pub fn broker_for_host(host: &str) -> Option<&'static DataBroker> {
    let mut normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(stripped) = normalized.strip_prefix("www.") {
        normalized = stripped.to_string();
    }
    BROKERS
        .iter()
        .find(|broker| crate::domains::is_or_subdomain_of(&normalized, broker.domain))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealerRow {
    pub log_id: Option<String>,
    pub domain: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    pub pwned_at: Option<String>,
    pub kind: StealerRowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StealerRowKind {
    Password,
    Combo,
}

impl StealerRowKind {
    #[must_use]
    pub fn classify(domain: Option<&str>) -> Self {
        match domain {
            Some(value) if !value.trim().is_empty() => Self::Password,
            _ => Self::Combo,
        }
    }

    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Combo => "combo",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Self {
        match value {
            "password" => Self::Password,
            _ => Self::Combo,
        }
    }
}

impl StealerRow {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.login.is_none() && self.password.is_none()
    }
}

#[must_use]
pub fn classify_crypto_address(value: &str) -> Option<&'static str> {
    let len = value.len();
    if (39..=74).contains(&len)
        && (value.starts_with("bc1") || value.starts_with("BC1"))
        && value.chars().skip(3).all(is_bech32_payload)
        && bech32_checksum_valid(value)
    {
        return Some("crypto_btc");
    }
    if (40..=74).contains(&len)
        && (value.starts_with("ltc1") || value.starts_with("LTC1"))
        && value.chars().skip(4).all(is_bech32_payload)
        && bech32_checksum_valid(value)
    {
        return Some("crypto_ltc");
    }
    if len == 42
        && (value.starts_with("0x") || value.starts_with("0X"))
        && value.chars().skip(2).all(|ch| ch.is_ascii_hexdigit())
    {
        return Some("crypto_eth");
    }
    if (26..=35).contains(&len)
        && (value.starts_with('1') || value.starts_with('3'))
        && value.chars().all(is_base58)
        && !is_all_ascii_hex(value)
        && base58check_valid(value)
    {
        return Some("crypto_btc");
    }
    if (26..=35).contains(&len)
        && (value.starts_with('L') || value.starts_with('M'))
        && value.chars().all(is_base58)
        && !is_all_ascii_hex(value)
        && base58check_valid(value)
    {
        return Some("crypto_ltc");
    }
    if len == 34
        && value.starts_with('D')
        && value.chars().all(is_base58)
        && !is_all_ascii_hex(value)
        && base58check_valid(value)
    {
        return Some("crypto_doge");
    }
    if (43..=44).contains(&len) && value.chars().all(is_base58) && !is_all_ascii_hex(value) {
        return Some("crypto_sol");
    }
    if len == 95
        && (value.starts_with('4') || value.starts_with('8'))
        && value.chars().all(is_base58)
        && !is_all_ascii_hex(value)
    {
        return Some("crypto_xmr");
    }
    None
}

#[must_use]
pub fn chain_label(tag: &str) -> &str {
    tag.strip_prefix("crypto_").unwrap_or(tag)
}

fn is_base58(ch: char) -> bool {
    matches!(ch, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

fn is_bech32_payload(ch: char) -> bool {
    matches!(ch.to_ascii_lowercase(), 'a' | 'c'..='h' | 'j'..='n' | 'p'..='z' | '0' | '2'..='9')
}

fn is_all_ascii_hex(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn base58_decode(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        let mut carry =
            u32::try_from(ALPHABET.iter().position(|candidate| *candidate == byte)?).ok()?;
        for digit in &mut result {
            carry += u32::from(*digit) * 58;
            *digit = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for byte in value.bytes() {
        if byte == b'1' {
            result.push(0);
        } else {
            break;
        }
    }
    result.reverse();
    Some(result)
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = crate::sha256::sha256(bytes);
    crate::sha256::sha256(&first)
}

fn base58check_valid(value: &str) -> bool {
    let Some(decoded) = base58_decode(value) else {
        return false;
    };
    if decoded.len() < 5 {
        return false;
    }
    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    double_sha256(payload)[..4] == *checksum
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GEN.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn bech32_checksum_valid(value: &str) -> bool {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let lower = value.to_ascii_lowercase();
    let Some(separator) = lower.rfind('1') else {
        return false;
    };
    let bytes = lower.as_bytes();
    if separator == 0 || bytes.len() < separator + 7 {
        return false;
    }
    let (hrp, data) = (&bytes[..separator], &bytes[separator + 1..]);
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1 + data.len());
    expanded.extend(hrp.iter().map(|byte| *byte >> 5));
    expanded.push(0);
    expanded.extend(hrp.iter().map(|byte| *byte & 31));
    for byte in data {
        let Some(index) = CHARSET.iter().position(|candidate| candidate == byte) else {
            return false;
        };
        let Ok(index) = u8::try_from(index) else {
            return false;
        };
        expanded.push(index);
    }
    let checksum = bech32_polymod(&expanded);
    checksum == 1 || checksum == 0x2bc8_30a3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_sectors_and_platforms() {
        assert_eq!(
            source_sector("0645_ZYNGA_COM_202M_GAMING_092019"),
            Some("gaming")
        );
        assert_eq!(source_sector("realestate.com.au"), Some("real-estate"));
        assert_eq!(source_sector("linkedinscrape-2021"), Some("tech"));
        assert_eq!(source_sector("pureincubation.com"), None);
        assert!(BREACH_SOCIAL_PLATFORMS.contains(&"github"));
    }

    #[test]
    fn brokers_and_stealer_rows_work() {
        assert_eq!(
            broker_for_host("WWW.Spokeo.COM.").map(|broker| broker.name),
            Some("Spokeo")
        );
        assert_eq!(broker_for_host("notspokeo.com"), None);
        assert_eq!(
            StealerRowKind::classify(Some("example.com")),
            StealerRowKind::Password
        );
        assert_eq!(
            StealerRowKind::from_db_str("garbage"),
            StealerRowKind::Combo
        );
        let row = StealerRow {
            log_id: None,
            domain: None,
            login: Some("alice".into()),
            password: None,
            pwned_at: None,
            kind: StealerRowKind::Combo,
        };
        assert!(!row.is_empty());
    }

    #[test]
    fn classifies_crypto_addresses_conservatively() {
        assert_eq!(
            classify_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            Some("crypto_btc")
        );
        assert_eq!(
            classify_crypto_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            Some("crypto_btc")
        );
        assert_eq!(
            classify_crypto_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            Some("crypto_eth")
        );
        assert_eq!(
            classify_crypto_address("5e3706b9c16282351af9c3aac7107b54"),
            None,
            "hex blob must stay a key, not a wallet"
        );
        assert_eq!(chain_label("crypto_btc"), "btc");
    }
}
