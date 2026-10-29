//! Pure selector classification for the `scan` command.
//!
//! Keeping routing out of `main.rs` gives the single-selector and batch paths
//! one deterministic contract and makes future recursive expansion reuse the
//! exact same classifier.

use crate::canonical::{
    canonical_asn, canonical_domain, canonical_email, canonical_handle, canonical_ip,
    canonical_name, canonical_netblock,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    People,
    Email,
    /// Keyed breach exposure for an email or username. Not inferred as a kind of its own: an
    /// `email` or `username` lookup already runs every exposure leg whose key is configured.
    Exposure,
    Username,
    Phone,
    /// Domain recon: crt.sh certificate transparency and DNS record lookups.
    Domain,
    /// One public IP address: `InternetDB`, `RIPEstat`, `GreyNoise`, and keyed reputation legs.
    Ip,
    /// One public address block in CIDR form: its RDAP registration, `RIPEstat` routing and the
    /// PTR records of its addresses.
    Netblock,
    /// One public AS number: its RDAP registration, and from `RIPEstat` its holder, every prefix
    /// it announces and every BGP neighbour.
    Asn,
    /// A `WiFi` network: a BSSID, a coordinate pair or an SSID, classified offline and searched
    /// on `WiGLE` when its credentials are configured.
    Network,
    /// One Bitcoin address or explicitly Base-prefixed EVM address, enriched
    /// with its balance and lifetime totals from blockchain.info. Not inferred as a kind of its
    /// own: a bare base58 or bech32 string is ambiguous against usernames and other selectors, so
    /// a crypto route is asked for explicitly.
    CryptoAddress,
    /// A place name, street address or `LAT,LON` point, geocoded through OpenStreetMap's
    /// Nominatim, keyless: Spiderfoot's `PHYSICAL_ADDRESS` and `PHYSICAL_COORDINATES` targets.
    /// Not inferred as a kind of its own: free text is a person's name to `scan` and a bare
    /// coordinate pair is a `WiFi` area, so a geocode is asked for explicitly.
    Place,
}

impl ScanKind {
    /// Every kind, in the order the CLI usage and the Web UI list them.
    pub const ALL: [Self; 12] = [
        Self::People,
        Self::Email,
        Self::Exposure,
        Self::Username,
        Self::Phone,
        Self::Domain,
        Self::Ip,
        Self::Netblock,
        Self::Asn,
        Self::Network,
        Self::CryptoAddress,
        Self::Place,
    ];

    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::People => "people",
            Self::Email => "email",
            Self::Exposure => "exposure",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Netblock => "netblock",
            Self::Asn => "asn",
            Self::Network => "network",
            Self::CryptoAddress => "crypto",
            Self::Place => "geocode",
        }
    }
}

pub use crate::network_selector::{
    CELL_PREFIX, MAX_CELL_ID, MAX_SSID_BYTES, NetworkSelector, SSID_PREFIX, network_selector,
};

/// Parse an explicit scan kind using the aliases accepted by the CLI.
///
/// # Errors
/// Returns the unknown spelling so the CLI can produce a stable usage error.
pub fn parse_kind(value: &str) -> Result<ScanKind, &str> {
    match value {
        "people" | "name" => Ok(ScanKind::People),
        "email" => Ok(ScanKind::Email),
        "exposure" | "breach" => Ok(ScanKind::Exposure),
        "username" | "handle" => Ok(ScanKind::Username),
        "phone" => Ok(ScanKind::Phone),
        "domain" => Ok(ScanKind::Domain),
        "ip" | "address" => Ok(ScanKind::Ip),
        "netblock" | "cidr" | "prefix" => Ok(ScanKind::Netblock),
        "asn" | "as" | "bgp" => Ok(ScanKind::Asn),
        "network" | "wifi" | "bssid" | "ssid" | "wigle" => Ok(ScanKind::Network),
        "crypto" | "bitcoin" | "btc" => Ok(ScanKind::CryptoAddress),
        "geocode" | "place" | "location" => Ok(ScanKind::Place),
        other => Err(other),
    }
}

/// Validated selector for a route. Username spelling preserves original case for case-sensitive
/// providers (Hacker News); other kinds retain their canonical forms. `None` refuses the route.
#[must_use]
pub fn canonical_selector(kind: ScanKind, raw: &str) -> Option<String> {
    match kind {
        ScanKind::Email => canonical_email(raw),
        ScanKind::Exposure => crate::exposure_cli::canonical_selector(raw),
        ScanKind::Username => {
            canonical_handle(raw)?;
            Some(raw.trim().trim_start_matches('@').to_owned())
        }
        // The rule `infer_kind` routes a phone by, so every selector routed here is accepted.
        ScanKind::Phone => crate::phone_intl::canonicalize(raw),
        ScanKind::Domain => canonical_domain(raw),
        ScanKind::Ip => canonical_ip(raw),
        ScanKind::Netblock => canonical_netblock(raw),
        ScanKind::Asn => canonical_asn(raw),
        ScanKind::Network => network_selector(raw),
        ScanKind::CryptoAddress => crate::crypto_cli::canonical_address(raw).ok(),
        // The query as the geocode keys on it; a `lat,lon` point is read by the lookup itself.
        ScanKind::Place => crate::nominatim_cli::canonical_query(raw).ok(),
        // The people command owns the two-token rule and its offline skip path;
        // here only an empty name is non-canonical.
        ScanKind::People => {
            let name = canonical_name(raw);
            (!name.is_empty()).then_some(name)
        }
    }
}

/// Infer the rebuilt lookup front-end for one selector.
///
/// Precedence is intentional: canonical email, explicit `@handle`, public IP address, public
/// address block, an `AS`-prefixed public AS number, a BSSID, `cell:` site or coordinate pair, recognised phone
/// syntax, digits alone as an AS number (as Spiderfoot reads `1234`), domain, then a person/name
/// fallback. A BSSID or
/// coordinate pair is judged before phone syntax because its digits could otherwise read as a
/// number. An SSID is free text, so it is never inferred.
#[must_use]
pub fn infer_kind(selector: &str) -> ScanKind {
    if crate::base_rpc::canonical_selector(selector).is_some() {
        ScanKind::CryptoAddress
    } else if canonical_email(selector).is_some() {
        ScanKind::Email
    } else if selector.starts_with('@') {
        ScanKind::Username
    } else if canonical_ip(selector).is_some() {
        ScanKind::Ip
    } else if canonical_netblock(selector).is_some() {
        ScanKind::Netblock
    } else if is_written_as_asn(selector) {
        ScanKind::Asn
    } else if NetworkSelector::parse_identifier(selector).is_some() {
        ScanKind::Network
    } else if crate::phone_intl::canonicalize(selector).is_some() {
        ScanKind::Phone
    } else if is_bare_number(selector) && canonical_asn(selector).is_some() {
        ScanKind::Asn
    } else if canonical_domain(selector).is_some() {
        ScanKind::Domain
    } else {
        ScanKind::People
    }
}

/// Whether `selector` is a public AS number written with its `AS` prefix.
fn is_written_as_asn(selector: &str) -> bool {
    selector
        .trim()
        .get(..2)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("as"))
        && canonical_asn(selector).is_some()
}

/// Digits alone, which Spiderfoot reads as an AS number once they are not a phone number. A
/// leading zero is a mistyped phone number (`0412`), never an AS number as one is written.
fn is_bare_number(selector: &str) -> bool {
    let trimmed = selector.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('0')
        && trimmed.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether an inferred people route has a name to look up. The selector is the first
/// positional, as it was on main: a second unquoted word is a separate argument and is not
/// part of the selector. So `scan Ada Lovelace` is refused, and `scan "Ada Lovelace"` is judged
/// as one name. Judging the joined words would run people-provider lookups from unquoted input
/// that main refused. A person lookup from unquoted words stays with the explicit `-k people`.
#[must_use]
pub fn inferred_people_is_name(positionals: &[String]) -> bool {
    positionals
        .first()
        .is_some_and(|selector| crate::people_cli::is_name(selector))
}

/// Whether an explicit `-k people` has a name to look up. The people command joins every
/// positional into its name, so an explicit request is judged on that joined name, as the people
/// command judges it. A single token is refused here rather than reaching the people command's
/// skip path, which exits 0: a refused lookup must not report success. Input the people command
/// rejects as a usage error passes here, so that command reports the error.
#[must_use]
pub fn explicit_people_is_name(positionals: &[String]) -> bool {
    match crate::people_cli::PeopleArgs::parse(positionals) {
        Ok(args) => crate::people_cli::is_name(&args.name),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_routed_by_its_international_prefix_is_a_canonical_selector() {
        // `scan "0044 20 7183 8750"` routed to phone and then refused the selector it routed.
        for (raw, canonical) in [
            ("0044 20 7183 8750", "+442071838750"),
            ("+44 20 7183 8750", "+442071838750"),
            ("+61 (0)412 345 678", "+61412345678"),
            ("0412 345 678", "+61412345678"),
        ] {
            assert_eq!(infer_kind(raw), ScanKind::Phone, "{raw}");
            assert_eq!(
                canonical_selector(ScanKind::Phone, raw).as_deref(),
                Some(canonical),
                "{raw}"
            );
        }
    }

    #[test]
    fn explicit_people_route_needs_a_joined_name() {
        // An explicit request names the person as the people command reads it: quoted or unquoted.
        assert!(explicit_people_is_name(&words(&["Ada Lovelace"])));
        assert!(explicit_people_is_name(&words(&["Ada", "Lovelace"])));
        // A single token is a refusal (65), not a skip that reports success.
        assert!(!explicit_people_is_name(&words(&["Madonna"])));
        assert!(!explicit_people_is_name(&words(&["0412345678"])));
        // No name and an unknown option are the people command's usage errors, which it reports.
        assert!(explicit_people_is_name(&[]));
        assert!(explicit_people_is_name(&words(&["Ada", "--bogus"])));
    }

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn inferred_people_route_judges_the_selector_as_main_did() {
        // Quoted, two words are one selector, and that is a name.
        assert!(inferred_people_is_name(&words(&["Ada Lovelace"])));
        // Unquoted, the second word is a separate argument, so the selector is one word.
        assert!(!inferred_people_is_name(&words(&["Ada", "Lovelace"])));
        assert!(!inferred_people_is_name(&words(&["Ada"])));
        assert!(!inferred_people_is_name(&words(&[
            "Ada", "--save", "out.json"
        ])));
        assert!(!inferred_people_is_name(&[]));
    }

    #[test]
    fn explicit_aliases_are_stable() {
        assert_eq!(parse_kind("people"), Ok(ScanKind::People));
        assert_eq!(parse_kind("name"), Ok(ScanKind::People));
        assert_eq!(parse_kind("handle"), Ok(ScanKind::Username));
        assert_eq!(parse_kind("phone"), Ok(ScanKind::Phone));
        assert_eq!(parse_kind("domain"), Ok(ScanKind::Domain));
        for alias in ["network", "wifi", "bssid", "ssid", "wigle"] {
            assert_eq!(parse_kind(alias), Ok(ScanKind::Network), "{alias}");
        }
        for kind in ScanKind::ALL {
            assert_eq!(parse_kind(kind.command()), Ok(kind));
        }
    }

    #[test]
    fn inference_preserves_cli_precedence() {
        assert_eq!(infer_kind("ada@example.org"), ScanKind::Email);
        assert_eq!(infer_kind("@ada"), ScanKind::Username);
        assert_eq!(infer_kind("+61412345678"), ScanKind::Phone);
        assert_eq!(infer_kind("example.com"), ScanKind::Domain);
        assert_eq!(infer_kind("1.1.1.1"), ScanKind::Ip);
        assert_eq!(infer_kind("2606:4700:4700::1111"), ScanKind::Ip);
        assert_eq!(parse_kind("ip"), Ok(ScanKind::Ip));
        assert_eq!(canonical_selector(ScanKind::Ip, "10.0.0.1"), None);
        assert_eq!(infer_kind("1.1.1.7/24"), ScanKind::Netblock);
        assert_eq!(infer_kind("2606:4700::/32"), ScanKind::Netblock);
        assert_eq!(
            canonical_selector(ScanKind::Netblock, "1.1.1.7/24").as_deref(),
            Some("1.1.1.0/24")
        );
        assert_eq!(canonical_selector(ScanKind::Netblock, "10.0.0.0/8"), None);
        assert_eq!(infer_kind("AS13335"), ScanKind::Asn);
        assert_eq!(infer_kind("asn13335"), ScanKind::Asn);
        assert_eq!(infer_kind("13335"), ScanKind::Asn);
        assert_eq!(infer_kind("+61412345678"), ScanKind::Phone);
        assert_ne!(infer_kind("64512"), ScanKind::Asn);
        assert_ne!(infer_kind("0412"), ScanKind::Asn);
        assert_ne!(infer_kind("Ashley"), ScanKind::Asn);
        assert_eq!(
            canonical_selector(ScanKind::Asn, "13335").as_deref(),
            Some("AS13335")
        );
        assert_eq!(canonical_selector(ScanKind::Asn, "AS64512"), None);
        assert_eq!(parse_kind("as"), Ok(ScanKind::Asn));
        assert_eq!(infer_kind("Ada Lovelace"), ScanKind::People);
        assert_eq!(infer_kind("00:1A:2B:3C:4D:5E"), ScanKind::Network);
        assert_eq!(infer_kind("00-1a-2b-3c-4d-5e"), ScanKind::Network);
        assert_eq!(infer_kind("-27.4698,153.0251"), ScanKind::Network);
        // An SSID is free text: inferring it would turn every word into a WiGLE query.
        assert_eq!(infer_kind("HomeWiFi"), ScanKind::People);
    }

    #[test]
    fn an_exposure_route_takes_an_address_or_a_username() {
        assert_eq!(
            canonical_selector(ScanKind::Exposure, "Ada@Example.com").as_deref(),
            Some("ada@example.com")
        );
        assert_eq!(
            canonical_selector(ScanKind::Exposure, "@Ada_99").as_deref(),
            Some("ada_99")
        );
        assert_eq!(canonical_selector(ScanKind::Exposure, "two words"), None);
        assert_eq!(canonical_selector(ScanKind::Email, "@Ada_99"), None);
    }

    #[test]
    fn a_crypto_route_takes_a_bitcoin_address_and_is_explicit_only() {
        for alias in ["crypto", "bitcoin", "btc"] {
            assert_eq!(parse_kind(alias), Ok(ScanKind::CryptoAddress), "{alias}");
        }
        assert_eq!(
            canonical_selector(
                ScanKind::CryptoAddress,
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
            )
            .as_deref(),
            Some("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        );
        // An Ethereum address is a crypto address but not one this route resolves.
        assert_eq!(
            canonical_selector(
                ScanKind::CryptoAddress,
                "0x0000000000000000000000000000000000000000"
            ),
            None
        );
        // A bare address is never inferred: it stays an explicit route.
        assert_ne!(
            infer_kind("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            ScanKind::CryptoAddress
        );
    }

    #[test]
    fn a_place_route_takes_free_text_or_a_point_and_is_explicit_only() {
        for alias in ["geocode", "place", "location"] {
            assert_eq!(parse_kind(alias), Ok(ScanKind::Place), "{alias}");
        }
        assert_eq!(
            canonical_selector(ScanKind::Place, "  Eiffel Tower, Paris ").as_deref(),
            Some("Eiffel Tower, Paris")
        );
        assert_eq!(
            canonical_selector(ScanKind::Place, "48.8584,2.2945").as_deref(),
            Some("48.8584,2.2945")
        );
        assert_eq!(canonical_selector(ScanKind::Place, " \t"), None);
        assert_eq!(canonical_selector(ScanKind::Place, "Paris\u{7}"), None);
        // Free text stays a name and a coordinate pair a WiFi area: a geocode is asked for.
        assert_eq!(infer_kind("Eiffel Tower"), ScanKind::People);
        assert_eq!(infer_kind("48.8584,2.2945"), ScanKind::Network);
    }

    #[test]
    fn username_scan_routes_keep_original_case_for_exact_account_lookups() {
        // CLI scan, saved scans and HTTP lookups all use this same route validation.
        for (raw, expected) in [
            ("@PaulHoule", "PaulHoule"),
            (" PaulHoule ", "PaulHoule"),
            ("@paulhoule", "paulhoule"),
        ] {
            assert_eq!(
                canonical_selector(ScanKind::Username, raw).as_deref(),
                Some(expected),
                "{raw}"
            );
            let plan = crate::scan_service::plan(raw, Some("username"))
                .expect("a valid case-sensitive username must be admitted");
            assert_eq!(plan.target, expected, "{raw}");
        }
        // Other breach/username correlation paths still receive canonical lowercase.
        assert_eq!(
            canonical_selector(ScanKind::Exposure, "@PaulHoule").as_deref(),
            Some("paulhoule")
        );
        assert_eq!(canonical_selector(ScanKind::Username, "two words"), None);
    }

    #[test]
    fn route_selector_is_canonical() {
        assert_eq!(
            canonical_selector(ScanKind::Email, " Ada@Example.ORG "),
            Some("ada@example.org".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::Username, "@Ada"),
            Some("Ada".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::People, " Ada   Lovelace "),
            Some("ada lovelace".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::People, "Ada"),
            Some("ada".into())
        );
        assert_eq!(canonical_selector(ScanKind::People, "   "), None);
        assert_eq!(
            canonical_selector(ScanKind::Network, "00-1A-2B-3C-4D-5E"),
            Some("00:1a:2b:3c:4d:5e".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::Network, " Cafe Guest "),
            Some("Cafe Guest".into())
        );
    }
}
