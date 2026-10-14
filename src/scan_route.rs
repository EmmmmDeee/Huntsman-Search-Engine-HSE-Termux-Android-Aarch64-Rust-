//! Pure selector classification for the `scan` command.
//!
//! Keeping routing out of `main.rs` gives the single-selector and batch paths
//! one deterministic contract and makes future recursive expansion reuse the
//! exact same classifier.

use crate::canonical::{
    canonical_domain, canonical_email, canonical_handle, canonical_name, canonical_phone,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    People,
    Email,
    /// Keyed breach exposure for an email. Never inferred: it spends operator keys, so it runs
    /// only when asked for by name.
    Exposure,
    Username,
    Phone,
    /// Domain recon: crt.sh certificate transparency and DNS record lookups.
    Domain,
    /// A `WiFi` network: a BSSID, a coordinate pair or an SSID, classified offline and searched
    /// on `WiGLE` when its credentials are configured.
    Network,
}

impl ScanKind {
    /// Every kind, in the order the CLI usage and the Web UI list them.
    pub const ALL: [Self; 7] = [
        Self::People,
        Self::Email,
        Self::Exposure,
        Self::Username,
        Self::Phone,
        Self::Domain,
        Self::Network,
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
            Self::Network => "network",
        }
    }
}

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
        "network" | "wifi" | "bssid" | "ssid" | "wigle" => Ok(ScanKind::Network),
        other => Err(other),
    }
}

/// Canonical selector for a route. `None` means the route cannot run.
#[must_use]
pub fn canonical_selector(kind: ScanKind, raw: &str) -> Option<String> {
    match kind {
        ScanKind::Email | ScanKind::Exposure => canonical_email(raw),
        ScanKind::Username => canonical_handle(raw),
        ScanKind::Phone => canonical_phone(raw),
        ScanKind::Domain => canonical_domain(raw),
        ScanKind::Network => crate::network_cli::canonical_selector(raw),
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
/// Precedence is intentional: canonical email, explicit `@handle`, a BSSID or coordinate
/// pair, recognised phone syntax, then a person/name fallback. A BSSID or coordinate pair is
/// judged before phone syntax because its digits could otherwise read as a number. An SSID is
/// free text, so it is never inferred.
#[must_use]
pub fn infer_kind(selector: &str) -> ScanKind {
    if canonical_email(selector).is_some() {
        ScanKind::Email
    } else if selector.starts_with('@') {
        ScanKind::Username
    } else if crate::network_cli::NetworkSelector::parse_identifier(selector).is_some() {
        ScanKind::Network
    } else if crate::phone_intl::canonicalize(selector).is_some() {
        ScanKind::Phone
    } else if canonical_domain(selector).is_some() {
        ScanKind::Domain
    } else {
        ScanKind::People
    }
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
        assert_eq!(infer_kind("Ada Lovelace"), ScanKind::People);
        assert_eq!(infer_kind("00:1A:2B:3C:4D:5E"), ScanKind::Network);
        assert_eq!(infer_kind("00-1a-2b-3c-4d-5e"), ScanKind::Network);
        assert_eq!(infer_kind("-27.4698,153.0251"), ScanKind::Network);
        // An SSID is free text: inferring it would turn every word into a WiGLE query.
        assert_eq!(infer_kind("HomeWiFi"), ScanKind::People);
    }

    #[test]
    fn route_selector_is_canonical() {
        assert_eq!(
            canonical_selector(ScanKind::Email, " Ada@Example.ORG "),
            Some("ada@example.org".into())
        );
        assert_eq!(
            canonical_selector(ScanKind::Username, "@Ada"),
            Some("ada".into())
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
