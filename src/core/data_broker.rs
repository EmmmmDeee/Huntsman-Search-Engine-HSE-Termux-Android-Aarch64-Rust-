//! Data-broker / people-search opt-out registry — the takedown surface.
//!
//! When a scan finds the subject listed on a people-search aggregator
//! (Spokeo, BeenVerified, Whitepages, …), that listing is an actionable PII
//! exposure: each broker publishes an opt-out / removal page. This module is
//! the single source of truth mapping a broker domain to its name and removal
//! URL, so the correlator (AU-054) can turn a raw broker hit into a concrete
//! "send the takedown here" finding.
//!
//! Pure data + a suffix lookup; no I/O. The opt-out URLs are the brokers'
//! public removal endpoints — operator-facing, no key required.
//!
//! These domains are deliberately a subset of the OSINT-aggregator block in
//! [`crate::core::scan`]'s mega-domain list (the engine already dampens them as
//! expansion noise); a test pins that every broker here is recognised there, so
//! the two views of "this is a people-search site" can't drift apart.

/// One people-search / data-broker site and where to file a removal request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBroker {
    /// Registrable domain, lowercase, no `www.` (the suffix matched against a
    /// discovered host).
    pub domain: &'static str,
    /// Operator-facing display name.
    pub name: &'static str,
    /// Public opt-out / removal request URL.
    pub optout_url: &'static str,
}

/// The curated broker registry. Kept alphabetical by domain for stable output
/// and easy review. Each `optout_url` is the broker's public removal page.
pub const BROKERS: &[DataBroker] = &[
    DataBroker {
        domain: "anywho.com",
        name: "AnyWho",
        optout_url: "https://www.intelius.com/opt-out/",
    },
    DataBroker {
        domain: "beenverified.com",
        name: "BeenVerified",
        optout_url: "https://www.beenverified.com/app/optout/search",
    },
    DataBroker {
        domain: "idcrawl.com",
        name: "IDCrawl",
        optout_url: "https://www.idcrawl.com/opt-out",
    },
    DataBroker {
        domain: "intelius.com",
        name: "Intelius",
        optout_url: "https://www.intelius.com/opt-out/",
    },
    DataBroker {
        domain: "mylife.com",
        name: "MyLife",
        optout_url: "https://www.mylife.com/ccpa/index.pubview",
    },
    DataBroker {
        domain: "nuwber.com",
        name: "Nuwber",
        optout_url: "https://nuwber.com/removal/link",
    },
    DataBroker {
        domain: "peekyou.com",
        name: "PeekYou",
        optout_url: "https://www.peekyou.com/about/contact/optout/index.php",
    },
    DataBroker {
        domain: "pipl.com",
        name: "Pipl",
        optout_url: "https://pipl.com/personal-information-removal-request",
    },
    DataBroker {
        domain: "radaris.com",
        name: "Radaris",
        optout_url: "https://radaris.com/control/privacy",
    },
    DataBroker {
        domain: "socialcatfish.com",
        name: "Social Catfish",
        optout_url: "https://socialcatfish.com/opt-out/",
    },
    DataBroker {
        domain: "spokeo.com",
        name: "Spokeo",
        optout_url: "https://www.spokeo.com/optout",
    },
    DataBroker {
        domain: "truepeoplesearch.com",
        name: "TruePeopleSearch",
        optout_url: "https://www.truepeoplesearch.com/removal",
    },
    DataBroker {
        domain: "usphonebook.com",
        name: "USPhonebook",
        optout_url: "https://www.usphonebook.com/opt-out",
    },
    DataBroker {
        domain: "whitepages.com",
        name: "Whitepages",
        optout_url: "https://www.whitepages.com/suppression-requests",
    },
    DataBroker {
        domain: "zabasearch.com",
        name: "ZabaSearch",
        optout_url: "https://www.intelius.com/opt-out/",
    },
];

/// The broker whose site `host` belongs to, if any. `host` is matched on whole
/// DNS labels after a `www.` / trailing-dot strip, so `www.spokeo.com` and
/// `spokeo.com` both match `spokeo.com` while `notspokeo.com` does not —
/// the same registrable-suffix discipline `is_mega_domain` uses.
#[must_use]
pub fn broker_for_host(host: &str) -> Option<&'static DataBroker> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = h.strip_prefix("www.").unwrap_or(&h);
    BROKERS.iter().find(|b| {
        h == b.domain
            || (h.len() > b.domain.len()
                && h.as_bytes()[h.len() - b.domain.len() - 1] == b'.'
                && h.ends_with(b.domain))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_matches_label_aligned_host_and_subdomains() {
        assert_eq!(
            broker_for_host("spokeo.com").map(|b| b.name),
            Some("Spokeo")
        );
        assert_eq!(
            broker_for_host("www.spokeo.com").map(|b| b.name),
            Some("Spokeo")
        );
        assert_eq!(
            broker_for_host("WWW.Spokeo.COM.").map(|b| b.name),
            Some("Spokeo")
        );
        // A subdomain of a broker still resolves to the broker.
        assert_eq!(
            broker_for_host("teaser.spokeo.com").map(|b| b.name),
            Some("Spokeo")
        );
        // Substring-but-not-label-aligned must NOT match.
        assert_eq!(broker_for_host("notspokeo.com"), None);
        assert_eq!(broker_for_host("spokeo.com.evil.test"), None);
        // A non-broker host.
        assert_eq!(broker_for_host("github.com"), None);
    }

    #[test]
    fn registry_is_well_formed() {
        for b in BROKERS {
            assert!(!b.domain.is_empty() && b.domain.contains('.'));
            assert_eq!(b.domain, b.domain.to_ascii_lowercase());
            assert!(!b.domain.starts_with("www."));
            assert!(
                b.optout_url.starts_with("https://"),
                "{} opt-out URL must be https",
                b.domain
            );
            assert!(!b.name.is_empty());
        }
        // Alphabetical by domain (stable review/output order).
        let mut sorted = BROKERS.to_vec();
        sorted.sort_by_key(|b| b.domain);
        assert_eq!(
            BROKERS.iter().map(|b| b.domain).collect::<Vec<_>>(),
            sorted.iter().map(|b| b.domain).collect::<Vec<_>>(),
            "BROKERS must stay sorted by domain"
        );
    }

    /// Drift-guard: every broker the removal registry knows must also be
    /// recognised as a mega/aggregator domain by the engine's expansion gate,
    /// so the two views of "this is a people-search site" can't diverge — the
    /// engine dampens exactly the sites this module offers takedowns for.
    #[test]
    fn every_broker_is_a_known_mega_domain() {
        for b in BROKERS {
            assert!(
                crate::core::scan::is_noncentral_domain(b.domain),
                "broker {} is not in the engine's mega/infra domain list — add it \
                 to MEGA_DOMAINS so expansion still treats it as aggregator noise",
                b.domain
            );
        }
    }
}
