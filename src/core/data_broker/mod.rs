//! Data-broker / people-search recognition — the data-LOCATION surface.
//!
//! HSE is itself an information broker; this module is how it recognises *other*
//! brokers. When a scan finds the subject listed on a people-search aggregator
//! (Spokeo, BeenVerified, Whitepages, …), that listing is a concrete location
//! finding: the subject's PII is being brokered/redistributed by that site.
//! This is the single source of truth mapping a broker domain to its display
//! name, so the correlator (AU-054) can surface *where the subject's data
//! lives* — squarely the current locating phase, not a takedown step.
//!
//! Pure data + a suffix lookup; no I/O.
//!
//! These domains are deliberately a subset of the OSINT-aggregator block in
//! [`crate::core::scan`]'s mega-domain list (the engine already dampens them as
//! expansion noise); a test pins that every broker here is recognised there, so
//! the two views of "this is a people-search site" can't drift apart.

/// One people-search / data-broker site that may host the subject's PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBroker {
    /// Registrable domain, lowercase, no `www.` (the suffix matched against a
    /// discovered host).
    pub domain: &'static str,
    /// Operator-facing display name.
    pub name: &'static str,
}

/// The curated broker registry. Kept alphabetical by domain for stable output
/// and easy review.
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
        domain: "locatefamily.com",
        name: "LocateFamily",
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
        domain: "radaris.com",
        name: "Radaris",
    },
    DataBroker {
        domain: "socialcatfish.com",
        name: "Social Catfish",
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
        domain: "usphonebook.com",
        name: "USPhonebook",
    },
    DataBroker {
        domain: "whitepages.com",
        name: "Whitepages",
    },
    DataBroker {
        domain: "whitepages.com.au",
        name: "White Pages Australia",
    },
    DataBroker {
        domain: "zabasearch.com",
        name: "ZabaSearch",
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
    include!("tests.rs");
}
