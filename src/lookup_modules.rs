//! Which modules each lookup kind may ask, by the names a scan chooses them by, so a scan that
//! chose modules runs only the lookups that ask one of them, and refuses a target none of them
//! looks up, as Spiderfoot runs no module that does not take a target's type.
//!
//! The lists are built from the same tables the lookups run (the DNS blocklist zones, the
//! filtering resolvers, the threat feeds and the indicator sources), and the tests hold each
//! lookup to its list: every module a lookup asks is on it, and a lookup that asks none of the
//! chosen modules sends nothing.

use crate::dns_filter;
use crate::dnsbl::{self, Takes};
use crate::indicator_legs;
use crate::indicator_sources::IndicatorKind;
use crate::module_selection::Selection;
use crate::scan_route::ScanKind;
use crate::threat_feeds;
use crate::{
    abuseipdb, asic_director, asic_persons, blockchain, bluesky_user, certspotter, dehashed,
    duolingo, exposure_cli, github_user, gravatar, greynoise, hunter, internetdb, keybase,
    mnemonic, nominatim, numverify, oathnet, openpgp_keys, rdap, ripestat, seeknow_collector,
    tiktok_public_contact, virustotal, wigle, wikipedia,
};

/// The breach legs an email address's lookup folds in.
const BREACH: [&str; 4] = [
    exposure_cli::HIBP_MODULE,
    exposure_cli::STOLEN_TAX_SOURCE,
    oathnet::SOURCE,
    dehashed::COLLECTOR_ID,
];

/// Every module `kind`'s lookup may ask, each once, in the order it asks them. **Pure.**
#[must_use]
pub fn modules(kind: ScanKind) -> Vec<&'static str> {
    let modules: Vec<&'static str> = match kind {
        ScanKind::Ip => {
            let mut ip = vec![
                crate::dns::RESOLVE_SOURCE,
                rdap::SOURCE,
                mnemonic::SOURCE,
                internetdb::SOURCE,
                ripestat::SOURCE,
                greynoise::SOURCE,
            ];
            ip.extend(zones(|takes| takes != Takes::Domains));
            ip.extend([abuseipdb::SOURCE, virustotal::SOURCE]);
            ip.extend(indicators(IndicatorKind::Ip));
            ip.extend(feeds());
            ip
        }
        ScanKind::Domain => {
            let mut domain = vec![
                "crtsh",
                certspotter::SOURCE,
                crate::wayback_cdx::SOURCE,
                "dns",
                rdap::SOURCE,
                mnemonic::SOURCE,
            ];
            domain.extend(zones(|takes| {
                matches!(takes, Takes::Domains | Takes::Ipv4AndDomains)
            }));
            domain.extend(dns_filter::FILTERS.iter().map(|filter| filter.source));
            domain.extend([virustotal::SOURCE, hunter::SOURCE]);
            domain.extend(indicators(IndicatorKind::Domain));
            domain.push(crate::dns::RESOLVE_SOURCE);
            domain.extend(feeds());
            domain
        }
        ScanKind::Netblock => {
            let mut netblock = vec![rdap::SOURCE, ripestat::SOURCE, crate::dns::RESOLVE_SOURCE];
            netblock.extend(feeds());
            netblock
        }
        ScanKind::Asn => vec![rdap::SOURCE, ripestat::SOURCE],
        ScanKind::Email => {
            let mut email = vec![gravatar::SRC, duolingo::SRC, openpgp_keys::SRC];
            email.extend(indicators(IndicatorKind::Email));
            email.push(seeknow_collector::COLLECTOR_ID);
            email.extend(BREACH);
            email
        }
        ScanKind::Username => vec![
            github_user::SRC,
            bluesky_user::SRC,
            keybase::SRC,
            wikipedia::SRC,
            crate::mastodon_user::SRC,
            tiktok_public_contact::SRC,
            seeknow_collector::COLLECTOR_ID,
            exposure_cli::STOLEN_TAX_SOURCE,
            oathnet::SOURCE,
        ],
        ScanKind::Phone => {
            let mut phone = vec![numverify::SOURCE];
            phone.extend(indicators(IndicatorKind::Phone));
            phone
        }
        ScanKind::People => vec![
            asic_persons::SRC,
            asic_director::SRC,
            seeknow_collector::COLLECTOR_ID,
        ],
        ScanKind::Network => {
            let mut network = vec![wigle::SOURCE];
            network.extend(indicators(IndicatorKind::Cell));
            network
        }
        ScanKind::Exposure => BREACH.to_vec(),
        ScanKind::CryptoAddress => vec![blockchain::SOURCE],
        ScanKind::Place => vec![nominatim::SOURCE],
    };
    // Stable deduplication keeps each source's first execution position and
    // avoids a tree allocation for the small, bounded module list.
    let mut unique = Vec::with_capacity(modules.len());
    for module in modules {
        if !unique.contains(&module) {
            unique.push(module);
        }
    }
    unique
}

/// Whether `kind`'s lookup asks any module `selection` runs. **Pure.**
#[must_use]
pub fn asks_any(kind: ScanKind, selection: &Selection) -> bool {
    modules(kind).iter().any(|module| selection.runs(module))
}

/// The lookup kinds that ask `module`, by their commands (`ip`, `domain`), in [`ScanKind`]'s
/// order: what a New Scan page shows each module looks up. `module` may be a label a Sources
/// table shows (`hibp_account`, `wigle_bluetooth`, `asic_persons.banned`), which names its
/// module. **Pure.**
#[must_use]
pub fn lookups_asking(module: &str) -> Vec<&'static str> {
    let module = crate::module::module_of(module);
    ScanKind::ALL
        .iter()
        .filter(|kind| modules(**kind).contains(&module))
        .map(|kind| kind.command())
        .collect()
}

/// The offline modules `kind`'s lookup runs over the target itself, whatever was chosen. They
/// ask nothing, so they are on no lookup's list and choosing one alone chooses no lookup; a scan's
/// Sources table still shows them. **Pure.**
#[must_use]
pub fn offline_runs(kind: ScanKind) -> Vec<&'static str> {
    match kind {
        ScanKind::Email => vec!["email_parse"],
        ScanKind::Username => vec!["username_variants"],
        ScanKind::Phone => vec!["phone_intl", "phone_au", crate::phone_cli::NANP_SOURCE],
        ScanKind::Network => vec![crate::network_cli::OUI_SOURCE],
        ScanKind::Ip
        | ScanKind::Domain
        | ScanKind::Netblock
        | ScanKind::Asn
        | ScanKind::People
        | ScanKind::Exposure
        | ScanKind::CryptoAddress
        | ScanKind::Place => Vec::new(),
    }
}

/// The lookup kinds that run `module` offline, by their commands, in [`ScanKind`]'s order: what a
/// New Scan page says instead of "no scan lookup asks it". **Pure.**
#[must_use]
pub fn lookups_running_offline(module: &str) -> Vec<&'static str> {
    let module = crate::module::module_of(module);
    ScanKind::ALL
        .iter()
        .filter(|kind| offline_runs(**kind).contains(&module))
        .map(|kind| kind.command())
        .collect()
}

fn zones(asked: impl Fn(Takes) -> bool) -> impl Iterator<Item = &'static str> {
    dnsbl::ZONES
        .iter()
        .filter(move |zone| asked(zone.takes))
        .map(|zone| zone.source)
}

fn indicators(kind: IndicatorKind) -> impl Iterator<Item = &'static str> {
    indicator_legs::SOURCES
        .iter()
        .filter(move |source| source.kinds.iter().any(|k| k.within(kind)))
        .map(|source| source.api.source)
}

fn feeds() -> impl Iterator<Item = &'static str> {
    threat_feeds::FEEDS.iter().map(|feed| feed.source)
}

#[cfg(test)]
mod tests;
