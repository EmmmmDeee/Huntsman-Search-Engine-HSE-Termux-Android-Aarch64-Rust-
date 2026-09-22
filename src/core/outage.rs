//! Network-path outage classification (T6, REQ-RESILIENCE-003) — what kind
//! of trouble stands between the device and the internet, from probe
//! evidence the caller already gathered.
//!
//! Same discipline as [`crate::core::link`]: pure, no I/O, no clock — one
//! [`classify`] entry point over an [`OutagePath`] snapshot the caller
//! assembles, the way `app::signal::link_sweeps_from_history` assembles
//! [`crate::core::link::LinkSweep`]s for `core::link::review`. The probing
//! itself — a DNS lookup, an HTTP request, a TLS handshake — is I/O and
//! belongs in an `app::`/module collector, never here; this module owns only
//! the judgment of what a completed set of probes MEANS.
//!
//! This is deliberately a single-snapshot classifier, not a history review
//! like `core::link::review`: "what kind of trouble is the path in right
//! now" does not need a timeline the way "was I disconnected repeatedly"
//! does. A caller that wants trend/pattern reporting composes it from
//! repeated [`OutageReport`]s the way it already composes anything else from
//! repeated reads — this module does not pre-guess that shape.
//!
//! Named "outage" (matching the directive: DNS failure, captive portals, IP
//! reassignment, routing changes, gateway instability, partial upstream
//! connectivity) rather than "connectivity" or "network": a Wi-Fi link that
//! IS connected can still be in one of these states, which is the whole
//! point — `core::link` says whether the device is ON a network; this module
//! says whether the network it is on actually reaches the internet honestly.
//! "IP reassignment" for the device's OWN interface is not a kind this module
//! classifies — that is already visible as a change in [`crate::core::link::LinkState::ip`]
//! across sweeps, an extension of the existing per-sweep record rather than a
//! second mechanism for the same fact.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// One snapshot of what a caller's probes found, at one moment. Every field
/// is what was OBSERVED, never inferred — an empty/`None` value means the
/// probe was not run or produced no usable answer, and [`classify`] must
/// read that as "no signal from this probe", never as a negative result in
/// its own right.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutagePath {
    /// When the probes ran, Unix seconds.
    pub at: u64,
    /// Addresses the system resolver returned for a pinned, stable probe
    /// domain. Empty means resolution failed or returned nothing usable —
    /// this is the ONLY signal `classify` reads as "DNS is down"; a
    /// non-empty list is "DNS answered", regardless of whether the answer
    /// is later found to disagree with `doh_dns`.
    pub system_dns: Vec<IpAddr>,
    /// Addresses a DNS-over-HTTPS resolver returned for the SAME probe
    /// domain `system_dns` was asked about. `None` means the check was not
    /// run (e.g. DoH is configured off); `Some(empty)` means it ran and also
    /// found nothing.
    pub doh_dns: Option<Vec<IpAddr>>,
    /// A request that never touches DNS at all — an IP-literal request to a
    /// stable anchor — reached its destination. Only the socket-level path
    /// matters here, not what the anchor answered.
    pub ip_literal_reachable: bool,
    /// The HTTP status from a neutral connectivity-check request (the
    /// `generate_204`-shaped probe every mobile OS's own captive-portal
    /// detector uses). `Some(204)` is the expected clean answer; any other
    /// `Some(status)` — most tellingly a `200` with a body — is what a
    /// captive portal answers instead of letting the request through.
    /// `None` means the request itself never completed (no answer at all,
    /// not even a wrong one) — inconclusive, not evidence of a portal.
    pub connectivity_status: Option<u16>,
    /// A TLS handshake to a pinned domain completed and a leaf certificate
    /// was captured.
    pub tls_cert_captured: bool,
    /// The captured leaf certificate's issuer organisation, when the DER
    /// carried a field a reader could extract. Only meaningful when
    /// `tls_cert_captured` is true; `None` beside `tls_cert_captured: true`
    /// means a cert was seen but its issuer field could not be read, which
    /// `classify` treats the same as an unrecognised issuer — a cert this
    /// module cannot identify is not evidence of safety.
    pub tls_issuer_org: Option<String>,
}

/// What the path is in, ranked from the most fundamental problem to the
/// least specific — [`classify`] returns the FIRST of these its evidence
/// supports, so a device with no route at all is never ALSO reported as
/// having a bad certificate on a connection it never made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageKind {
    /// No path exists at all: DNS resolution failed AND a request that never
    /// touches DNS also failed. Not a resolver problem specifically —
    /// nothing reaches the internet from here right now.
    Offline,
    /// DNS resolution failed but a direct path exists: the resolver itself
    /// is down, blocked, or filtered, while the network otherwise has a
    /// route out. Distinct from `Offline` because the fix is different —
    /// change resolver (the DoH fallback already does this for HSE's own
    /// requests), not change network.
    DnsUnavailable,
    /// The system resolver and a DNS-over-HTTPS resolver, asked about the
    /// SAME domain at roughly the same time, returned disjoint address
    /// sets: the two paths tell a different truth for one lookup, which a
    /// healthy resolver should never do for a stable, pinned domain — the
    /// signature of DNS interception or poisoning, not mere unavailability.
    /// Checked before the captive-portal signal because a hijacked resolver
    /// can also make the connectivity probe itself look like a portal; the
    /// upstream cause is reported, not the downstream symptom.
    DnsHijacked,
    /// DNS resolved (through the system resolver, and it was not judged
    /// hijacked) and a direct path exists, but the connectivity probe's
    /// answer was not the expected 204: something between here and the
    /// probe target is intercepting the request and answering for it — the
    /// signature of a captive portal.
    CaptivePortal,
    /// A TLS handshake completed and a certificate was captured, but its
    /// issuer is not on the allow-list of public CAs expected for the
    /// pinned probe domain (or no issuer could be read at all) — the
    /// signature of a TLS-intercepting proxy: a corporate MITM box, a
    /// hostile network, or malware.
    TlsIntercepted,
    /// Every probe that ran behaved as expected. Not a guarantee nothing is
    /// wrong — only that these specific checks found no evidence of it.
    Clear,
}

/// The full result: the kind, and the concrete evidence that earned it, so
/// the operator sees WHY, not only a label — the same discipline as
/// `core::link::Disruption`'s fields and `advice()`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OutageReport {
    /// The kind of trouble the evidence supports — first-match order, see
    /// [`OutageKind`].
    pub kind: OutageKind,
    /// When the probes this classified ran, Unix seconds — carried straight
    /// from [`OutagePath::at`].
    pub at: u64,
    /// A short, human sentence naming the specific evidence.
    pub evidence: String,
}

impl OutageReport {
    /// What an operator can do about it — the same words wherever this is
    /// shown, so the page and the shell cannot drift (the `core::link`
    /// `Disruption::advice` precedent).
    #[must_use]
    pub fn advice(&self) -> &'static str {
        match self.kind {
            OutageKind::Offline => {
                "Nothing reaches the internet from here right now. Check the radio is on \
                 (airplane mode, Wi-Fi/mobile data toggles) and that the access point or \
                 tower itself is up before assuming HSE or the target is at fault."
            }
            OutageKind::DnsUnavailable => {
                "DNS is failing while the network itself has a route out. Try a different \
                 resolver — Android's system-wide Private DNS (Settings > Network > Private \
                 DNS) to a resolver your carrier or network doesn't filter — or wait for the \
                 automatic DNS-over-HTTPS fallback HSE's own requests already use."
            }
            OutageKind::DnsHijacked => {
                "The system resolver and an independent DNS-over-HTTPS resolver disagree on \
                 the same lookup. Do not trust this network's DNS answers for anything \
                 sensitive; set Android's system-wide Private DNS to a resolver you control, \
                 or prefer cell data until this clears."
            }
            OutageKind::CaptivePortal => {
                "Something between here and the internet is intercepting requests and \
                 answering for the real destination — open a browser and complete the \
                 portal's login/terms page, or switch to a network that does not do this \
                 before trusting anything sensitive on it."
            }
            OutageKind::TlsIntercepted => {
                "A certificate on this network was not issued by a recognised public \
                 authority — the connection may be intercepted (a corporate proxy, a hostile \
                 network, or malware on the device). Do not enter credentials on this network \
                 until you know why, and check the device for an unexpected installed \
                 certificate authority."
            }
            OutageKind::Clear => {
                "DNS, direct connectivity, the captive-portal check and the TLS issuer all \
                 read as expected."
            }
        }
    }
}

/// Organisations expected to appear as a leaf certificate's issuer for the
/// pinned TLS probe domain — a conservative allow-list of major public CAs
/// a stable, well-known HTTPS domain is realistically issued by. Absence
/// from this list is the ONLY thing [`classify`] treats as suspicious; it is
/// deliberately never a completeness claim about every legitimate CA in
/// existence, only a check against known-good for the ONE stable domain the
/// caller pins the probe to. Matched by substring (`org.contains(..)`) so an
/// issuer string carrying a suite/jurisdiction suffix (`"DigiCert Inc"` vs a
/// bare `"DigiCert"`) still matches.
pub const EXPECTED_CA_ORGS: &[&str] = &[
    "Google Trust Services",
    "DigiCert",
    "Let's Encrypt",
    "GlobalSign",
    "Amazon",
    "Cloudflare",
    "Sectigo",
    "ISRG",
    "GTS CA",
];

/// True when neither address set is empty and they share no address —
/// a real disagreement between two resolution paths for the same lookup,
/// not merely "one of them found nothing" (that is `DnsUnavailable`'s
/// territory, decided before this is ever reached) and not a false alarm
/// from a multi-address CDN answer that happens to differ in ORDER or in
/// which subset each path returned, as long as the sets overlap at all.
fn disjoint(a: &[IpAddr], b: &[IpAddr]) -> bool {
    !a.is_empty() && !b.is_empty() && !a.iter().any(|x| b.contains(x))
}

/// Classify one probe snapshot. Pure: the same [`OutagePath`] always yields
/// the same [`OutageReport`] (only `at`/`evidence` text vary with the input,
/// never with when this runs).
#[must_use]
pub fn classify(path: &OutagePath) -> OutageReport {
    let at = path.at;
    let mk = |kind: OutageKind, evidence: String| OutageReport { kind, at, evidence };

    let dns_ok = !path.system_dns.is_empty();

    if !dns_ok && !path.ip_literal_reachable {
        return mk(
            OutageKind::Offline,
            "DNS resolution failed and a direct IP-literal request also failed: no path to \
             the internet exists right now."
                .to_string(),
        );
    }
    if !dns_ok {
        return mk(
            OutageKind::DnsUnavailable,
            "DNS resolution failed, but a direct IP-literal request succeeded: the network \
             has a route out, but the DNS resolver is down, blocked, or filtered."
                .to_string(),
        );
    }
    if let Some(doh) = &path.doh_dns
        && disjoint(&path.system_dns, doh)
    {
        return mk(
            OutageKind::DnsHijacked,
            format!(
                "the system resolver returned {:?} and an independent DNS-over-HTTPS resolver \
                 returned {doh:?} for the same lookup — no address in common.",
                path.system_dns
            ),
        );
    }
    if let Some(status) = path.connectivity_status
        && status != 204
    {
        return mk(
            OutageKind::CaptivePortal,
            format!(
                "a neutral connectivity check expected an empty 204 and received {status} \
                 instead: something is intercepting the request and answering for the real \
                 destination."
            ),
        );
    }
    if path.tls_cert_captured {
        let issuer_ok = path
            .tls_issuer_org
            .as_deref()
            .is_some_and(|org| EXPECTED_CA_ORGS.iter().any(|ex| org.contains(ex)));
        if !issuer_ok {
            let issuer = path
                .tls_issuer_org
                .as_deref()
                .unwrap_or("(no issuer field could be read)");
            return mk(
                OutageKind::TlsIntercepted,
                format!(
                    "the pinned domain's certificate was issued by \"{issuer}\", which is not \
                     one of the expected public certificate authorities."
                ),
            );
        }
    }
    mk(
        OutageKind::Clear,
        "DNS, direct connectivity, the captive-portal check and the TLS issuer all read as \
         expected."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    include!("outage_tests.rs");
}
