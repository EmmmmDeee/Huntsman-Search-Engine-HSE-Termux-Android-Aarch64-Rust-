use std::sync::OnceLock;

use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

/// Upstream resolvers, in preference order, that back the shared resolver's
/// self-healing pool:
///
/// 1. **Cloudflare** (`1.1.1.1`) — fastest anycast, privacy-respecting.
/// 2. **Quad9** (`9.9.9.9`) — no-logging, malware-blocking, independent (Swiss).
/// 3. **Google** (`8.8.8.8`) — ubiquitous, rarely blocked.
///
/// One reputable resolver is a single point of failure: networks that block
/// `1.1.1.1` (some mobile carriers, captive portals, and censored regions do)
/// would make **every** DNS-issuing module fail — resources unreachable purely
/// for DNS reasons. A pool of independent providers removes that: if the
/// preferred resolver is blocked or dead, hickory transparently fails over to
/// the next (see [`resolver_config`]).
const PROVIDERS: [hickory_resolver::config::ServerGroup<'static>; 3] = [CLOUDFLARE, QUAD9, GOOGLE];

/// Build the shared resolver's [`ResolverConfig`]: a validated, self-healing
/// pool of the [`PROVIDERS`], mirroring the egress proxy pool's
/// prefer-healthy / route-around-dead design one layer down.
///
/// **Failover is within a single lookup**: hickory's `NameServerPool` tries the
/// servers `num_concurrent_reqs` at a time and, on error or timeout, advances
/// through the *rest* of the pool before giving up — so a blocked preferred
/// resolver falls through to Quad9 then Google in the same query, not only on a
/// later one. Across queries, the default `QueryStatistics` server-ordering
/// then reorders the pool by observed success/latency: a resolver that starts
/// failing is passively demoted and the healthy ones are preferred — validated
/// failover from real outcomes, with no extra probe traffic. This is the DNS
/// analogue of [`crate::util::egress`]'s health-ranked proxy pool.
///
/// **IPv4-only nameservers.** Each provider also publishes IPv6 resolver IPs,
/// but on a v6-less host (this container, many no-root Termux / mobile setups)
/// connecting to them just burns a per-server timeout during failover — the
/// same wedge the `Ipv4thenIpv6` lookup strategy avoids for target records. We
/// keep only the v4 resolver addresses so the pool's worst-case failover stays
/// tightly bounded (6 servers, 2 at a time ⇒ ≤3 rounds); this constrains only
/// which IP we *talk to the resolver over*, never which record types we can
/// resolve (AAAA target lookups are unaffected).
#[must_use]
fn resolver_config() -> ResolverConfig {
    let name_servers = PROVIDERS
        .iter()
        .flat_map(hickory_resolver::config::ServerGroup::udp_and_tcp)
        .filter(|ns| ns.ip.is_ipv4())
        .collect::<Vec<_>>();
    ResolverConfig::from_parts(None, vec![], name_servers)
}

/// The process-wide DNS resolver — a lazily-initialised [`TokioResolver`] backed
/// by a self-healing multi-provider pool (Cloudflare → Quad9 → Google; see
/// [`resolver_config`]) and shared by every DNS-issuing module (`dns_intel`,
/// `geo_intel`, the DNSBL checks, …) so they reuse one connection pool and cache
/// instead of each standing up its own.
///
/// Tuned for **bounded latency over completeness** (the platform's "a slow or
/// dead service degrades the scan, never freezes it" rule): a 2-second timeout
/// with a single attempt so a wedged query fails fast, and an `Ipv4thenIpv6`
/// strategy so a v6-less host doesn't pay the failover tax on every lookup — see
/// the inline notes for the observed wedge this prevents. Initialised once via
/// [`OnceLock`]; the hardcoded config is infallible by construction.
#[must_use]
pub fn shared_resolver() -> &'static TokioResolver {
    static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        use hickory_resolver::config::LookupIpStrategy;
        let mut builder =
            TokioResolver::builder_with_config(resolver_config(), TokioRuntimeProvider::default());
        // Bound DNS like every other external call (Requirement: a slow or
        // dead service degrades the scan, never freezes it). hickory's
        // defaults are 5s timeout x 2 attempts = ~10s PER lookup, and
        // dns_intel issues A/AAAA/MX/NS/SOA/TXT (+ DNSBL) lookups, so a
        // stalled resolver stacked well past the module's 15s budget — an
        // IP scan was observed wedging ~25s on a single DNSBL AAAA query
        // when IPv6 nameserver connect failed (os error 97) and the
        // resolver paid the full v6→v4 failover tax on every lookup.
        //
        // - timeout 2s, attempts 1: a wedged query fails fast and the scan
        //   moves on, staying inside dns_intel's 15s declaration even when
        //   several lookups are slow. One attempt is enough because the
        //   pool already fails over across ALL providers within a single
        //   query (see `resolver_config`) — `attempts` would only add a
        //   redundant second sweep of the same pool.
        // - Ipv4thenIpv6: try the v4 nameserver first so a v6-less host
        //   (this container, many mobile networks) doesn't stall on an
        //   unreachable AAAA nameserver, while v6 still resolves where
        //   available.
        {
            let opts = builder.options_mut();
            opts.timeout = std::time::Duration::from_secs(2);
            opts.attempts = 1;
            opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        }
        builder
            .build()
            .expect("hardcoded multi-provider resolver config must build")
    })
}

// ---------------------------------------------------------------------------
// Outcome classification: "the zone said no" vs "we never got an answer".
//
// The DNS counterpart of the keyed-HTTP family in `crate::util::http`, and
// deliberately shaped the same way so a reader who knows that file knows this
// one:
//
//   util::http                     util::dns              role
//   ---------------------------    --------------------   -------------------
//   is_keyed_error_status          classify               pure classifier
//   http_status_error              lookup_error           uniform Error ctor
//   keyed_ok_or_404                lookup_or_absent       the tri-state
//   (per-module warn + latch)      absent_or_degrade      degrade-and-latch
//   fetch_json_probe               lookup_probe           argued exemption
// ---------------------------------------------------------------------------

use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::op::ResponseCode;

use crate::core::error::{Error, Result};

/// What the resolver actually established about a name, once hickory's
/// [`NetError`] is reduced to the one distinction every caller needs: **did an
/// authority answer, or did we never get an answer at all?**
///
/// * [`Self::NxDomain`] — a **clean miss**, authoritative. The zone answered
///   `NXDOMAIN`: this name does not exist, and no type exists at it.
/// * [`Self::NoData`] — a **clean miss**, type-specific (RFC 2308 "NODATA").
///   The zone answered `NOERROR` with no matching record: the name exists but
///   publishes nothing of the type asked for. This is what "no CAA policy",
///   "no MX", and "no DKIM key at this selector" genuinely look like.
/// * [`Self::Malfunction`] — **no statement was obtained.** `SERVFAIL`,
///   `REFUSED`, a timeout, a blocked port 53, an exhausted connection pool.
///   The question was never answered, so the caller may claim nothing.
///
/// The two clean misses are kept apart because a few callers need the
/// difference: an unclaimed cloud hostname is `NxDomain` (the label is
/// unregistered, hence claimable), whereas `NoData` means the label *does*
/// exist and publishes some other type, which is not claimable.
///
/// The split is hickory's own, stated in the [`NoRecords`] field doc
/// (`hickory-net-0.26.1/src/error.rs:350-351`): "if `NXDOMAIN`, the domain does
/// not exist (and no other types). If `NoError`, then the domain exists but
/// there exist either other types at the same label, or subzones of that
/// label."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsVerdict {
    /// rcode `NXDOMAIN` — the name does not exist.
    NxDomain,
    /// rcode `NOERROR` with no matching answer — the name exists, this record
    /// type at it does not.
    NoData,
    /// No answer was obtained at all.
    Malfunction,
}

impl DnsVerdict {
    /// True when an authority actually answered "no" — i.e. the caller may
    /// treat this as a genuine absence rather than an outage. False only for
    /// [`Self::Malfunction`].
    #[must_use]
    pub fn is_clean_miss(self) -> bool {
        !matches!(self, Self::Malfunction)
    }
}

/// Classify a hickory lookup error: did the zone answer "no", or did we never
/// get an answer? **Pure** — no I/O, independently unit-tested, and the only
/// place in the crate that pattern-matches hickory's error enum. The DNS
/// sibling of [`crate::util::http::is_keyed_error_status`].
///
/// **Deliberately stricter than hickory's own `NetError::is_no_records_found`.**
/// That predicate (`hickory-net-0.26.1/src/error.rs:160-162`) matches
/// `NoRecordsFound` *regardless of rcode*, and
/// `hickory-resolver-0.26.1/src/name_server.rs:132-135` matches a [`NoRecords`]
/// carrying `ResponseCode::ServFail` — so a SERVFAIL can sit inside a
/// `NoRecordsFound` and hickory's predicate calls it a miss. Verified by
/// construction in `classify_does_not_trust_hickorys_is_no_records_found_for_servfail`,
/// which asserts `is_no_records_found()` is `true` for exactly that value while
/// this function returns [`DnsVerdict::Malfunction`]. Using the upstream
/// shorthand would launder a broken authority into a clean bill of health.
///
/// Both hickory enums are `#[non_exhaustive]`, so the trailing arm is
/// mandatory. It lands in [`DnsVerdict::Malfunction`] on purpose: a future
/// hickory variant must degrade into "we don't know", never into a fabricated
/// clean answer.
#[must_use]
pub fn classify(err: &NetError) -> DnsVerdict {
    match err {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NXDomain,
            ..
        })) => DnsVerdict::NxDomain,
        NetError::Dns(DnsError::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NoError,
            ..
        })) => DnsVerdict::NoData,
        _ => DnsVerdict::Malfunction,
    }
}

/// Build the uniform [`Error::module`] for a DNS malfunction —
/// `"<TYPE> lookup for <name> failed: <resolver error>"`, rendered by
/// `Error::Module`'s Display as
/// `[dns_intel] CAA lookup for example.com failed: request timed out`.
///
/// The single source of the DNS error construction, so every DNS-issuing module
/// reports a failure identically. Sibling of
/// [`crate::util::http::http_status_error`]. `record_type` is a display label
/// (`"A/AAAA"`, `"MX"`, `"CAA"`, `"PTR"`), not a `RecordType`, so a composite
/// lookup such as `lookup_ip` can name what it actually asked for.
#[must_use]
pub fn lookup_error(module: &str, record_type: &str, name: &str, err: &NetError) -> Error {
    Error::module(
        module,
        format!("{record_type} lookup for {name} failed: {err}"),
    )
}

/// Classify an awaited resolver outcome into the house tri-state — the DNS
/// counterpart of [`crate::util::http::keyed_ok_or_404`].
///
/// * `Ok(Some(answer))` — the resolver answered.
/// * `Ok(None)` — a **clean miss**: `NXDOMAIN`, or `NOERROR` with no matching
///   record. An authority answered; there is genuinely nothing here. Callers
///   map this to empty findings (**was**: byte-identical to a timeout).
/// * `Err` — a **malfunction**: `SERVFAIL`, `REFUSED`, a timeout, a blocked
///   port 53. No statement about the name was obtained at all, so the caller
///   must not report a negative (**was**: an empty success, indistinguishable
///   from "nothing here").
///
/// **`Ok(Some(_))` does not imply a non-empty answer set.** hickory returns
/// `Ok` for a truncated response, for an `NXDOMAIN` carrying a CNAME referral,
/// and for an unknown rcode; and its `contains_answer()` searches the
/// AUTHORITY/ADDITIONAL sections too, so a match found only there yields `Ok`
/// with an empty `answers()` slice. Every caller's existing
/// `answers().is_empty()` / `iter().next()` emptiness check therefore stays
/// load-bearing and must be kept — this helper does not and cannot do it for
/// them (`Lookup` and `LookupIp` share no answers accessor).
///
/// Takes an already-awaited outcome rather than performing the lookup, for the
/// same reason [`crate::util::http::keyed_ok_or_404`] takes an already-sent
/// `reqwest::Response`: `dns_intel::resolve_records` fires seven lookups in one
/// `tokio::join!` and classifies afterwards, and the eleven lookup methods have
/// three different argument shapes across two return types. Keeping it
/// synchronous and I/O-free also makes it unit-testable with a constructed
/// [`NetError`] — no runtime, no listener, no network.
///
/// Pairs with `let-else`:
///
/// ```ignore
/// // NXDOMAIN/NODATA → clean miss; SERVFAIL/REFUSED/timeout/transport → Err.
/// let Some(lookup) = crate::util::dns::lookup_or_absent(
///     SRC, "CAA", domain, resolver.lookup(domain, RecordType::CAA).await,
/// )? else {
///     return Ok(Vec::new());
/// };
/// ```
pub fn lookup_or_absent<T>(
    module: &str,
    record_type: &str,
    name: &str,
    outcome: std::result::Result<T, NetError>,
) -> Result<Option<T>> {
    match outcome {
        Ok(answer) => Ok(Some(answer)),
        Err(e) if classify(&e).is_clean_miss() => Ok(None),
        Err(e) => Err(lookup_error(module, record_type, name, &e)),
    }
}

/// [`lookup_or_absent`] for a caller that must **degrade rather than
/// propagate**: one record class failing must never discard the classes that
/// succeeded.
///
/// A clean miss and a malfunction both yield `None` *to this call*, but they
/// are no longer indistinguishable to the module: a malfunction is logged
/// through the house `tracing::warn!` path and latched into `first_failure`,
/// which the caller hands to
/// [`crate::core::module::ModuleResult::or_hard_failure`] at the end of
/// `process()`. The module therefore errors **only** when it collected nothing
/// at all *and* something genuinely malfunctioned — a total outage — and stays
/// a silent, honest empty on the partial-failure case a flaky mobile link
/// produces constantly.
///
/// **That asymmetry is the regression guard**, and it is why a clean miss must
/// never latch: a domain that simply publishes no MX, no CAA and no SRV — the
/// overwhelmingly common case — puts zero pressure on `circuit::record_error`.
/// Pinned by `degrade_latches_only_the_malfunction_and_keeps_the_first`.
///
/// Bundling classify + `warn!` + latch into one call is deliberate: the three
/// steps are easy to separate and easy to forget, and a forgotten
/// `first_failure.get_or_insert(e)` silently restores the very bug this
/// taxonomy exists to remove.
pub fn absent_or_degrade<T>(
    module: &str,
    record_type: &str,
    name: &str,
    outcome: std::result::Result<T, NetError>,
    first_failure: &mut Option<Error>,
) -> Option<T> {
    match lookup_or_absent(module, record_type, name, outcome) {
        Ok(answer) => answer,
        Err(e) => {
            tracing::warn!(
                module,
                record_type,
                name,
                error = %e,
                "DNS lookup failed — this record class is omitted from the result"
            );
            first_failure.get_or_insert(e);
            None
        }
    }
}

/// A *speculative candidate probe*: like [`lookup_or_absent`], but ALSO treats a
/// resolver malfunction as a miss (`None`) rather than an error.
///
/// This is for the enumeration sweeps that resolve a large dictionary of
/// hostnames the zone is overwhelmingly expected NOT to publish — 146
/// brute-force labels, up to 80 permutations, 41 DKIM selectors, 35 SRV
/// services, 128 typosquat lookalikes, and the two wildcard canaries that are
/// *designed* never to resolve. For such a probe, "the zone has no such name"
/// and "that one lookup failed" are the same negative answer, and the sweep's
/// aggregate result is unharmed by losing one candidate in a hundred.
///
/// It returns `Option<T>` (not `Result`) precisely because there is no error a
/// caller could act on, and because routing hundreds of expected negatives
/// through the error channel would inflate `stats.errored`, feed
/// `circuit::record_error`, and eventually stop `dns_intel` being dispatched at
/// all. A *malfunction* — never a clean miss, which is the expected answer and
/// far too frequent to log — is recorded at `debug` so a sweep-wide outage is
/// still traceable in the verbose log ring without polluting the event stream.
///
/// Do NOT use this where the lookup IS the module's answer — a CNAME target's
/// existence, a zone's NS set, an email domain's MX, a DNSBL verdict. There a
/// malfunction IS actionable and must surface: use [`lookup_or_absent`].
#[must_use]
pub fn lookup_probe<T>(
    module: &str,
    record_type: &str,
    name: &str,
    outcome: std::result::Result<T, NetError>,
) -> Option<T> {
    match outcome {
        Ok(answer) => Some(answer),
        Err(e) if classify(&e).is_clean_miss() => None,
        Err(e) => {
            tracing::debug!(
                module,
                record_type,
                name,
                error = %e,
                "candidate probe hit a resolver malfunction — treating as a clean miss"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    use hickory_resolver::proto::op::Query;
    use hickory_resolver::proto::rr::{Name, RecordType};

    /// Build the exact [`NetError`] hickory delivers for a negative answer, with
    /// no network, no resolver and no runtime. `DnsError::from_response`
    /// (`hickory-net-0.26.1/src/error.rs:278-328`) produces this value for both
    /// `NXDOMAIN` and `NOERROR`-with-no-answer, so a test built on it exercises
    /// the real production type rather than a stand-in. This is why the DNS
    /// split needs no loopback nameserver, unlike its HTTP sibling in
    /// `src/util/http/tests.rs:368-411`.
    fn negative_answer(name: &str, record_type: RecordType, code: ResponseCode) -> NetError {
        NetError::from(NoRecords::new(
            Query::query(
                Name::from_ascii(name).expect("valid test name"),
                record_type,
            ),
            code,
        ))
    }

    #[test]
    fn classify_separates_nxdomain_from_nodata() {
        let nx = negative_answer("nope.example.com.", RecordType::A, ResponseCode::NXDomain);
        assert_eq!(classify(&nx), DnsVerdict::NxDomain);
        assert!(classify(&nx).is_clean_miss());

        // rcode NOERROR with no matching answer: the name exists, the type does
        // not. `subdomain_takeover` must NOT read this as a claimable label.
        let nodata = negative_answer("example.com.", RecordType::CAA, ResponseCode::NoError);
        assert_eq!(classify(&nodata), DnsVerdict::NoData);
        assert!(classify(&nodata).is_clean_miss());
    }

    #[test]
    fn classify_calls_every_transport_failure_a_malfunction() {
        // Every `NetError` variant reachable under this crate's feature set
        // (default-features = false, features = ["tokio"]), plus the two rcode
        // errors that arrive as a DIFFERENT `DnsError` variant than
        // `NoRecordsFound` and so would slip past a NoRecordsFound-only test.
        for err in [
            NetError::Timeout,
            NetError::NoConnections,
            NetError::Busy,
            NetError::QueryCaseMismatch,
            NetError::Message("boom"),
            NetError::Msg("boom".to_string()),
            NetError::Io(std::sync::Arc::new(std::io::Error::other(
                "port 53 blocked",
            ))),
            NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
            NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)),
        ] {
            assert_eq!(classify(&err), DnsVerdict::Malfunction, "{err}");
            assert!(!classify(&err).is_clean_miss(), "{err}");
        }
    }

    #[test]
    fn classify_does_not_trust_hickorys_is_no_records_found_for_servfail() {
        // The load-bearing correction. `NetError::is_no_records_found`
        // (hickory-net-0.26.1/src/error.rs:160-162) matches `NoRecordsFound`
        // regardless of rcode, and hickory-resolver-0.26.1/src/name_server.rs:132-135
        // matches a `NoRecords` carrying ServFail — so a SERVFAIL can sit inside
        // a NoRecordsFound and hickory's own predicate calls it a miss.
        // `classify` matches the rcode explicitly instead. If this assertion
        // ever flips, the upstream taxonomy moved and `classify` should be
        // revisited, not silenced.
        let servfail = negative_answer("example.com.", RecordType::A, ResponseCode::ServFail);
        assert!(
            servfail.is_no_records_found(),
            "hickory's own predicate calls a ServFail-bearing NoRecords a miss"
        );
        assert_eq!(
            classify(&servfail),
            DnsVerdict::Malfunction,
            "an rcode we never asked about must never render as a clean miss"
        );
        assert!(lookup_or_absent::<u8>("m", "A", "example.com", Err(servfail)).is_err());
    }

    #[test]
    fn lookup_or_absent_maps_a_negative_answer_to_none_but_propagates_a_timeout_as_err() {
        // The contract every DNS-issuing module now relies on, and the reason
        // this taxonomy exists: a genuine "the zone says no" is a clean miss the
        // caller maps to empty findings, while a timeout / SERVFAIL / blocked
        // port 53 is a real outage that MUST surface as `Err` — never collapse
        // into the same empty result. That collapse is the T2.115 defect class;
        // on Termux, where port 53 is routinely blocked, it made "no such
        // record" and "we never asked" render identically. Sibling of
        // `fetch_json_or_404_maps_404_to_none_but_propagates_5xx_as_err`
        // (src/util/http/tests.rs:414), which pins the HTTP half.
        let nx = negative_answer("nope.example.com.", RecordType::A, ResponseCode::NXDomain);
        let absent: Result<Option<u8>> = lookup_or_absent("t", "A", "nope.example.com", Err(nx));
        assert!(matches!(absent, Ok(None)), "NXDOMAIN is a clean miss");

        let nodata = negative_answer("example.com.", RecordType::MX, ResponseCode::NoError);
        let absent: Result<Option<u8>> = lookup_or_absent("t", "MX", "example.com", Err(nodata));
        assert!(matches!(absent, Ok(None)), "NODATA is a clean miss");

        let errored: Result<Option<u8>> =
            lookup_or_absent("t", "A", "example.com", Err(NetError::Timeout));
        assert!(errored.is_err(), "a timeout must not masquerade as absence");

        let answered: Result<Option<u8>> = lookup_or_absent("t", "A", "example.com", Ok(7));
        assert!(matches!(answered, Ok(Some(7))));
    }

    #[test]
    fn lookup_error_names_the_module_the_record_type_and_the_name() {
        let e = lookup_error("dns_intel", "CAA", "example.com", &NetError::Timeout);
        assert_eq!(
            e.to_string(),
            "[dns_intel] CAA lookup for example.com failed: request timed out"
        );
    }

    #[test]
    fn degrade_latches_only_the_malfunction_and_keeps_the_first() {
        let mut first: Option<Error> = None;

        // A clean miss degrades to None WITHOUT latching a failure. This is the
        // executable form of the whole regression-safety argument: a domain that
        // simply publishes no MX can never reach `circuit::record_error`.
        assert!(
            absent_or_degrade::<u8>(
                "dns_intel",
                "MX",
                "example.com",
                Err(negative_answer(
                    "example.com.",
                    RecordType::MX,
                    ResponseCode::NoError
                )),
                &mut first,
            )
            .is_none()
        );
        assert!(first.is_none(), "a clean miss must not latch a failure");

        assert!(
            absent_or_degrade::<u8>(
                "dns_intel",
                "NS",
                "first.example.com",
                Err(NetError::Timeout),
                &mut first,
            )
            .is_none()
        );
        assert!(
            absent_or_degrade::<u8>(
                "dns_intel",
                "TXT",
                "second.example.com",
                Err(NetError::NoConnections),
                &mut first,
            )
            .is_none()
        );
        let latched = first.expect("a malfunction latches").to_string();
        assert!(
            latched.contains("first.example.com"),
            "the FIRST failure is kept: {latched}"
        );

        // An answer passes straight through and never latches.
        let mut clean: Option<Error> = None;
        assert_eq!(
            absent_or_degrade("dns_intel", "A", "example.com", Ok(7u8), &mut clean),
            Some(7)
        );
        assert!(clean.is_none());
    }

    #[test]
    fn lookup_probe_never_errors_so_a_dictionary_sweep_cannot_trip_the_breaker() {
        // The protected set: 146 brute-force labels (dns_intel/constants.rs:6),
        // up to 80 permutations, 41 DKIM selectors, 35 SRV services, 128
        // typosquat candidates, and 2 wildcard canaries designed never to
        // resolve. Routing those expected negatives through the error channel
        // would inflate stats.errored, feed circuit::record_error, and via
        // scraper_health's yield-drift quarantine eventually stop dns_intel
        // being dispatched at all. `lookup_probe` returns `Option` for exactly
        // that reason.
        let nx = negative_answer("zz.example.com.", RecordType::A, ResponseCode::NXDomain);
        assert_eq!(
            lookup_probe::<u8>("t", "A/AAAA", "zz.example.com", Err(nx)),
            None
        );
        assert_eq!(
            lookup_probe::<u8>("t", "A/AAAA", "zz.example.com", Err(NetError::Timeout)),
            None,
            "even a malfunction stays a miss here — logged at debug, never raised"
        );
        assert_eq!(
            lookup_probe("t", "A/AAAA", "zz.example.com", Ok(7u8)),
            Some(7)
        );
    }

    #[test]
    fn pool_spans_all_three_providers() {
        let cfg = resolver_config();
        let ips: Vec<IpAddr> = cfg.name_servers.iter().map(|ns| ns.ip).collect();
        // One dead/blocked provider must never take DNS down: each independent
        // network is represented so failover has somewhere to go.
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "Cloudflare"
        );
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            "Quad9"
        );
        assert!(
            ips.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            "Google"
        );
    }

    #[test]
    fn pool_is_ipv4_only() {
        // v6 resolver IPs would burn a connect timeout per server during
        // failover on a v6-less host; the pool must carry none.
        let cfg = resolver_config();
        assert!(
            cfg.name_servers.iter().all(|ns| ns.ip.is_ipv4()),
            "no IPv6 resolver addresses in the pool"
        );
        assert!(!cfg.name_servers.is_empty(), "pool is populated");
    }

    #[test]
    fn preferred_resolver_is_cloudflare() {
        // Ordering seeds hickory's QueryStatistics pool; the fastest, most
        // privacy-respecting provider leads before real stats accrue.
        let cfg = resolver_config();
        assert_eq!(
            cfg.name_servers.first().map(|ns| ns.ip),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "Cloudflare is tried first"
        );
    }

    #[tokio::test]
    async fn resolver_initialises() {
        // The hardcoded config must actually build a resolver (the `expect` in
        // `shared_resolver` never fires) and be process-shared (same pointer).
        // Built inside a runtime because the Tokio-backed resolver expects one.
        let a = shared_resolver();
        let b = shared_resolver();
        assert!(std::ptr::eq(a, b), "one shared resolver, not per-call");
    }
}
