//! Canonical entity tag string constants. One definition so a tag a
//! module emits and a correlator rule matches on can't drift in spelling.
//!
//! A tag records **how a value was learned, or what it is** — never a
//! conclusion. What a tag *causes* lives in the pass or rule that reads it, and
//! each constant below names its consumers so the effect of adding one to an
//! entity is discoverable from here rather than by grep.

/// The value came out of a **breach corpus** — a compromised-credential dump or
/// a breach-search provider's index.
///
/// Read in three places: [`crate::core::engine`]'s enrichment gates
/// `tag_breach_sector` on it (a non-breach entity has no breach sector to
/// classify), the AU-061 geo-corroboration pass requires it before it will
/// promote a [`CANDIDATE`], and lead triage counts it alongside [`STEALER_LOG`]
/// and [`BREACH_DERIVED`] as breach-class provenance.
pub const BREACH: &str = "breach";
/// The value came from an **infostealer log** specifically — malware exfil from
/// an infected device, not a service-side database breach.
///
/// Narrower and more serious than [`BREACH`]: it implies a compromised *device*,
/// so the breach correlator treats a stealer-logged `Email` as its own signal
/// rather than folding it in with dump-sourced addresses.
pub const STEALER_LOG: &str = "stealer-log";
/// Observed over HTTP(S) by a module that fetched the host itself — the crawler
/// and the server-banner probe.
pub const WEB: &str = "web";
/// Reached by this scan's own crawler, as opposed to being reported by a
/// third-party index. Always accompanies [`WEB`] on crawled output.
pub const CRAWLED: &str = "crawled";
/// A `Domain` that is a **subdomain of the target**, not an independent one.
///
/// Emitted by every enumeration path (CT logs, passive DNS, aggregated corpora).
/// The audit's pollution check reads it as an exemption: a low-confidence
/// subdomain is expected output for a domain scan, so it is excluded from the
/// "generic low-confidence domains" finding that flags an unfocused scan.
pub const SUBDOMAIN: &str = "subdomain";
/// Points **away from the target** — an off-site link the crawler followed to,
/// an MX host in someone else's zone, a third-party reference. Marks the value
/// as related-to but not owned-by the subject.
pub const EXTERNAL: &str = "external";
/// Lifted from **rendered page text** rather than a structured API field, by the
/// crawler or a search provider that returns page content. Text-mined values
/// carry the extractor's false-positive risk, which a typed API field does not.
pub const WEB_SCRAPED: &str = "web-scraped";
/// Recovered from a **Certificate Transparency log** — a SAN or issuer field in
/// a publicly logged certificate.
pub const CT_LOG: &str = "ct-log";
/// A `Domain` derived from an IP's **reverse-DNS (PTR) record**. The operator of
/// the address chose this name, so it evidences hosting rather than ownership.
pub const PTR: &str = "ptr";
/// The identifier appears across an unusually **large number of breaches**, as
/// judged by the emitting provider's own count.
pub const HIGH_EXPOSURE: &str = "high-exposure";
/// The value was published in a **paste** (Pastebin and similar), rather than in
/// a breach dump.
pub const PASTE_EXPOSED: &str = "paste-exposed";
/// A **password or credential** for this identity is present in the source
/// corpus — not merely the identity's existence in a breach.
pub const PASSWORD_AT_RISK: &str = "password-at-risk";
/// The identity appears on **more than one compromised device** in stealer-log
/// data, which distinguishes a reused personal account from a one-off infection.
pub const MULTI_DEVICE: &str = "multi-device";
/// The crawled host is **missing security response headers**. A property of the
/// server's configuration, recorded as exposure context.
pub const MISSING_SECURITY_HEADERS: &str = "missing-security-headers";

// Geolocation
/// The location came from a **geospatial source** — a gazetteer/OSM lookup, a
/// mail-header trace, an externally-published address — rather than being
/// inferred from the entity's own text.
///
/// Used as a quality signal by the address→coordinates enrichment in
/// [`crate::core::engine`]: a `geoint` address that is also a professional or
/// [`SOCIAL_PROFILE`] address counts as externally validated, which lowers its
/// confidence gate from 0.45 to 0.40 so conservatively-scored but real addresses
/// still reach the footprint.
pub const GEOINT: &str = "geoint";
/// An IP worth geolocating, but **not itself a location**. Carried by addresses
/// that breach and stealer-log records attach to an identity.
///
/// The location correlator selects on exactly `IpAddress` + this tag. It is a
/// no-fabrication device: the module states "here is where to look" instead of
/// emitting coordinates it cannot stand behind.
pub const GEOLOCATION_LEAD: &str = "geolocation-lead";
/// The place is **an area, not a point** — a postcode, suburb or city centroid
/// standing in for a precise address.
///
/// Three separate passes refuse to treat it as precise, and this is the tag's
/// whole purpose. A coarse `Address` is not a cross-scan bridge
/// (`engine::history`), never links a household (`relation::builders` —
/// two people sharing a postcode are not co-residents), and is not pivoted for
/// recursive expansion (`engine`, which records the skip as
/// `coarse_geo_not_pivoted`). It is still admissible as evidence; only these
/// three inferences are withheld.
pub const COARSE: &str = "coarse";
/// Datacenter / CDN / cloud-host location, not a residence. Carried by
/// coordinates that geolocate a hosting IP (e.g. a Cloudflare edge), so the
/// area-of-operation rule (AU-052) can exclude them from a person's footprint.
pub const HOSTING: &str = "hosting";
/// Shared / third-party **platform infrastructure** — cloud-storage buckets,
/// datacenter/CDN hosting endpoints, and third-party analytics IDs. Not
/// subject-owned, so the default report ([`crate::api::scan_export`]) suppresses
/// it (restorable via `--include-infra` / `--output full`) and the location
/// rules keep it out of the subject's physical footprint. Stamped by the
/// `tag_platform_infra` enrichment pass in [`crate::core::engine`].
pub const PLATFORM_INFRA: &str = "platform-infra";
/// A WHOIS/RDAP **registrant** location — the domain owner's filing or privacy
/// address (often a registrar's privacy service), not the scan subject's home.
/// Carried by the address/coordinates a WHOIS record yields so the geo rules
/// can keep it out of the subject's physical footprint (see
/// `is_infrastructure_geo`, AU-018/026/030).
pub const REGISTRANT: &str = "registrant";

// Device / local
/// A **Wi-Fi access point** — observed by the on-device radio scan, or looked up
/// in a wardriving database by BSSID.
///
/// Two geo rules read it: AU-013 counts it as a LAN-adjacency signal alongside
/// [`LOCAL_ARP`] and [`LOCAL_INTERFACE`], and the presence profile counts it as
/// passive corroboration of physical presence, independent of any GPS fix.
pub const WIFI_AP: &str = "wifi-ap";
/// A **cellular tower** the device observed, or one resolved from a
/// `MCC/MNC/LAC/CID` against a tower database. Like [`WIFI_AP`], it corroborates
/// presence in the geo profile without depending on a satellite fix.
pub const CELL_TOWER: &str = "cell-tower";
/// Seen in the device's own **ARP table** — a host on the same layer-2 segment.
/// One of AU-013's three LAN-adjacency tags.
pub const LOCAL_ARP: &str = "local-arp";
/// An address **belonging to a local network interface** of the device running
/// the scan, rather than to a discovered peer. Also an AU-013 LAN tag.
pub const LOCAL_INTERFACE: &str = "local-interface";

// Reputation / threat
/// A **threat-intelligence provider reported on this entity** — the neutral
/// fact of a reputation lookup having returned something, which is not the same
/// as a bad verdict. [`MALICIOUS`] is the verdict.
///
/// The infrastructure correlator pairs it with a benign-infrastructure filter,
/// so a shared CDN or cloud endpoint that any reputation feed will mention does
/// not become a finding about the subject.
pub const THREAT_INTEL: &str = "threat-intel";
/// A reputation source **judged this entity malicious**.
///
/// The correlator does not act on one opinion: its infrastructure rule requires
/// the entity to be non-benign infrastructure *and* corroborated by at least two
/// sources before the verdict is escalated.
pub const MALICIOUS: &str = "malicious";
/// The address is a **Tor exit node**. Grouped with the other anonymising-network
/// tags by the infrastructure correlator — it says traffic was relayed, not that
/// the subject was at that address.
pub const TOR_EXIT: &str = "tor-exit";
/// The address is a **proxy**. Like [`TOR_EXIT`], an attribution caveat: it
/// breaks the link between the address and a physical location.
pub const PROXY: &str = "proxy";
/// The address belongs to a **VPN** provider — the same attribution caveat as
/// [`PROXY`] and [`TOR_EXIT`].
pub const VPN: &str = "vpn";
/// The host or resource is **exposed or misconfigured** — an AXFR-open zone, a
/// world-readable storage bucket, a service a scanner flagged.
///
/// One of the infrastructure correlator's exposure tags, and the specific
/// condition its open-cloud-storage rule looks for. Defensive by construction:
/// it records that an exposure exists, not how to use it.
pub const VULNERABLE: &str = "vulnerable";

// Sanctions / regulatory risk
/// Listed on a sanctions list (OFAC SDN, UN, EU, DFAT, …) — carried by a
/// `Person`/`Organisation` entity an `opensanctions`-style module escalates.
pub const SANCTIONED: &str = "sanctioned";
/// Politically Exposed Person — an official/political role that elevates
/// corruption/bribery risk under AML/CTF due-diligence conventions.
pub const PEP: &str = "pep";
/// Debarred from public contracting (World Bank, IDB, and similar
/// multilateral debarment lists).
pub const DEBARRED: &str = "debarred";

// Identity
/// The entity is a **social-media or community profile** — a platform account
/// page, or a URL that resolves to one.
///
/// [`crate::core::engine`] reads it twice: a `Url` target carrying it is handled
/// as a profile rather than as an arbitrary page, and an address published on a
/// profile counts toward the externally-validated gate described on [`GEOINT`].
pub const SOCIAL_PROFILE: &str = "social-profile";
/// **Quarantine.** The value is plausible but unconfirmed — a same-name breach
/// record that may be a namesake, a geocode that resolved off-region, a
/// generated username variant never verified to exist.
///
/// The most consequential tag in this file, and the only one with a lifecycle.
/// It is enforced, not advisory: a quarantined entity is held out of every
/// shareable export ([`crate::api::scan_export`], the CLI exporters and `diff`),
/// out of the timeline, out of cross-scan bridging, out of exposure scoring, and
/// out of the correlator's rule inputs. The audit counts it as quarantined and
/// the live event stream renders it marked as such.
///
/// Two things clear it, and both require evidence rather than time. Merging with
/// a non-candidate observation of the same value drops the tag — something
/// unconditional has now been seen. And the AU-061 geo-corroboration pass
/// removes it when a same-name breach record sits within the threshold distance
/// of the subject's confirmed location: same name *and* same place resolve the
/// namesake doubt, so the entity is un-quarantined and lifted to Probable.
///
/// Its absence is therefore load bearing — never add it to something already
/// confirmed, and never strip it except through one of those two paths.
pub const CANDIDATE: &str = "candidate";

// Discovery method
/// Found via a **search engine or web archive** result, rather than by querying
/// a source that holds the data itself.
pub const SEARCH_DISCOVERED: &str = "search-discovered";
/// **Derived from** a breach record rather than published in one — a domain
/// split out of a breached email address, for example.
///
/// Distinct from [`BREACH`]: the corpus contained the parent value, and this one
/// was inferred from it. Lead triage counts all three breach-class tags together.
pub const BREACH_DERIVED: &str = "breach-derived";
/// Entity injected from the persistent store at scan start — prior-scan
/// knowledge recalled so the local database acts as a source, not just a sink.
pub const RECALLED: &str = "recalled";
