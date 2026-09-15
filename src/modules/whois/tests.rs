use std::sync::Mutex;

use crate::core::entity::{Entity, EntityKind};
use crate::core::error::Error;
use crate::core::event::SkipClass;
use crate::core::scan::{Target, TargetKind};

use super::Whois;
use super::client::{AuthoritativeError, Transport, find_referral};
use super::is_usable_contact_email;
use super::parse::{
    all_fields, clean_nameserver, field, is_rpsl_org_handle, most_specific_network_record,
    parse_whois, rate_limit_notice, starts_with_ascii_ci,
};
use super::registrant_location_parts;
use super::registrant_org_name;
use super::vcard_field;
use super::{bootstrap_referral, build_result, lookup};
use crate::core::module::Module;

// ── Authentic wire fixtures ──────────────────────────────────────────────────
//
// Captured 2026-09-15 from the live servers over HTTPS mirrors of the same
// records (`https://www.iana.org/whois?q=…`, ARIN Whois-RWS `.txt`, RIPE
// `search.txt`) — byte-for-byte the port-43 wire dialects, so these tests
// exercise the real shapes the module parses in production, not a synthetic
// approximation of them.

/// IANA's bootstrap record for the `COM` TLD (nservers abbreviated to three;
/// the live record lists thirteen). Note what it carries: a `created:` (the
/// TLD's, 1985), `status: ACTIVE`, `nserver:` lines WITH glue, and a
/// `whois:` referral — everything a naive parse would attribute to the
/// queried domain.
const IANA_COM: &str = "\
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.verisign-grs.com

domain:       COM

organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)

contact:      administrative
name:         Registry Customer Service
organisation: VeriSign Global Registry Services
phone:        +1 703 925-6999
e-mail:       info@verisign-grs.com

nserver:      A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30
nserver:      B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30
nserver:      M.GTLD-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30
ds-rdata:     19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a

whois:        whois.verisign-grs.com

status:       ACTIVE
remarks:      Registration information: http://www.verisigninc.com

created:      1985-01-01
changed:      2026-03-10
source:       IANA
";

/// IANA's bootstrap record for the `VN` TLD — HSE's primary operating
/// jurisdiction. Its `whois:` line is BLANK: VNNIC publishes no port-43 WHOIS
/// server, so there is no referral to follow. Every `.vn` domain used to be
/// answered from this record: "created 1994-04-14, status ACTIVE", plus the
/// seven `.vn` TLD servers as the domain's nameservers.
const IANA_VN: &str = "\
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

domain:       VN

organisation: Viet Nam Internet Network Information Center (VNNIC)
address:      Ministry of Information and Communications of Socialist Republic of Viet Nam
address:      18 Nguyen Du
address:      Hanoi 100000
address:      Viet Nam

contact:      administrative
name:         Nguyen Hong Thang
organisation: Vietnam Internet Network Information Center (VNNIC)
phone:        +84 24 35564944 ext 301
e-mail:       nhthang@vnnic.vn

nserver:      A.DNS-SERVERS.VN 194.0.1.18 2001:678:4:0:0:0:0:12
nserver:      B.DNS-SERVERS.VN 2001:dc8:1:2:0:0:0:105 203.119.73.105
nserver:      G.DNS-SERVERS.VN 2001:dc8:1:0:0:0:0:69 203.119.68.69
ds-rdata:     16196 8 2 cb68c5384104b31e1d9cbc1c45f861a92cda9d8121afe76f9a8978527983fd99

whois:        

status:       ACTIVE
remarks:      Registration information: https://www.vnnic.vn/

created:      1994-04-14
changed:      2023-07-19
source:       IANA
";

/// IANA's bootstrap record for an address in `8.0.0.0/8`: the /8's own
/// `inetnum` + `status: LEGACY` + a referral to ARIN.
const IANA_8888: &str = "\
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.arin.net

inetnum:      8.0.0.0 - 8.255.255.255
organisation: Administered by ARIN
status:       LEGACY

whois:        whois.arin.net

changed:      1992-12
source:       IANA
";

/// ARIN's port-43 answer for `8.8.8.8`: the net record, its organisation,
/// then the org's abuse and technical points of contact, in ARIN's documented
/// layout. No registrar, no creation date, no nameservers, no `status:`.
const ARIN_8888: &str = "\
#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#

NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
NetHandle:      NET-8-8-8-0-2
Parent:         NET8 (NET-8-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       
Organization:   Google LLC (GOGL)
RegDate:        2023-12-28
Updated:        2023-12-28
Ref:            https://rdap.arin.net/registry/ip/8.8.8.0


OrgName:        Google LLC
OrgId:          GOGL
Address:        1600 Amphitheatre Parkway
City:           Mountain View
StateProv:      CA
PostalCode:     94043
Country:        US
RegDate:        2000-03-30
Updated:        2019-10-31
Comment:        Please note that the recommended way to file abuse complaints are located in the following links. 
Ref:            https://rdap.arin.net/registry/entity/GOGL


OrgAbuseHandle: ABUSE5250-ARIN
OrgAbuseName:   Abuse
OrgAbusePhone:  +1-650-253-0000 
OrgAbuseEmail:  network-abuse@google.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE5250-ARIN

OrgTechHandle: ZG39-ARIN
OrgTechName:   Google LLC
OrgTechPhone:  +1-650-253-0000 
OrgTechEmail:  arin-contact@google.com
OrgTechRef:    https://rdap.arin.net/registry/entity/ZG39-ARIN

#
# ARIN WHOIS data and services are subject to the Terms of Use
#
";

/// ARIN's answer shape for an address inside a reassignment: the enclosing
/// carrier block (least specific) comes FIRST with its own org and abuse
/// contact, then the block reassigned to the actual operator. A first-match
/// read attributes the carrier to the address.
const ARIN_NESTED: &str = "\
NetRange:       8.0.0.0 - 8.127.255.255
CIDR:           8.0.0.0/9
NetName:        LVLT-ORG-8-8
NetHandle:      NET-8-0-0-0-1
Parent:         NET8 (NET-8-0-0-0-0)
NetType:        Direct Allocation
Organization:   Level 3 Parent, LLC (LPL-141)
RegDate:        1992-12-01
Updated:        2018-04-23
Ref:            https://rdap.arin.net/registry/ip/8.0.0.0

OrgName:        Level 3 Parent, LLC
OrgId:          LPL-141
Address:        1025 Eldorado Blvd.
City:           Broomfield
StateProv:      CO
PostalCode:     80021
Country:        US
RegDate:        2018-02-06
Updated:        2018-02-22
Ref:            https://rdap.arin.net/registry/entity/LPL-141

OrgAbuseHandle: IPADD5-ARIN
OrgAbuseName:   ipaddressing
OrgAbuseEmail:  ipaddressing@level3.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/IPADD5-ARIN

NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
NetHandle:      NET-8-8-8-0-1
Parent:         LVLT-ORG-8-8 (NET-8-0-0-0-1)
NetType:        Reassigned
Organization:   Google LLC (GOGL)
RegDate:        2014-03-14
Updated:        2014-03-14
Ref:            https://rdap.arin.net/registry/ip/8.8.8.0

OrgName:        Google LLC
OrgId:          GOGL
Address:        1600 Amphitheatre Parkway
City:           Mountain View
StateProv:      CA
PostalCode:     94043
Country:        US
RegDate:        2000-03-30
Updated:        2019-10-31
Ref:            https://rdap.arin.net/registry/entity/GOGL

OrgAbuseHandle: ABUSE5250-ARIN
OrgAbuseName:   Abuse
OrgAbuseEmail:  network-abuse@google.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE5250-ARIN
";

/// RIPE's RPSL answer for `193.0.6.139`: the `inetnum` (whose `org:` is the
/// HANDLE `ORG-RIEN1-RIPE`), the referenced `organisation` object (whose
/// `org-name:` is the name), a `role` and a `person` object — the network's
/// own contacts, not anyone the address is being investigated for.
const RIPE_193: &str = "\
% This is the RIPE Database query service.
% The objects are in RPSL format.

inetnum:        193.0.0.0 - 193.0.7.255
netname:        RIPE-NCC
descr:          RIPE Network Coordination Centre
org:            ORG-RIEN1-RIPE
descr:          Amsterdam, Netherlands
remarks:        Used for RIPE NCC infrastructure.
country:        NL
admin-c:        MDIR-RIPE
tech-c:         OPS4-RIPE
status:         ASSIGNED PA
mnt-by:         RIPE-NCC-MNT
created:        2003-03-17T12:15:57Z
last-modified:  2026-03-19T09:08:35Z
source:         RIPE

organisation:   ORG-RIEN1-RIPE
org-name:       Reseaux IP Europeens Network Coordination Centre (RIPE NCC)
country:        NL
org-type:       LIR
address:        P.O. Box 10096
address:        Amsterdam
phone:          +31205354444
e-mail:         ncc@ripe.net
abuse-c:        ops4-ripe
mnt-by:         RIPE-NCC-HM-MNT
created:        2012-03-09T13:21:52Z
last-modified:  2026-05-13T07:34:07Z
source:         RIPE

role:           RIPE NCC Operations
address:        RIPE Network Coordination Centre
abuse-mailbox:  abuse@ripe.net
nic-hdl:        OPS4-RIPE
mnt-by:         RIPE-NCC-HM-MNT
created:        2002-06-27T13:03:05Z
last-modified:  2026-01-08T10:12:00Z
source:         RIPE

person:         Hans Petter Holen
address:        RIPE Network Coordination Centre
phone:          +31 20 535 4444
nic-hdl:        HPH2
mnt-by:         RIPE-NCC-HM-MNT
created:        2002-01-15T14:00:00Z
last-modified:  2024-11-02T09:00:00Z
source:         RIPE
";

/// A canned two-hop transport: what IANA answers, and what (if anything) the
/// authoritative server answers. Records every authoritative hop attempted so
/// a test can prove the referral was — or was not — followed.
struct Canned {
    bootstrap: &'static str,
    authoritative: Result<&'static str, &'static str>,
    hops: Mutex<Vec<(String, String)>>,
}

impl Canned {
    fn new(bootstrap: &'static str, authoritative: Result<&'static str, &'static str>) -> Self {
        Self {
            bootstrap,
            authoritative,
            hops: Mutex::new(Vec::new()),
        }
    }
    fn hops(&self) -> Vec<(String, String)> {
        self.hops.lock().expect("hops lock").clone()
    }
}

#[async_trait::async_trait]
impl Transport for Canned {
    async fn bootstrap(&self, _q: &str) -> std::io::Result<String> {
        Ok(self.bootstrap.to_string())
    }
    async fn authoritative(&self, server: &str, q: &str) -> Result<String, AuthoritativeError> {
        self.hops
            .lock()
            .expect("hops lock")
            .push((server.to_string(), q.to_string()));
        match self.authoritative {
            Ok(text) => Ok(text.to_string()),
            Err("unresolvable") => Err(AuthoritativeError::Unresolvable),
            Err(msg) => Err(AuthoritativeError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                msg,
            ))),
        }
    }
}

fn attr<'a>(e: &'a Entity, key: &str) -> Option<&'a str> {
    e.evidence
        .iter()
        .find_map(|ev| ev.attributes.get(key).map(String::as_str))
}

fn of_kind(entities: &[Entity], kind: EntityKind) -> Vec<&Entity> {
    entities.iter().filter(|e| e.kind == kind).collect()
}

// ── IANA is a bootstrap, never the record ───────────────────────────────────

#[test]
fn iana_bootstrap_yields_only_the_referral_for_com() {
    assert_eq!(
        bootstrap_referral(IANA_COM, "example.com").expect("COM has a referral"),
        "whois.verisign-grs.com"
    );
    assert_eq!(
        bootstrap_referral(IANA_8888, "8.8.8.8").expect("8/8 refers to ARIN"),
        "whois.arin.net"
    );
}

/// REGRESSION. `.vn`'s registry publishes no WHOIS server (IANA's `whois:` is
/// blank), so there is no referral. That is a typed NOT-APPLICABLE skip —
/// port-43 WHOIS cannot speak about the namespace — never an answer parsed
/// out of IANA's own TLD record, and never a clean "no registration data".
#[test]
fn a_registry_without_a_whois_server_is_a_typed_not_applicable_skip() {
    let err = bootstrap_referral(IANA_VN, "vnnic.vn").expect_err("no referral to follow");
    let Error::Skipped { class, reason } = err else {
        panic!("must be the typed skip, got {err}");
    };
    assert_eq!(class, SkipClass::NotApplicable);
    assert!(
        reason.contains("no WHOIS server") && reason.contains("vnnic.vn"),
        "reason must name the gap and the target: {reason}"
    );
    assert!(
        reason.contains("rdap_domain"),
        "reason must point the operator at the registry-data path: {reason}"
    );
}

/// REGRESSION (docs/PROVIDER_SWEEP_BACKLOG.md #47, verified). When the
/// authoritative hop fails the lookup used to fall back to IANA's TLD record:
/// `example.com` came back "created 1985-01-01, status ACTIVE" with the gTLD
/// root servers minted as its nameservers. A failed hop is a failed lookup,
/// reported as one — the registry did not say "no record", it said nothing.
#[tokio::test]
async fn a_failed_referral_hop_is_a_lookup_failure_never_the_tld_record() {
    for failure in [Err("connection timed out"), Err("unresolvable")] {
        let transport = Canned::new(IANA_COM, failure);
        let target = Target::new(TargetKind::Domain, "example.com");
        let err = lookup(&transport, &target, "scan-1")
            .await
            .expect_err("a failed hop must not produce a result");
        let Error::Module { module, message } = &err else {
            panic!("must be a module failure, got {err}");
        };
        assert_eq!(module, "whois");
        assert!(
            message.contains("whois.verisign-grs.com") && message.contains("example.com"),
            "failure must name the server and the target: {message}"
        );
        assert!(
            message.contains("not \"no registration record\""),
            "failure must say it is not a negative: {message}"
        );
        assert_eq!(
            transport.hops(),
            vec![(
                "whois.verisign-grs.com".to_string(),
                "example.com".to_string()
            )],
            "exactly one authoritative hop, to the referred server"
        );
    }
}

/// The `.vn` case end to end: IANA answers with the TLD record and no
/// referral, so no authoritative hop is attempted and nothing is minted —
/// before, the TLD's seven `.vn` servers became the domain's nameservers.
#[tokio::test]
async fn a_vn_domain_is_skipped_without_fabricating_registration_data() {
    let transport = Canned::new(IANA_VN, Ok("never reached"));
    let target = Target::new(TargetKind::Domain, "vnnic.vn");
    let err = lookup(&transport, &target, "scan-1")
        .await
        .expect_err("no WHOIS server → typed skip");
    assert!(
        matches!(
            err,
            Error::Skipped {
                class: SkipClass::NotApplicable,
                ..
            }
        ),
        "got {err}"
    );
    assert!(
        transport.hops().is_empty(),
        "no referral, so no authoritative hop may be attempted"
    );
}

/// A URL with no host has nothing to look up — a typed skip, not a fabricated
/// lookup of an empty string and not a clean negative.
#[tokio::test]
async fn a_url_without_a_host_is_a_typed_skip() {
    let transport = Canned::new(IANA_COM, Ok("never reached"));
    let target = Target::new(TargetKind::Url, "https:///no-host");
    let err = lookup(&transport, &target, "scan-1")
        .await
        .expect_err("nothing to query");
    assert!(
        matches!(
            err,
            Error::Skipped {
                class: SkipClass::NotApplicable,
                ..
            }
        ),
        "got {err}"
    );
    assert!(transport.hops().is_empty());
}

// ── Address (RIR) records ───────────────────────────────────────────────────

/// REGRESSION. ARIN's answer for `8.8.8.8` carries no registrar / creation
/// date / nameservers / status, so the domain-shaped "actionable data" gate
/// discarded it whole — the operator, country and abuse contact ARIN plainly
/// returned were lost, and the weekly live sweep recorded `whois 8.8.8.8` as
/// EMPTY. The HTTPS RDAP fallback for the same address yields all three.
#[tokio::test]
async fn an_arin_address_record_yields_operator_country_and_abuse_contact() {
    let transport = Canned::new(IANA_8888, Ok(ARIN_8888));
    let target = Target::new(TargetKind::IpAddress, "8.8.8.8");
    let result = lookup(&transport, &target, "scan-1")
        .await
        .expect("ARIN answered with a record");
    assert_eq!(
        transport.hops(),
        vec![("whois.arin.net".to_string(), "8.8.8.8".to_string())]
    );

    let ips = of_kind(&result.entities, EntityKind::IpAddress);
    assert_eq!(
        ips.len(),
        1,
        "the address itself, once: {:?}",
        result.entities
    );
    let ip = ips[0];
    assert_eq!(attr(ip, "whois_server"), Some("whois.arin.net"));
    assert_eq!(attr(ip, "net_name"), Some("GOGL"));
    assert_eq!(attr(ip, "net_range"), Some("8.8.8.0 - 8.8.8.255"));
    assert_eq!(attr(ip, "cidr"), Some("8.8.8.0/24"));
    assert_eq!(attr(ip, "net_type"), Some("Direct Allocation"));
    assert_eq!(attr(ip, "registrant_org"), Some("Google LLC"));
    assert_eq!(attr(ip, "registrant_country"), Some("US"));
    assert_eq!(attr(ip, "abuse_email"), Some("network-abuse@google.com"));
    // ARIN's RegDate is the allocation date — the `created` the timeline reads.
    assert_eq!(attr(ip, "created"), Some("2023-12-28"));
    assert_eq!(attr(ip, "updated"), Some("2023-12-28"));
    // Nothing domain-shaped is invented for an address.
    assert_eq!(attr(ip, "registrar"), None);
    assert_eq!(attr(ip, "name_servers"), None);

    let orgs = of_kind(&result.entities, EntityKind::Organisation);
    assert_eq!(orgs.len(), 1, "{:?}", result.entities);
    assert_eq!(orgs[0].raw_value, "Google LLC");
    assert!(orgs[0].has_tag("ip-registrant"), "{:?}", orgs[0].tags);
    assert!(
        !orgs[0].has_tag(crate::core::tags::REGISTRANT),
        "an allocation's operator is not a domain registrant"
    );

    let addrs = of_kind(&result.entities, EntityKind::Address);
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].raw_value, "US");

    assert!(
        of_kind(&result.entities, EntityKind::Person).is_empty(),
        "an RIR record names no registrant person: {:?}",
        result.entities
    );
    assert!(
        of_kind(&result.entities, EntityKind::Domain).is_empty(),
        "an RIR record has no nameservers: {:?}",
        result.entities
    );
}

/// REGRESSION. ARIN lists every enclosing allocation least-specific first, so
/// a first-match read over the whole answer attributed the carrier block's
/// operator (`Level 3 Parent, LLC`), abuse contact and net name to the address
/// instead of the block actually reassigned to its operator.
#[test]
fn arin_nested_allocations_attribute_the_most_specific_block() {
    let target = Target::new(TargetKind::IpAddress, "8.8.8.8");
    let result = build_result(&target, "8.8.8.8", "whois.arin.net", ARIN_NESTED, "scan-1")
        .expect("record present");
    let ip = of_kind(&result.entities, EntityKind::IpAddress)[0];
    assert_eq!(attr(ip, "net_name"), Some("GOGL"));
    assert_eq!(attr(ip, "net_range"), Some("8.8.8.0 - 8.8.8.255"));
    assert_eq!(attr(ip, "net_type"), Some("Reassigned"));
    assert_eq!(attr(ip, "registrant_org"), Some("Google LLC"));
    assert_eq!(attr(ip, "abuse_email"), Some("network-abuse@google.com"));
    let orgs: Vec<&str> = of_kind(&result.entities, EntityKind::Organisation)
        .into_iter()
        .map(|e| e.raw_value.as_str())
        .collect();
    assert_eq!(orgs, ["Google LLC"], "the carrier must not be attributed");
}

/// A URL whose host is an address is looked up as that address, and the RIR's
/// answer is read as an address record — not judged by the domain-shaped gate
/// (registrar/nameservers) and discarded.
#[tokio::test]
async fn a_url_with_an_ip_host_reads_the_rir_record_as_an_address_record() {
    let transport = Canned::new(IANA_8888, Ok(ARIN_8888));
    let target = Target::new(TargetKind::Url, "http://8.8.8.8/login");
    let result = lookup(&transport, &target, "scan-1")
        .await
        .expect("ARIN answered with a record");
    assert_eq!(
        transport.hops(),
        vec![("whois.arin.net".to_string(), "8.8.8.8".to_string())],
        "looked up by host, not by URL"
    );
    let urls = of_kind(&result.entities, EntityKind::Url);
    assert_eq!(urls.len(), 1, "{:?}", result.entities);
    assert_eq!(attr(urls[0], "net_name"), Some("GOGL"));
    assert_eq!(attr(urls[0], "registrant_org"), Some("Google LLC"));
    assert!(of_kind(&result.entities, EntityKind::Person).is_empty());
}

/// CONTROL for the address-record gate. Every RIR dialect the parser knows
/// happens to carry a date or a `status:` line, so the ARIN/RIPE fixtures
/// above would pass even the old domain-shaped gate through `created`. This
/// legacy-style RPSL record (synthetic: netname / description / operator /
/// country only — no registrar, no date, no status, no nameservers) is what
/// isolates the invariant: an address answer is judged on ADDRESS fields.
/// Falsification: restoring the domain-shaped gate for addresses turns
/// exactly this test red.
#[test]
fn an_address_record_without_dates_or_status_is_still_a_record() {
    let legacy = "\
inetnum:        192.0.2.0 - 192.0.2.255
netname:        LEGACY-NET
descr:          Example Legacy Network Operator
org-name:       Example Legacy Operator Ltd
country:        AU
abuse-mailbox:  abuse@example-legacy.test
source:         TEST
";
    let target = Target::new(TargetKind::IpAddress, "192.0.2.10");
    let result = build_result(
        &target,
        "192.0.2.10",
        "whois.example-rir.test",
        legacy,
        "scan-1",
    )
    .expect("an allocation record is a record");
    let ip = of_kind(&result.entities, EntityKind::IpAddress);
    assert_eq!(ip.len(), 1, "{:?}", result.entities);
    assert_eq!(attr(ip[0], "net_name"), Some("LEGACY-NET"));
    assert_eq!(
        attr(ip[0], "registrant_org"),
        Some("Example Legacy Operator Ltd")
    );
    assert_eq!(attr(ip[0], "registrant_country"), Some("AU"));
    assert_eq!(attr(ip[0], "created"), None);
    assert_eq!(attr(ip[0], "statuses"), None);
    // The reverse control: the SAME fields on a DOMAIN answer are not a
    // registration record (a ccTLD "no match" page can carry a `country:`).
    let domain = Target::new(TargetKind::Domain, "example-nope.test");
    let result = build_result(
        &domain,
        "example-nope.test",
        "whois.example-registry.test",
        "country:        AU\ndescr:          no such object\n",
        "scan-1",
    )
    .expect("clean negative");
    assert!(result.entities.is_empty(), "{:?}", result.entities);
}

#[test]
fn most_specific_network_record_anchors_on_the_last_netrange_or_first_inetnum() {
    assert!(
        most_specific_network_record(ARIN_NESTED)
            .starts_with("NetRange:       8.8.8.0 - 8.8.8.255"),
        "ARIN: the LAST NetRange object"
    );
    assert!(
        most_specific_network_record(RIPE_193).starts_with("inetnum:        193.0.0.0"),
        "RPSL: the first inetnum, comment preamble dropped"
    );
    let plain = "Registrar: X\nCreation Date: 2020-01-01\n";
    assert_eq!(
        most_specific_network_record(plain),
        plain,
        "no network object → the whole answer"
    );
}

/// REGRESSION. An RPSL `org:` line is an organisation HANDLE; the module used
/// to mint an Organisation entity literally named `ORG-RIEN1-RIPE` and ignore
/// the `org-name:`. And the `person:` object in the same answer is the
/// network's contact, never the subject — no Person may be minted from it.
#[test]
fn a_ripe_record_names_the_organisation_not_its_handle_and_mints_no_person() {
    let target = Target::new(TargetKind::IpAddress, "193.0.6.139");
    let result = build_result(&target, "193.0.6.139", "whois.ripe.net", RIPE_193, "scan-1")
        .expect("record present");
    let ip = of_kind(&result.entities, EntityKind::IpAddress)[0];
    assert_eq!(
        attr(ip, "registrant_org"),
        Some("Reseaux IP Europeens Network Coordination Centre (RIPE NCC)")
    );
    assert_eq!(attr(ip, "net_name"), Some("RIPE-NCC"));
    assert_eq!(attr(ip, "net_range"), Some("193.0.0.0 - 193.0.7.255"));
    assert_eq!(attr(ip, "descr"), Some("RIPE Network Coordination Centre"));
    assert_eq!(attr(ip, "registrant_country"), Some("NL"));
    assert_eq!(attr(ip, "statuses"), Some("ASSIGNED PA"));
    assert_eq!(attr(ip, "created"), Some("2003-03-17T12:15:57Z"));
    assert_eq!(attr(ip, "updated"), Some("2026-03-19T09:08:35Z"));
    assert_eq!(attr(ip, "abuse_email"), Some("abuse@ripe.net"));
    assert_eq!(
        attr(ip, "registrant_name"),
        None,
        "person: is not a registrant"
    );

    let orgs: Vec<&str> = of_kind(&result.entities, EntityKind::Organisation)
        .into_iter()
        .map(|e| e.raw_value.as_str())
        .collect();
    assert_eq!(
        orgs,
        ["Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"]
    );
    assert!(
        of_kind(&result.entities, EntityKind::Person).is_empty(),
        "RIR contact objects must never become Person entities: {:?}",
        result.entities
    );
}

#[test]
fn is_rpsl_org_handle_matches_rir_handles_only() {
    assert!(is_rpsl_org_handle("ORG-RIEN1-RIPE"));
    assert!(is_rpsl_org_handle("ORG-GAP1-AP"));
    assert!(is_rpsl_org_handle("  ORG-ABC1-AFRINIC "));
    assert!(!is_rpsl_org_handle("JSC Example"));
    assert!(!is_rpsl_org_handle("ORG-Wide Holdings Pty Ltd"));
    assert!(!is_rpsl_org_handle(""));
}

/// `.ru`'s registry writes the registrant's real name on `org:` — the handle
/// guard must not swallow it.
#[test]
fn a_ru_style_org_line_with_a_real_name_still_surfaces_as_the_registrant_org() {
    let f = parse_whois(
        "domain:        EXAMPLE.RU\nnserver:       ns1.example.ru.\nstate:         REGISTERED, DELEGATED, VERIFIED\norg:           JSC Example\nregistrar:     RU-CENTER-RU\ncreated:       2001-01-01T00:00:00Z\npaid-till:     2027-01-01T00:00:00Z\n",
    );
    assert_eq!(f.registrant_org.as_deref(), Some("JSC Example"));
    assert_eq!(f.registrar.as_deref(), Some("RU-CENTER-RU"));
    assert_eq!(f.nameservers, ["ns1.example.ru"]);
}

// ── Registry replies that are not records ───────────────────────────────────

/// REGRESSION. A load refusal (`WHOIS LIMIT EXCEEDED`, DENIC's access-control
/// notice) parsed to nothing and read as a clean "no registration data". It
/// is the typed rate-limit: the registry said "not now", not "no record".
#[test]
fn a_load_refusal_is_a_typed_rate_limit_not_a_clean_negative() {
    let target = Target::new(TargetKind::Domain, "example.org");
    for refusal in [
        "WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS\n",
        "% Error: 55000000002 Connection refused; access control limit reached.\n",
        "Your connection limit exceeded. Please slow down and try again later.\n",
    ] {
        let err = build_result(
            &target,
            "example.org",
            "whois.example-registry.test",
            refusal,
            "scan-1",
        )
        .expect_err("a refusal is not a record");
        let Error::RateLimited(msg) = &err else {
            panic!("must be RateLimited for {refusal:?}, got {err}");
        };
        assert!(
            msg.contains("whois.example-registry.test") && msg.contains("example.org"),
            "{msg}"
        );
    }
    assert_eq!(
        rate_limit_notice("% no such thing\nWHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG\n"),
        Some("WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG")
    );
    assert_eq!(rate_limit_notice("No match for \"X.COM\".\n"), None);
}

/// The one genuine clean negative: the registry answered and holds nothing.
#[test]
fn a_no_match_reply_is_a_clean_negative() {
    let target = Target::new(TargetKind::Domain, "example-nope-zzz.com");
    let result = build_result(
        &target,
        "example-nope-zzz.com",
        "whois.verisign-grs.com",
        "No match for \"EXAMPLE-NOPE-ZZZ.COM\".\n>>> Last update of whois database: 2026-09-15T00:00:00Z <<<\n",
        "scan-1",
    )
    .expect("a no-match reply is a clean negative, not an error");
    assert!(result.entities.is_empty());
}

/// A registry that answers a record still carries no `quota`/`limit` prose
/// that could be misread as a refusal — the refusal check only runs on an
/// answer that parsed to nothing.
#[test]
fn a_record_mentioning_a_quota_in_its_remarks_is_still_a_record() {
    let target = Target::new(TargetKind::Domain, "example.com");
    let result = build_result(
        &target,
        "example.com",
        "whois.verisign-grs.com",
        "Registrar: Example Registrar LLC\nCreation Date: 2020-01-01T00:00:00Z\nremarks: query quota applies to bulk access\n",
        "scan-1",
    )
    .expect("a record is a record");
    assert_eq!(of_kind(&result.entities, EntityKind::Domain).len(), 1);
}

// ── Nameserver values ───────────────────────────────────────────────────────

/// REGRESSION. `nserver:` lines carry glue after the host (IANA, DENIC); the
/// whole line used to become a Domain entity — `a.gtld-servers.net 192.5.6.30
/// 2001:503:a83e:0:0:0:2:30` — which admission accepts (it has a dot) and the
/// expansion loop then pivots on. Only the host is the name; a bare address
/// or junk is not a nameserver at all.
#[test]
fn nameserver_glue_is_stripped_and_non_hosts_dropped() {
    assert_eq!(
        clean_nameserver("A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30").as_deref(),
        Some("A.GTLD-SERVERS.NET")
    );
    assert_eq!(
        clean_nameserver("ns1.example.de 192.0.2.1").as_deref(),
        Some("ns1.example.de")
    );
    assert_eq!(
        clean_nameserver("ns1.example.ru.").as_deref(),
        Some("ns1.example.ru")
    );
    assert_eq!(
        clean_nameserver("192.0.2.1"),
        None,
        "glue alone is not a host"
    );
    assert_eq!(clean_nameserver("localhost"), None);
    assert_eq!(clean_nameserver("   "), None);

    let f = parse_whois(
        "Name Server: NS1.EXAMPLE.COM\nName Server: ns1.example.com\nnserver: NS2.EXAMPLE.COM 192.0.2.2\nName Server: 192.0.2.9\n",
    );
    assert_eq!(
        f.nameservers,
        ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
        "case-insensitive dedup after cleaning; glue-only line dropped"
    );
}

fn rdap_entities(json: &str) -> Vec<super::RdapIpEntity> {
    serde_json::from_str(json).expect("valid RdapIpEntity fixture")
}

/// Mirrors `ip_registry::tests::rdap_individual_registrant_is_not_emitted_as_org`
/// over the same RDAP shape — the whole point of this test existing is that
/// the two RDAP-consuming modules must agree here, not just that each is
/// internally consistent.
#[test]
fn registrant_org_name_skips_an_individual_kind_registrant() {
    let entities = rdap_entities(
        r#"[{
            "roles":["registrant"],
            "vcardArray":["vcard",[["fn",{},"text","Jane Q Public"],["kind",{},"text","individual"]]]
        }]"#,
    );
    assert_eq!(
        registrant_org_name(&entities),
        None,
        "individual-kind registrant must never surface as an Organisation"
    );
}

#[test]
fn registrant_org_name_prefers_fn_over_org() {
    let entities = rdap_entities(
        r#"[{
            "roles":["registrant"],
            "vcardArray":["vcard",[["fn",{},"text","Acme Networks"],["org",{},"text","Acme Holdings"]]]
        }]"#,
    );
    assert_eq!(
        registrant_org_name(&entities).as_deref(),
        Some("Acme Networks")
    );
}

/// Regression: this module used to fall back to the RDAP object's top-level
/// network-block `name` (e.g. a handle like "NET-1-2-3-0-24") when `fn` was
/// absent — a different concept from the registrant's own identity, and a
/// value `ip_registry`'s sibling builder never produces for the same record.
/// Falling back to vCard `org` instead (exactly what `ip_registry` does)
/// keeps both modules capable of emitting the identical Organisation value
/// for the identical registrant.
#[test]
fn registrant_org_name_falls_back_to_vcard_org_when_fn_is_absent() {
    let entities = rdap_entities(
        r#"[{
            "roles":["registrant"],
            "vcardArray":["vcard",[["org",{},"text","Acme Holdings"]]]
        }]"#,
    );
    assert_eq!(
        registrant_org_name(&entities).as_deref(),
        Some("Acme Holdings")
    );
}

#[test]
fn accepts_domain_and_ip() {
    let m = Whois;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn produces_declares_ip_address() {
    // Regression: `target.to_entity(...)` (dynamically kinded) can re-emit
    // an IpAddress target itself, but produces() never declared it.
    use crate::core::entity::EntityKind;
    assert!(Whois.produces().contains(&EntityKind::IpAddress));
}

#[test]
fn parses_referral() {
    let s = "refer:        whois.verisign-grs.com\nstatus:        ACTIVE";
    assert_eq!(find_referral(s).as_deref(), Some("whois.verisign-grs.com"));
}

#[test]
fn parses_field_case_insensitive() {
    let s = "Registrar: Example LLC\nCreation Date: 2020-01-01";
    assert_eq!(field(s, &["Registrar:"]).as_deref(), Some("Example LLC"));
    assert_eq!(
        field(s, &["Creation Date:", "created:"]).as_deref(),
        Some("2020-01-01")
    );
}

#[test]
fn parses_multiple_nameservers_deduplicated() {
    let s =
        "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM\nName Server: NS1.EXAMPLE.COM";
    let ns = all_fields(s, &["Name Server:"]);
    assert_eq!(ns.len(), 2);
}

#[test]
fn parse_whois_extracts_typed_fields() {
    let s = "\
Registrar: Example Registrar LLC
Registrar IANA ID: 1234
Creation Date: 2020-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Updated Date: 2024-06-01T00:00:00Z
Registrant Organization: Example Org
Registrant Country: US
Registrant State/Province: NV
Registrant Email: owner@example.com
Admin Email: admin@example.com
Tech Email: tech@example.com
Registrar Abuse Contact Email: abuse@registrar.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
DNSSEC: unsigned
";
    let f = parse_whois(s);
    assert_eq!(f.registrar.as_deref(), Some("Example Registrar LLC"));
    assert_eq!(f.registrar_iana.as_deref(), Some("1234"));
    assert_eq!(f.created.as_deref(), Some("2020-01-01T00:00:00Z"));
    assert_eq!(f.expires.as_deref(), Some("2030-01-01T00:00:00Z"));
    assert_eq!(f.updated.as_deref(), Some("2024-06-01T00:00:00Z"));
    assert_eq!(f.registrant_org.as_deref(), Some("Example Org"));
    assert_eq!(f.registrant_country.as_deref(), Some("US"));
    assert_eq!(f.registrant_state.as_deref(), Some("NV"));
    assert_eq!(f.registrant_email.as_deref(), Some("owner@example.com"));
    assert_eq!(f.admin_email.as_deref(), Some("admin@example.com"));
    assert_eq!(f.tech_email.as_deref(), Some("tech@example.com"));
    assert_eq!(f.abuse_email.as_deref(), Some("abuse@registrar.com"));
    assert_eq!(f.nameservers, ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]);
    assert_eq!(f.statuses, ["clientTransferProhibited"]);
    assert_eq!(f.dnssec.as_deref(), Some("unsigned"));
}

#[test]
fn parse_whois_filters_non_at_email_placeholders() {
    // Registrant Email present but without '@' (REDACTED placeholder) → None.
    let f = parse_whois("Registrant Email: REDACTED FOR PRIVACY\nRegistrar: X");
    assert!(f.registrant_email.is_none());
    assert_eq!(f.registrar.as_deref(), Some("X"));
}

#[test]
fn registrant_email_never_falls_back_to_admin_or_tech() {
    // Regression: "Registrant Email:" used to share a multi-key lookup with
    // "Tech Email:"/"Admin Email:" as if they were dialect synonyms for the
    // same field (like registrar/created's genuine synonym lists) — but
    // they're a DIFFERENT role. A response with no published Registrant
    // Email (common post-GDPR) silently substituted the admin/tech
    // contact's address and evidenced it as "WHOIS registrant contact".
    let f = parse_whois("Admin Email: admin@example.com\nTech Email: tech@example.com\n");
    assert!(
        f.registrant_email.is_none(),
        "must not fall back to admin/tech email: {:?}",
        f.registrant_email
    );
    // The admin/tech contacts are still captured — under their own,
    // correct role.
    assert_eq!(f.admin_email.as_deref(), Some("admin@example.com"));
    assert_eq!(f.tech_email.as_deref(), Some("tech@example.com"));
}

#[test]
fn starts_with_ascii_ci_matches_prefix_ignoring_case() {
    assert!(starts_with_ascii_ci("Registrar: X", "registrar:"));
    // Case-insensitive in both directions.
    assert!(starts_with_ascii_ci("registrar: x", "REGISTRAR:"));
    // A different prefix does not match.
    assert!(!starts_with_ascii_ci("Registrar: X", "creation"));
    // Key longer than the line can never match (the length guard).
    assert!(!starts_with_ascii_ci("Reg", "registrar:"));
    // The empty key is a prefix of everything.
    assert!(starts_with_ascii_ci("anything", ""));
}

#[test]
fn vcard_field_extracts_fn_and_email() {
    // Standard vcardArray structure: ["vcard", [[name, params, type, value], ...]]
    let vc: serde_json::Value = serde_json::json!([
        "vcard",
        [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Example Organisation Ltd"],
            ["email", {}, "text", "abuse@example.org"]
        ]
    ]);
    assert_eq!(
        vcard_field(&vc, "fn").as_deref(),
        Some("Example Organisation Ltd"),
        "fn field extracted"
    );
    assert_eq!(
        vcard_field(&vc, "email").as_deref(),
        Some("abuse@example.org"),
        "email field extracted"
    );
    assert!(
        vcard_field(&vc, "tel").is_none(),
        "missing field returns None"
    );
}

#[test]
fn vcard_field_returns_none_for_malformed_input() {
    let not_a_vcard = serde_json::json!({"key": "value"});
    assert!(vcard_field(&not_a_vcard, "fn").is_none());
    let empty_array = serde_json::json!([]);
    assert!(vcard_field(&empty_array, "fn").is_none());
}

#[test]
fn registrant_location_parts_drops_privacy_proxy_placeholders_via_shared_guard() {
    // Real values pass straight through, preserving order (state, country).
    assert_eq!(
        registrant_location_parts(Some("NV"), "US"),
        vec!["NV", "US"]
    );
    // "Data Protected" and "Withheld" contain neither "redacted" nor "privacy",
    // so the previous inline substring check let them become a fake registrant
    // Address; the shared whois guard rejects them. A real value in the same
    // record still survives.
    assert_eq!(
        registrant_location_parts(Some("Data Protected"), "Australia"),
        vec!["Australia"]
    );
    assert!(registrant_location_parts(Some("Redacted For Privacy"), "Withheld").is_empty());
    // Empty parts are dropped.
    assert_eq!(registrant_location_parts(Some(""), "US"), vec!["US"]);
}

#[test]
fn is_usable_contact_email_rejects_infra_and_privacy_proxy_but_keeps_real_addresses() {
    // Regression: Email was the one WHOIS contact field missing the
    // is_infrastructure_email gate the others (`registrant_location_parts`
    // above, org, name) already applied.
    assert!(
        !is_usable_contact_email("abuse@cloudflare.com"),
        "role + infra domain"
    );
    assert!(
        !is_usable_contact_email("dns@example.com"),
        "role local-part"
    );
    // Dedicated privacy-proxy forwarding mailboxes — a real (non-placeholder-
    // TEXT) address, so is_infrastructure_email alone doesn't catch these;
    // is_whois_privacy_placeholder's substring match does (it matches
    // anywhere in the string, not just name/org fields).
    assert!(!is_usable_contact_email("a1b2c3.protect@whoisguard.com"));
    assert!(!is_usable_contact_email("some.id@domainsbyproxy.com"));
    // A real, individually-addressed mailbox must survive both gates.
    assert!(is_usable_contact_email("jane.doe@example.com"));
}
