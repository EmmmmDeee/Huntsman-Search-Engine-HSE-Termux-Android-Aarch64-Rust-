//! Shared "maximum raw data" extractor for breach/stealer records.
//!
//! Both paid breach pools — `see_know` and `oathnet_pro` — receive verbose
//! per-record detail objects (infostealer device fingerprints, social handles,
//! address parts, employer, and a long tail of provider-specific scalar fields).
//! This module turns that long tail into first-class, pivotable entities so
//! nothing valuable stays locked inside the evidence blob (operator directive:
//! "I want everything. Maximum raw data.").
//!
//! It lives here, shared and source-parameterised, so the two providers extract
//! the **same** field set with the **same** semantics — the field knowledge
//! can't drift between them, and a new provider gets the full pass for free. The
//! caller supplies its own `source` tag (`"see-know"` / `"oathnet-pro"`) and the
//! evidence record; entities are pushed at full confidence and the caller
//! applies its own non-target demotion (see_know range-demotes after the call,
//! oathnet per row) — this pass stays demotion-agnostic.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    tags,
};
use crate::util::extract::is_placeholder_secret;
use crate::util::json::{is_null_sentinel, val_str};

/// A value that is an *absence/redaction marker*, not real data: a SQL NULL
/// sentinel (`\N`, written for an empty column in dumped exports) or a provider
/// redaction placeholder (`UPGRADE_TO_SEE_FULL`, `REDACTED`, bracketed
/// `[NULL]`/`[FAIL]`…). Such a value must NEVER mint a graph node — two records
/// that each carry `\N`/`REDACTED` in, say, `company` would otherwise both yield
/// an `Organisation("\N")` node and falsely co-occur, poisoning correlation.
fn is_absent_marker(s: &str) -> bool {
    is_null_sentinel(s) || is_placeholder_secret(s)
}

/// A hardware-fingerprint value that is a well-known BIOS/SMBIOS/dmidecode
/// PLACEHOLDER (or a trivial all-zero / broadcast filler), not a real per-machine
/// id. Infostealer logs capture these verbatim from boards whose OEM never burned
/// a real serial, so the SAME string recurs across thousands of UNRELATED
/// machines — typing it as a `DeviceId`/`MacAddress` would defeat AU-106's
/// uniqueness assumption and let a shared placeholder falsely link two strangers
/// as "one physical machine". Compared case-insensitively and whitespace-trimmed.
fn is_placeholder_fingerprint(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    // Trivial all-zero / all-`F` fillers, ignoring separators (`00:00:..`,
    // `00000000`, the null GUID, `FF-FF-..`/broadcast MAC).
    let core: String = t.chars().filter(char::is_ascii_alphanumeric).collect();
    if !core.is_empty()
        && (core.bytes().all(|b| b == b'0') || core.bytes().all(|b| b == b'f' || b == b'F'))
    {
        return true;
    }
    // Documented SMBIOS / dmidecode placeholder strings.
    let u = t.to_ascii_uppercase();
    matches!(
        u.as_str(),
        "TO BE FILLED BY O.E.M."
            | "TO BE FILLED BY OEM."
            | "TO BE FILLED BY OEM"
            | "SYSTEM SERIAL NUMBER"
            | "CHASSIS SERIAL NUMBER"
            | "BASE BOARD SERIAL NUMBER"
            | "DEFAULT STRING"
            | "NOT SPECIFIED"
            | "NOT APPLICABLE"
            | "NOT AVAILABLE"
            | "SERIAL NUMBER"
            | "SYSTEM MANUFACTURER"
            | "SYSTEM PRODUCT NAME"
            | "DEFAULT"
            | "NONE"
            | "UNKNOWN"
            | "O.E.M."
            | "OEM"
            | "STANDARD"
            | "INVALID"
            | "N/A"
            | "NA"
            | "NULL"
    )
}

/// Field names already turned into typed entities by the providers' primary
/// extractors (or deliberately suppressed as structural/metadata noise). The
/// catch-all pass skips these so it only emits the *long tail* — every other
/// value-bearing field — without duplicating a node already created or surfacing
/// envelope bookkeeping. Lower-cased compare so schema casing variants can't
/// leak through.
const RICH_DETAIL_SKIP: &[&str] = &[
    // Already typed by the primary identity/credential extractors.
    "email",
    "username",
    "phone",
    "phone_number",
    // Alternate phone-number fields — typed as Phone by the shared alias loop
    // above, so the catch-all must not also mint them as Other().
    "mobile",
    "cell",
    "cellphone",
    "telephone",
    "tel",
    "msisdn",
    "contact_number",
    "phone2",
    "alt_phone",
    // WiFi SSID fields — typed as Ssid by the shared alias loop above.
    "ssid",
    "wifi_ssid",
    "wifi",
    "network_name",
    "wlan",
    "full_name",
    "name",
    "display_name",
    "nickname",
    "real_name",
    "realname",
    "ip",
    "country",
    "discord_id",
    "discordid",
    "steam_id",
    "steamid",
    "steam_id64",
    "password",
    "passwordhash",
    "password_hash",
    "hashed_password",
    "hash",
    "url",
    "url_str",
    "domain",
    // Composed/typed in the rich pass itself.
    "first_name",
    "firstname",
    "last_name",
    "lastname",
    "company",
    "employer",
    "organization",
    "organisation",
    "org",
    "mac",
    "mac_address",
    "bssid",
    "hwid",
    "machine_id",
    "device_id",
    "uuid",
    "guid",
    "computer_name",
    "machine",
    "hostname",
    "imei",
    "serial",
    "serial_number",
    "device_serial",
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
    // Cross-platform handle aliases — typed as platform-prefixed Usernames by the
    // social-handle map above, so the catch-all must not also mint them Other().
    "twitter_username",
    "x_username",
    "telegram_username",
    "youtube",
    "tiktok",
    "github",
    "reddit",
    // Mined for alternate emails/phones in the rich pass, not emitted verbatim.
    "bio",
    "city",
    "state",
    "region",
    "province",
    "zip",
    "zipcode",
    "postal",
    "postal_code",
    "postcode",
    "street",
    "address",
    "address_line",
    // Structural / metadata / provenance bookkeeping (kept verbatim on evidence,
    // but not worth a standalone graph node).
    "source",
    "source_db",
    "dbname",
    "_origin",
    "id",
    "_id",
    // Provider-internal record IDs — the pools stamp a `uid` and a
    // `migration_id` on every row (their own database keys, not the subject's).
    // Left un-skipped they leaked as `Other("uid")` / `Other("migration_id")`
    // junk nodes — one per record — diluting the graph with plumbing.
    "uid",
    "migration_id",
    "log_id",
    "log",
    "salt",
    // Validated + typed by each provider's own IBAN branch (OathNet's breach
    // path, SeekNow's extract path) — the mod-97 check-digit gate there refuses a
    // bad/redacted value. Skipped here so the UNVALIDATED catch-all can't also
    // mint an `Other("iban")` financial artifact for any string.
    "iban",
    "response_time_ms",
    "type",
    "success",
    "total",
    "breach_count",
    "stealer_count",
    "external_count",
    "index",
    "score",
    "_score",
    // API-envelope / wrapper plumbing surfaced when an endpoint double-wraps its
    // payload (e.g. SeekNow's TikTok endpoint nests the profile under a
    // `{credit, service, …, profile:{…}}` layer). Attribution and quota metadata,
    // not investigative data — kept on evidence, never a graph node.
    "credit",
    "service",
    "quota",
    "quota_remaining",
    "quota_max",
    "credits",
    "credits_remaining",
    "credits_daily_limit",
    "credits_used_today",
    "execution_time_ms",
    "response_time",
    "took_ms",
    "took",
    "version",
    "api_version",
    "count",
    "results_count",
    "timestamp",
    "ts",
    "resets_at",
    "plan",
    "mode",
    "query",
    "cached",
    // Domain WHOIS/RDAP metadata — surfaced as Domain *attributes* by the
    // dedicated DNS/RDAP modules, not worth duplicating as standalone graph
    // nodes (and `dns` is a record map, never an entity value).
    "registrar",
    "dns",
    "nameservers",
    "name_servers",
    "created",
    "created_date",
    "creation_date",
    "updated",
    "updated_date",
    "last_changed",
    "expires",
    "expiry",
    "expiration_date",
    "status",
    "whois",
];

/// `O(1)` membership view over [`RICH_DETAIL_SKIP`], built once on first use.
/// The catch-all pass runs this lookup per field per record, so a `HashSet`
/// replaces a linear scan of the ~100 `&str` entries.
static RICH_DETAIL_SKIP_SET: std::sync::LazyLock<HashSet<&'static str>> =
    std::sync::LazyLock::new(|| RICH_DETAIL_SKIP.iter().copied().collect());

/// Push a breach-PII entity: tags `breach`, the provider `source`, plus any
/// `extra_tags`, then a cloned evidence record. (Source-sector tagging is
/// applied universally at engine admission, so it is not done per-module.)
fn push_breach_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    source: &str,
    extra_tags: &[&str],
) {
    e.tag(tags::BREACH);
    e.tag(source);
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Push a stealer/infrastructure-CONTEXT entity: tags the provider `source` plus
/// any `extra_tags`, but deliberately NOT `breach`. Device fingerprints (MAC,
/// HWID, hostname, …) are infrastructure/context, not leaked PII.
fn push_context_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    source: &str,
    extra_tags: &[&str],
) {
    e.tag(source);
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Maximum-raw-data extractor: turn the long tail of a breach/stealer record
/// into first-class, pivotable entities. Typed where a kind fits (Person,
/// Organisation, Address, MacAddress, DeviceId, platform Usernames), and
/// `Other(field)` for everything else — so EVERY value-bearing field of the raw
/// response becomes a node, not just an evidence attribute. Confidences are
/// modest (secondary, record-derived) so this breadth never outranks the primary
/// identity entities. Pushes at full confidence; the caller demotes non-target
/// rows in its own idiom.
pub fn extract_rich_detail(
    item: &Value,
    scan_id: &str,
    source: &str,
    ev: &Evidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(obj) = item.as_object() else {
        return;
    };

    // ── Names: first + last → a composed Person (the bare `name`/`full_name`
    // path only fires when the value already contains a space). ──
    let first = val_str(item, "first_name").or_else(|| val_str(item, "firstname"));
    let last = val_str(item, "last_name").or_else(|| val_str(item, "lastname"));
    if let (Some(f), Some(l)) = (&first, &last) {
        let full = format!("{} {}", f.trim(), l.trim());
        // A SQL NULL (`\N`) or redaction marker in either name component is
        // absence, not a name — never compose a `"\N \N"` (nor a half-real
        // `"\N Smith"` / `"REDACTED Smith"`) Person from it.
        if full.len() >= 3
            && !is_absent_marker(f)
            && !is_absent_marker(l)
            // Breach dumps store `full_name = "{username} {username}"` when only a
            // handle is known; a doubled/slug username is not a real person.
            && !crate::core::validation::is_username_derived_name(&full)
            && seen.insert(format!("@person:{}", full.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Person, &full, confidence::MEDIUM_PLUS, scan_id),
                ev,
                source,
                &[],
            );
        }
    }

    // ── Organisation / employer. ──
    for k in ["company", "employer", "organization", "organisation", "org"] {
        if let Some(o) = val_str(item, k)
            && o.len() >= 2
            && !is_absent_marker(&o)
            && seen.insert(format!("@org:{}", o.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Organisation, &o, confidence::MEDIUM, scan_id),
                ev,
                source,
                &[],
            );
        }
    }

    // ── Device fingerprints — strong stealer-log pivots. ──
    for k in ["mac", "mac_address", "bssid"] {
        if let Some(m) = val_str(item, k)
            && m.len() >= 12
            && !is_absent_marker(&m)
            && !is_placeholder_fingerprint(&m)
            && seen.insert(format!("@mac:{}", m.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::MacAddress, &m, confidence::MEDIUM_PLUS, scan_id),
                ev,
                source,
                &["device"],
            );
        }
    }
    for k in [
        "hwid",
        "machine_id",
        "device_id",
        "uuid",
        "guid",
        "computer_name",
        "machine",
        "hostname",
        // Hardware serials / mobile equipment ids — globally-unique device
        // anchors. A shared IMEI/serial across ≥2 accounts is strong single-device
        // co-location proof; typed as DeviceId so AU-106 (shared-device identity)
        // consumes them. (Also in RICH_DETAIL_SKIP so the catch-all does not also
        // mint a duplicate `Other("imei")` from the distinct `@other:` namespace.)
        "imei",
        "serial",
        "serial_number",
        "device_serial",
    ] {
        if let Some(d) = val_str(item, k)
            && d.len() >= 3
            && !is_absent_marker(&d)
            && !is_placeholder_fingerprint(&d)
            && seen.insert(format!("@device:{k}:{}", d.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::DeviceId, &d, confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &["device", "stealer"],
            );
        }
    }

    // ── Extra social handles → platform-prefixed Username pivots. ──
    for (k, plat) in [
        ("telegram", "telegram"),
        ("skype", "skype"),
        ("facebook", "facebook"),
        ("instagram", "instagram"),
        ("twitter", "twitter"),
        ("linkedin", "linkedin"),
        ("vk", "vk"),
        ("snapchat", "snapchat"),
        // Cross-platform aliases a provider's profile carries under a namespaced
        // key — e.g. SeekNow's `username/github` (and GitHub itself) surface a
        // linked `twitter_username`. GitHub→Twitter is a standard high-signal
        // identity link; recover it as a pivotable `twitter:<handle>` at no cost.
        ("twitter_username", "twitter"),
        ("x_username", "twitter"),
        ("telegram_username", "telegram"),
        ("youtube", "youtube"),
        ("tiktok", "tiktok"),
        // github/reddit are real handle columns in both providers' breach
        // records; without these they fell to the catch-all as opaque
        // `Other("github")` junk nodes instead of first-class Username pivots the
        // github_user/reddit_user/etc. modules can resolve. Runs for SeekNow
        // (every record) and OathNet's stealer path at zero extra API cost.
        ("github", "github"),
        ("reddit", "reddit"),
    ] {
        if let Some(h) = val_str(item, k)
            && h.len() >= 2
            && !is_absent_marker(&h)
            && seen.insert(format!("@{plat}:{}", h.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(
                    EntityKind::Username,
                    format!("{plat}:{h}"),
                    confidence::MEDIUM_HIGH,
                    scan_id,
                ),
                ev,
                source,
                &[plat],
            );
        }
    }

    // ── Free-text `bio` mining → alternate contact leads. ──
    // A profile bio routinely carries an alternate email or phone the structured
    // columns miss — a genuine new pivot (unlocks HIBP/emailrep/phone modules).
    // Reuse the canonical scanner-grade extractors so "what an email/phone looks
    // like in free text" has one definition engine-wide. Lower confidence than a
    // structured field (inferred from prose). Shared here so BOTH breach providers
    // gain it on every record routed through the rich pass; OathNet's own breach
    // path mines bio separately, and the shared `seen` set dedups any overlap.
    if let Some(bio) = val_str(item, "bio") {
        for email in crate::util::extract::emails(&bio) {
            if seen.insert(email.clone()) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Email, &email, confidence::MEDIUM, scan_id),
                    ev,
                    source,
                    &["bio-mined"],
                );
            }
        }
        for phone in crate::util::extract::phones(&bio) {
            if seen.insert(format!("@bio-phone:{phone}")) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Phone, &phone, confidence::MEDIUM, scan_id),
                    ev,
                    source,
                    &["bio-mined"],
                );
            }
        }
    }

    // ── Physical location: each part as its own geo-hint Address, plus a
    // composed multi-part address (street/city/state/postal/country). ──
    let mut addr_parts: Vec<String> = Vec::new();
    for k in [
        "street",
        "address",
        "address_line",
        "city",
        "state",
        "region",
        "province",
        "zip",
        "zipcode",
        "postal",
        "postal_code",
        "postcode",
    ] {
        if let Some(p) = val_str(item, k)
            && p.len() >= 2
            && !is_absent_marker(&p)
        {
            if seen.insert(format!("@addr-part:{k}:{}", p.to_lowercase())) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Address, &p, confidence::LOW_MEDIUM, scan_id),
                    ev,
                    source,
                    &["geo-hint"],
                );
            }
            addr_parts.push(p);
        }
    }
    if addr_parts.len() >= 2 {
        if let Some(c) = val_str(item, "country")
            && !is_absent_marker(&c)
        {
            addr_parts.push(c);
        }
        let composed = addr_parts.join(", ");
        if seen.insert(format!("@addr:{}", composed.to_lowercase())) {
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&composed) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    confidence::LOW_MEDIUM,
                    scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag(tags::BREACH);
                c.tag(source);
                c.add_evidence(ev.clone());
                result.push(c);
            }
            push_breach_entity(
                result,
                Entity::new(
                    EntityKind::Address,
                    &composed,
                    confidence::MEDIUM_HIGH,
                    scan_id,
                ),
                ev,
                source,
                &["geo-hint", "composed-address"],
            );
        }
    }

    // WiFi SSID — a unique home/work network name is often a MORE precise
    // geolocator than the login IP (WiGLE resolves an SSID to GPS points). Field-
    // aliased (a bare string can't be value-detected); generic names ("linksys",
    // "xfinitywifi", …) and out-of-range lengths are rejected. The offline WiGLE
    // CSV path already mints `Ssid`, so the live breach/stealer paths were the
    // only ones dropping it — and this shared extractor fixes BOTH paid pools.
    for k in ["ssid", "wifi_ssid", "wifi", "network_name", "wlan"] {
        if let Some(s) = val_str(item, k)
            && (4..=32).contains(&s.chars().count()) // TargetKind::Ssid rejects >32
            && !is_absent_marker(&s)
            && !crate::modules::wigle::is_generic_ssid(&s)
            && seen.insert(format!("@ssid:{}", s.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::Ssid, &s, confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &["wifi-network", "stealer"],
            );
        }
    }

    // Alternate phone-number fields — carrier/breach dumps routinely file the
    // number under a non-canonical key. Field-aliased (NOT value-based: a bare
    // 7+ digit run could be a numeric ID, not a phone). Gated on digit COUNT so a
    // formatted number ("+1 (555) 123-4567") still qualifies. The bare-value seen
    // key coordinates with the primary phone path so a repeat isn't re-emitted.
    for k in [
        "mobile",
        "cell",
        "cellphone",
        "telephone",
        "tel",
        "msisdn",
        "contact_number",
        "phone2",
        "alt_phone",
    ] {
        if let Some(ph) = val_str(item, k)
            && ph.chars().filter(char::is_ascii_digit).count() >= 7
            && !is_absent_marker(&ph)
            && seen.insert(ph.to_lowercase())
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Phone, &ph, confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &[],
            );
        }
    }

    // ── Catch-all: every remaining value-bearing SCALAR field becomes an entity,
    // so no atomic data point in the raw record is left un-surfaced. Nested
    // objects/arrays are NOT turned into entities — a stringified JSON blob (e.g.
    // a `dns` record map) is not a meaningful graph node and only pollutes the
    // entity set; its atomic contents are surfaced by the typed paths above and
    // by the dedicated DNS/RDAP modules.
    //
    // Typed BY VALUE, not by field name (future-proof): a URL or email carried in
    // ANY field — a provider's `blog` / `html_url` / `recovery_email` / a field a
    // future endpoint adds — is surfaced as a pivotable `Url`/`Email` that feeds
    // crawl/DNS/identity expansion, instead of an inert `Other(field)` node that
    // pivots nowhere. Everything else falls through to `Other(field)`. ──
    for (k, v) in obj {
        // Lowercased field key for the O(1) set lookups below; only pay for the
        // copy when `k` actually contains uppercase ASCII (the common case is
        // already lowercase → no allocation, `kl` borrows `k`).
        let kl_lower;
        let kl: &str = if k.bytes().any(|b| b.is_ascii_uppercase()) {
            kl_lower = k.to_lowercase();
            &kl_lower
        } else {
            k.as_str()
        };
        if RICH_DETAIL_SKIP_SET.contains(kl) {
            continue;
        }
        let val = match v {
            Value::Null | Value::Array(_) | Value::Object(_) => continue,
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
        };
        if val.is_empty() || val.len() > 2000 || is_absent_marker(&val) {
            continue;
        }
        let trimmed = val.trim();

        // Value-typing 1 — a web URL in any field. Display assets (avatars,
        // images) are excluded by field name (`avatar*`/`image*`/…) AND by the
        // URL's own path extension (`.webp`/`.jpg`/…) — the latter future-proofs
        // against a provider naming an image field anything (TikTok's
        // `avatar_thumb`/`avatar_larger` are signed CDN `.webp` URLs). Display
        // media is not an investigative web page and would only aim the crawler at
        // an image CDN. Shares the `@url:` seen-key namespace with the primary URL
        // path so a URL already surfaced there is not re-minted.
        if !MEDIA_URL_FIELDS.contains(kl)
            && trimmed.len() >= 11
            && (trimmed.starts_with("http://") || trimmed.starts_with("https://"))
            && trimmed.contains('.')
            && !url_path_is_media(trimmed)
            && seen.insert(format!("@url:{}", trimmed.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Url, trimmed, confidence::MEDIUM, scan_id),
                ev,
                source,
                &["raw-field"],
            );
            continue;
        }

        // Value-typing 2 — an email address in any field (recovery/alt/contact
        // emails a future endpoint may surface under a novel key).
        if crate::util::extract::looks_like_email(trimmed)
            && seen.insert(format!("@email:{}", trimmed.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Email, trimmed, confidence::MEDIUM_HIGH, scan_id),
                ev,
                source,
                &["raw-field"],
            );
            continue;
        }

        // Value-typing 3 — a PUBLIC IP in any field (`lastip`/`last_ip`/
        // `registration_ip`/… or a key a future endpoint adds). A public IP is a
        // geolocation lead; private/reserved IPs are not, so they fall through to
        // `Other()`. Confidence MEDIUM_HIGH (0.55) stays below the provider
        // primary-IP path's MEDIUM_PLUS (0.60) so the primary node wins on
        // collision (both key by the bare value). The `continue` is
        // unconditional: it dedups against that primary key AND suppresses
        // the duplicate `Other(field)` this loop would otherwise mint.
        if crate::util::preflight::is_public_ip(trimmed) {
            if seen.insert(trimmed.to_string()) {
                push_breach_entity(
                    result,
                    Entity::new(
                        EntityKind::IpAddress,
                        trimmed,
                        confidence::MEDIUM_HIGH,
                        scan_id,
                    ),
                    ev,
                    source,
                    &["geolocation-lead", "raw-field"],
                );
            }
            continue;
        }

        if seen.insert(format!("@other:{k}:{}", val.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Other(k.clone()), &val, confidence::LOW, scan_id),
                ev,
                source,
                &["raw-field"],
            );
        }
    }
}

/// True when a URL's path (the segment before any `?`/`#`) ends in a known image
/// or media extension — a display asset, not an investigative web page. Value-
/// based so it catches an image URL under ANY field name (a provider's
/// `avatar_thumb`, `cover`, `banner`, …), including the signed-query CDN URLs
/// social endpoints return (`…/x.webp?x-signature=…`). Case-insensitive.
fn url_path_is_media(url: &str) -> bool {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .trim_end_matches('/');
    let tail = path.rsplit('.').next().unwrap_or("");
    matches!(
        tail.to_ascii_lowercase().as_str(),
        "webp"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "svg"
            | "bmp"
            | "ico"
            | "tiff"
            | "heic"
            | "avif"
            | "mp4"
            | "webm"
            | "mov"
            | "mp3"
            | "wav"
            | "ogg"
    )
}

/// Field names whose value is a display asset (profile picture / avatar / icon),
/// not an investigative web page — so the value-based URL typing in the catch-all
/// skips them rather than minting a crawl target pointed at an image CDN.
static MEDIA_URL_FIELDS: std::sync::LazyLock<HashSet<&'static str>> =
    std::sync::LazyLock::new(|| {
        [
            "avatar_url",
            "avatar",
            "image",
            "image_url",
            "img",
            "photo",
            "photo_url",
            "picture",
            "profile_pic",
            "profile_picture",
            "icon",
            "icon_url",
            "thumbnail",
            "thumb",
            "logo",
            "gravatar",
            "banner",
            "background_image",
        ]
        .into_iter()
        .collect()
    });

#[cfg(test)]
mod tests {
    include!("breach_rich_tests.rs");
}
