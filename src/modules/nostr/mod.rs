//! Nostr identity resolution — offline `npub` decode **and** keyless NIP-05
//! lookup. Free, no API key.
//!
//! Nostr identities are 32-byte public keys. They surface in two public forms,
//! and this module resolves both:
//!
//! * **`npub1…`** — the key bech32-encoded (BIP-173). It is decoded **offline**
//!   (no network, no key) into the canonical hex pubkey by validating the
//!   `npub` HRP, the bech32 checksum, and the 256-bit length — so a random or
//!   non-Nostr string yields nothing rather than a fabricated key.
//! * **NIP-05 `name@domain`** — an *email-shaped* Nostr identifier verified
//!   against the domain's own well-known document:
//!   `GET https://<domain>/.well-known/nostr.json?name=<name>`.
//!   An ordinary mail domain returns `404` (it serves no such file); a
//!   Nostr-enabled domain returns `{"names":{"<name>":"<hexpubkey>"},…}`,
//!   confirming the identity *and* — via the optional `relays` map — the
//!   relay infrastructure that account publishes to.
//!
//! Both paths converge on the same canonical identity: the hex pubkey and the
//! human-viewable profile URL `https://njump.me/<npub>` (the keyless Nostr
//! gateway), so an `npub` seed and a NIP-05 seed for the same person fold
//! together. This is the decentralized-social counterpart to
//! [`crate::modules::fediverse`] (Mastodon/WebFinger) for the fastest-growing
//! protocol the keyed OSINT stacks don't cover. No mock: NIP-05 JSON is fetched
//! live from the domain's own endpoint, and the `npub` decode is pure
//! arithmetic over the identifier itself.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::looks_like_email;
use crate::util::http::{fetch_json_probe, urlencode};

const SRC: &str = "nostr";
/// bech32 data charset (BIP-173).
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub struct Nostr;

/// A NIP-05 well-known document: a `name → hex pubkey` map and an optional
/// `pubkey → [relay]` map.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Nip05 {
    names: BTreeMap<String, String>,
    relays: BTreeMap<String, Vec<String>>,
}

#[async_trait]
impl Module for Nostr {
    fn name(&self) -> &'static str {
        "nostr"
    }

    fn description(&self) -> &'static str {
        "Nostr identity resolution — offline-decodes an npub to its pubkey and resolves NIP-05 name@domain to pubkey plus relays"
    }

    fn priority(&self) -> u8 {
        105
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only so the dispatch index stays consistent; the `npub` shape gate
        // (Username) and the NIP-05 email-shape gate (Email) are applied in
        // process().
        matches!(t.kind, TargetKind::Username | TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Open decentralized social graph — T1593.001 Search Open
        // Websites/Domains; NIP-05 consumes an email-shaped identifier —
        // T1589.002 Email Addresses.
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Also emits `Other("nostr-pubkey")` / `Other("nostr-relay")`, which
        // cannot appear in a `const` slice (they own a `String`); the canonical
        // pivots are the profile URL, the local username, and the seed email.
        const KINDS: &[EntityKind] = &[EntityKind::Url, EntityKind::Username, EntityKind::Email];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let v = target.value.trim();

        match target.kind {
            // Offline `npub` decode — deterministic, no network.
            TargetKind::Username => {
                if let Some(hex) = decode_npub(v) {
                    let npub = v.to_ascii_lowercase();
                    let ev =
                        Evidence::new(SRC, format!("Nostr key `{npub}` (offline npub decode)"))
                            .with_attr("npub", &npub)
                            .with_attr("pubkey_hex", &hex)
                            .with_attr("source", "npub-bech32");
                    emit_identity(&npub, &hex, 0.74, 0.72, &ev, &ctx.scan_id, &mut result);
                }
            }
            // NIP-05: `name@domain` → the domain's own well-known document.
            TargetKind::Email => {
                if looks_like_email(v)
                    && let Some((name, domain)) = v.split_once('@')
                    && nip05_worth_probing(domain)
                {
                    let url = format!(
                        "https://{domain}/.well-known/nostr.json?name={}",
                        urlencode(name)
                    );
                    // 404 (every ordinary mail domain) → not a Nostr identity, a
                    // clean miss. Freemail domains are skipped entirely above (a
                    // certain 404 — they serve no NIP-05 document). A domain that
                    // is simply unreachable (no server, DNS/TLS/connection failure)
                    // is the SAME "not a Nostr identity" miss, not a module error —
                    // `fetch_json_probe` folds both into `None`.
                    if let Some(doc) = fetch_json_probe::<Nip05>(&ctx.http, SRC, &url).await
                        && let Some(hex) = lookup_pubkey(&doc, name).filter(|h| is_hex64(h))
                    {
                        let hex = hex.to_ascii_lowercase();
                        emit_nip05(name, domain, v, &hex, &doc, &ctx.scan_id, &mut result);
                    }
                }
            }
            _ => {}
        }

        Ok(result)
    }
}

/// Whether `domain` is worth a NIP-05 probe. A freemail provider (gmail/outlook/
/// yahoo/…) serves no `/.well-known/nostr.json`, so the probe is a guaranteed 404
/// — skip it rather than spend the request on a certain miss (freemail is the
/// majority of email seeds). A custom domain MIGHT self-host NIP-05, so it is
/// still probed. Pure. (The `fediverse` module applies the identical guard to its
/// WebFinger probe.)
fn nip05_worth_probing(domain: &str) -> bool {
    !crate::util::domains::is_freemail(domain)
}

/// Emit the canonical, path-independent identity entities — the `njump.me`
/// profile URL (keyed on the `npub`) and the hex pubkey — so an `npub` seed and
/// a NIP-05 seed for the same key fold together. Shared by both resolution
/// paths; each supplies its own evidence and confidences.
fn emit_identity(
    npub: &str,
    hex: &str,
    url_conf: f64,
    pubkey_conf: f64,
    ev: &Evidence,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    // Human-viewable profile on the keyless Nostr gateway.
    let profile_url = format!("https://njump.me/{npub}");
    let mut u = Entity::new(EntityKind::Url, &profile_url, url_conf, scan_id);
    u.tag("nostr");
    u.tag("social-profile");
    u.add_evidence(ev.clone());
    result.push(u);

    // The canonical hex pubkey. `Other(_)` is never re-dispatched as a scan
    // target (no consumer resolves a raw Nostr key over keyless HTTP), so it is
    // a searchable, correlatable identity with no scan noise.
    let mut pk = Entity::new(
        EntityKind::Other("nostr-pubkey".into()),
        hex,
        pubkey_conf,
        scan_id,
    );
    pk.tag("nostr");
    pk.tag("nostr-pubkey");
    pk.add_evidence(ev.clone());
    result.push(pk);
}

/// Build entities from a confirmed NIP-05 resolution: the shared identity, the
/// seed email flagged as a confirmed NIP-05 identity, the local username pivot,
/// and the account's relay infrastructure.
fn emit_nip05(
    name: &str,
    domain: &str,
    email: &str,
    hex: &str,
    doc: &Nip05,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    let npub = encode_npub(hex);
    let ev = Evidence::new(SRC, format!("Nostr NIP-05 identity `{email}` verified"))
        .with_attr("nip05", email)
        .with_attr("domain", domain)
        .with_attr("pubkey_hex", hex);
    let ev = match npub.as_deref() {
        Some(n) => ev.with_attr("npub", n),
        None => ev,
    };

    // The canonical identity (profile URL + hex pubkey), keyed on the npub so it
    // converges with an npub-seeded scan. NIP-05 is domain-bound and live, so it
    // is the higher-confidence path.
    if let Some(ref npub) = npub {
        emit_identity(
            npub,
            hex,
            confidence::HIGH_PLUSPLUS_PLUS,
            confidence::HIGH_PLUSPLUS_PLUS,
            &ev,
            scan_id,
            result,
        );
    } else {
        // Encoding cannot fail for a 64-hex key, but never drop the pubkey if it
        // somehow does.
        let mut pk = Entity::new(
            EntityKind::Other("nostr-pubkey".into()),
            hex,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        pk.tag("nostr");
        pk.tag("nostr-pubkey");
        pk.add_evidence(ev.clone());
        result.push(pk);
    }

    // The seed email is a confirmed Nostr identity (GREATEST-merge only ever
    // adds the tag/evidence, never lowers existing confidence).
    let mut seed = Entity::new(EntityKind::Email, email, confidence::HIGH_PLUSPLUS, scan_id);
    seed.tag("nostr");
    seed.tag("nip05");
    seed.add_evidence(ev.clone());
    result.push(seed);

    // The local part as a username pivot, unless it is the `_` root identifier
    // (a domain-primary marker, not a real handle).
    if name != "_" && name.len() >= 2 {
        let mut un = Entity::new(EntityKind::Username, name, 0.66, scan_id);
        un.tag("nostr");
        un.add_evidence(ev.clone());
        result.push(un);
    }

    // Relay endpoints the account publishes to — infrastructure pivots. Emitted
    // as `Other("nostr-relay")` (not `Url`) so a `wss://` endpoint is never fed
    // to an HTTP crawler. Every DISTINCT ws/wss relay is surfaced (deduped by
    // `seen_relay`): the NIP-05 `relays` array is the identity's OWN, self-
    // published set served from its `.well-known/nostr.json`, so each entry is a
    // genuine infrastructure pivot for this exact pubkey — not co-tenant noise.
    // Dropping the tail would hide relays the subject actually uses; the list is
    // fetched once and yields terminal (non-crawled) entities, so there is no
    // frontier to bound.
    if let Some(relays) = doc.relays.get(hex) {
        let mut seen_relay: std::collections::HashSet<String> = std::collections::HashSet::new();
        for relay in relays
            .iter()
            .filter(|r| r.starts_with("wss://") || r.starts_with("ws://"))
            .filter(|r| seen_relay.insert(r.to_ascii_lowercase()))
        {
            let mut r = Entity::new(
                EntityKind::Other("nostr-relay".into()),
                relay,
                confidence::MEDIUM_HIGH,
                scan_id,
            );
            r.tag("nostr");
            r.tag("nostr-relay");
            r.tag("infrastructure");
            r.add_evidence(
                Evidence::new(SRC, format!("Relay for Nostr identity `{email}`"))
                    .with_attr("nip05", email)
                    .with_attr("relay", relay),
            );
            result.push(r);
        }
    }
}

/// Case-insensitive NIP-05 name lookup (exact match preferred).
fn lookup_pubkey<'a>(doc: &'a Nip05, name: &str) -> Option<&'a str> {
    if let Some(h) = doc.names.get(name) {
        return Some(h.as_str());
    }
    doc.names
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// True for a 64-char lowercase-or-uppercase hex string (a 32-byte pubkey).
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Decode a Nostr `npub1…` (bech32, BIP-173) into its 32-byte pubkey as
/// lowercase hex, validating the HRP, charset, checksum, and 256-bit length.
/// `None` for anything that is not a well-formed `npub`.
fn decode_npub(s: &str) -> Option<String> {
    let s = s.trim();
    // bech32 caps the whole string at 90 chars; an npub is 63.
    if !(8..=90).contains(&s.len()) {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let rest = lower.strip_prefix("npub1")?;
    let mut values = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        values.push(BECH32.iter().position(|&x| x == c)? as u8);
    }
    // Checksum: polymod over hrp-expand("npub") ++ data must equal 1.
    let mut chk_input = crate::util::bech32::hrp_expand(b"npub");
    chk_input.extend_from_slice(&values);
    if crate::util::bech32::polymod(&chk_input) != 1 {
        return None;
    }
    // Drop the 6-symbol checksum, then regroup 5-bit → 8-bit.
    let data = values.get(..values.len().checked_sub(6)?)?;
    let bytes = convert_bits(data, 5, 8, false)?;
    if bytes.len() != 32 {
        return None;
    }
    Some(hex::encode(bytes))
}

/// Encode a 32-byte pubkey (hex) as a Nostr `npub1…`. Inverse of
/// [`decode_npub`]; lets a NIP-05 hit surface the canonical `npub` form so both
/// resolution paths converge. `None` if `hex` is not a 32-byte hex key.
fn encode_npub(hex_pubkey: &str) -> Option<String> {
    let bytes = hex::decode(hex_pubkey).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut data = convert_bits(&bytes, 8, 5, true)?;
    // Append the 6-symbol checksum.
    let mut chk_input = crate::util::bech32::hrp_expand(b"npub");
    chk_input.extend_from_slice(&data);
    chk_input.extend_from_slice(&[0u8; 6]);
    let polymod = crate::util::bech32::polymod(&chk_input) ^ 1;
    for i in 0..6 {
        data.push(((polymod >> (5 * (5 - i))) & 0x1f) as u8);
    }
    let mut out = String::from("npub1");
    out.extend(data.iter().map(|&v| BECH32[v as usize] as char));
    Some(out)
}

/// Regroup a base-`from` digit stream into base-`to` digits (the bech32
/// 5↔8-bit conversion). `None` on an out-of-range digit or invalid padding.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        if u32::from(value) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(value);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || (acc << (to - bits)) & maxv != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
