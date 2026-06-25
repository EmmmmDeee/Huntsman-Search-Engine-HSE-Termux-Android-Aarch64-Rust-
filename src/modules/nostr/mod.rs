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
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::looks_like_email;
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "nostr";
/// bech32 data charset (BIP-173).
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Max relay endpoints surfaced as infrastructure pivots per identity.
const RELAY_CAP: usize = 8;

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
        "Nostr identity resolution (npub → pubkey offline decode; NIP-05 name@domain → pubkey + relays)"
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
                {
                    let url = format!(
                        "https://{domain}/.well-known/nostr.json?name={}",
                        urlencode(name)
                    );
                    // 404 (every ordinary mail domain) → not a Nostr identity, a
                    // clean miss.
                    if let Some(doc) = fetch_json_or_404::<Nip05>(&ctx.http, SRC, &url).await?
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
        emit_identity(npub, hex, 0.85, 0.85, &ev, scan_id, result);
    } else {
        // Encoding cannot fail for a 64-hex key, but never drop the pubkey if it
        // somehow does.
        let mut pk = Entity::new(EntityKind::Other("nostr-pubkey".into()), hex, 0.85, scan_id);
        pk.tag("nostr");
        pk.tag("nostr-pubkey");
        pk.add_evidence(ev.clone());
        result.push(pk);
    }

    // The seed email is a confirmed Nostr identity (GREATEST-merge only ever
    // adds the tag/evidence, never lowers existing confidence).
    let mut seed = Entity::new(EntityKind::Email, email, 0.80, scan_id);
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
    // to an HTTP crawler.
    if let Some(relays) = doc.relays.get(hex) {
        for relay in relays
            .iter()
            .filter(|r| r.starts_with("wss://") || r.starts_with("ws://"))
            .take(RELAY_CAP)
        {
            let mut r = Entity::new(
                EntityKind::Other("nostr-relay".into()),
                relay,
                0.55,
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
    let mut chk_input = hrp_expand("npub");
    chk_input.extend_from_slice(&values);
    if bech32_polymod(&chk_input) != 1 {
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
    let mut chk_input = hrp_expand("npub");
    chk_input.extend_from_slice(&data);
    chk_input.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&chk_input) ^ 1;
    for i in 0..6 {
        data.push(((polymod >> (5 * (5 - i))) & 0x1f) as u8);
    }
    let mut out = String::from("npub1");
    out.extend(data.iter().map(|&v| BECH32[v as usize] as char));
    Some(out)
}

/// bech32 checksum polynomial (BIP-173).
fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Expand a human-readable prefix into the bech32 checksum pre-image.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 0x1f));
    v
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
