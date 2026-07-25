//! Sanctioned digital-currency addresses — the half of the SDN list this
//! module used to download and throw away.
//!
//! OFAC publishes the wallet addresses it designates inline in the `Remarks`
//! column, not in a column of their own. A live pull while this was written
//! carried **463 address designations across 91 SDN rows and 15 currency
//! symbols** (XBT 252, ETH 72, TRX 64, USDT 42, LTC 8, XMR 6, DASH 5, ZEC 3,
//! USDC/DOGE/BCH 2 each, XVG/SOL/ETC/BTG 1 each) — every one of them already
//! being fetched, parsed into [`SdnRecord::remarks`](super::parse::SdnRecord),
//! and then discarded, because screening only ever looked at names.
//!
//! # Grammar
//! Remarks are `;`-separated clauses. An address clause is:
//!
//! ```text
//! [alt. ]Digital Currency Address - <SYMBOL> <ADDRESS>
//! ```
//!
//! The `alt. ` prefix marks the second and subsequent addresses on one row —
//! OFAC's convention for "also known as", the same one it uses for alias
//! names. Verified against the live file: those two are the ONLY clause
//! prefixes that occur, and every well-formed clause's payload is exactly two
//! whitespace-separated tokens.
//!
//! # Why this matters more than a name match
//! Everything in [the parent module](super)'s misattribution-risk apparatus —
//! the deliberately-lowered confidence, the `caution` attribute, the
//! `needs-identity-verification` tag — exists because matching a *name*
//! against a global list of common transliterations is inherently fuzzy.
//!
//! An address match is not. A wallet address is a high-entropy identifier that
//! names exactly one thing; if the string is on the list, the designation
//! applies to it, full stop. So an address hit is graded far higher and
//! carries none of the identity-verification hedging — see
//! [`ADDRESS_HIT_CONFIDENCE`](super::entity::ADDRESS_HIT_CONFIDENCE).
//!
//! Pure: no network, no IO, no global state.

use super::parse::SdnRecord;

/// The literal that introduces an address in a remarks clause.
const MARKER: &str = "Digital Currency Address - ";

/// OFAC's "and also this one" prefix on the second and subsequent addresses of
/// a row.
const ALT_PREFIX: &str = "alt.";

/// One digital-currency address exactly as OFAC designated it.
///
/// `symbol` is Treasury's own currency code (`XBT`, `TRX`, `USDT`, …), kept
/// verbatim rather than mapped onto
/// [`core::crypto`](crate::core::crypto)'s `crypto_<chain>` tags. Those tags
/// are HSE's *inference* from an address's shape; this is the designating
/// authority's own statement of what it designated. Recording OFAC's symbol
/// keeps the two apart — a `USDT` designation is a token designation, and
/// collapsing it into whichever chain the address happens to live on would be
/// putting words in Treasury's mouth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SanctionedAddress {
    /// OFAC's currency symbol for the designation, verbatim.
    pub(super) symbol: String,
    /// The address string, verbatim — never case-folded. See [`match_key`] for
    /// why folding happens at comparison time and not here.
    pub(super) address: String,
}

/// Every address designated by one SDN row, in the order OFAC lists them.
///
/// Malformed clauses are skipped rather than guessed at: a clause whose
/// payload is not exactly `<SYMBOL> <ADDRESS>` is not an address designation
/// this parser understands, and emitting a half-read one would be inventing a
/// sanctions finding. Total — never panics on any input.
pub(super) fn digital_currency_addresses(remarks: &str) -> Vec<SanctionedAddress> {
    remarks
        .split(';')
        .filter_map(|clause| {
            let clause = clause.trim();
            // Strip OFAC's `alt. ` marker if present; it carries no meaning
            // beyond "this row has more than one".
            let clause = clause
                .strip_prefix(ALT_PREFIX)
                .map_or(clause, str::trim_start);
            let payload = clause.strip_prefix(MARKER)?;
            let mut tokens = payload.split_whitespace();
            let symbol = tokens.next()?;
            let address = tokens.next()?;
            // Exactly two tokens, or it isn't the grammar above.
            if tokens.next().is_some() || symbol.is_empty() || address.is_empty() {
                return None;
            }
            Some(SanctionedAddress {
                symbol: symbol.to_string(),
                address: address.to_string(),
            })
        })
        .collect()
}

/// The form two addresses are compared in.
///
/// EVM addresses are hex, and hex is case-insensitive — but OFAC publishes
/// many of them in EIP-55 mixed-case checksum form (47 of the 463 designations
/// in the live pull above carried uppercase hex digits). An operator who
/// pastes the all-lowercase form of a sanctioned Ethereum wallet — the same
/// address, and what most explorers and wallets emit — would MISS the
/// designation entirely under a plain string match. That is a screening false
/// negative on an authoritative government list, which is the worst failure
/// this module can have. So `0x…` keys fold to lowercase.
///
/// **Nothing else does.** Base58 — Bitcoin, TRON, Litecoin, Solana, Monero,
/// every other symbol on the list — is case-SIGNIFICANT: its alphabet
/// deliberately contains both cases as distinct characters, and a case-variant
/// of a valid address is a different string that is almost certainly not a
/// valid address at all. Folding those would manufacture matches that OFAC
/// never made, which is the opposite failure and a worse one: telling an
/// operator a wallet is sanctioned when it is not.
fn match_key(address: &str) -> String {
    let is_evm_hex = address.len() > 2
        && (address.starts_with("0x") || address.starts_with("0X"))
        && address[2..].chars().all(|c| c.is_ascii_hexdigit());
    if is_evm_hex {
        address.to_ascii_lowercase()
    } else {
        address.to_string()
    }
}

/// True if `a` and `b` are the same designated address — see [`match_key`].
pub(super) fn addresses_match(a: &str, b: &str) -> bool {
    match_key(a) == match_key(b)
}

/// Every SDN row that designates `query`, paired with the designation clause
/// that matched it.
///
/// One address can appear on more than one row (co-designated entities share
/// wallets — 463 designations resolve to 456 distinct addresses in the live
/// pull), so this returns all of them rather than the first: an operator
/// screening a wallet needs to know about *every* party OFAC tied to it, not
/// whichever row happened to sort first.
///
/// Uncapped, deliberately. The upper bound is the number of SDN rows carrying
/// the same address, which the data puts in the low single digits; a cap here
/// could only ever hide a genuine co-designation. Pure.
pub(super) fn screen_address<'a>(
    records: &'a [SdnRecord],
    query: &str,
) -> Vec<(&'a SdnRecord, SanctionedAddress)> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }
    records
        .iter()
        // Cheap substring reject first: 99.5% of SDN rows carry no address at
        // all, and skipping the clause split on those is what keeps screening
        // an O(rows) scan rather than an O(clauses) one.
        .filter(|r| r.remarks.contains(MARKER))
        .flat_map(|rec| {
            digital_currency_addresses(&rec.remarks)
                .into_iter()
                .filter(|sa| addresses_match(&sa.address, query))
                .map(move |sa| (rec, sa))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    include!("crypto_tests.rs");
}
