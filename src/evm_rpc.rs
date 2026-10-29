//! Keyless, read-only EVM account observations via a chain's public JSON-RPC.
//!
//! The chain-agnostic core shared by the per-chain modules (`base_rpc`, `eth_rpc`). This is an
//! independent OSINT method: no explorer index, paid database, private API or account
//! integration. One bounded batch reads the finalized account balance, outgoing nonce, and
//! contract-code presence. An address is not a verified identity; zero balances do not establish
//! absence of past activity. A public RPC is rate-limited and cannot enumerate a full transaction
//! history.

use serde_json::{Value, json};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

const MAX_CODE_HEX: usize = 2 * 24_576;
const MAX_QUANTITY_HEX: usize = 64;

/// One EVM chain's fixed identity and keyless public JSON-RPC endpoint. A per-chain module owns a
/// single `Chain` constant; this shared core reads only from it, so adding a chain is a new
/// constant and its wiring, never a second copy of the logic below.
#[derive(Debug, Clone, Copy)]
pub struct Chain {
    /// Module/source id, e.g. `base_rpc`.
    pub source: &'static str,
    /// Diagnostic label used in outcome reasons, e.g. `Base RPC`.
    pub display: &'static str,
    /// Human network name used in evidence, e.g. `Base mainnet`.
    pub network_human: &'static str,
    /// Machine network tag stored as the `network` attribute, e.g. `base_mainnet`.
    pub network_attr: &'static str,
    /// The public JSON-RPC origin.
    pub rpc_url: &'static str,
    /// The chain id the batch must echo, e.g. `8453`.
    pub chain_id: u64,
    /// The explicit selector prefix, e.g. `base:`.
    pub prefix: &'static str,
    /// The block-explorer address-page prefix, e.g. `https://basescan.org/address/`.
    pub explorer_prefix: &'static str,
    /// Entity tags, e.g. `["base", "evm", "public_rpc", "ownership_unverified"]`.
    pub tags: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// Explicit chain selector. A bare 0x-address is intentionally ambiguous across EVM chains and is
/// never silently routed to one chain.
///
/// A mixed-case selector is normalized but its optional EIP-55 checksum is not verified; the public
/// account lookup does not establish who controls it.
#[must_use]
pub fn canonical_selector(chain: &Chain, raw: &str) -> Option<String> {
    let address = raw.strip_prefix(chain.prefix)?;
    if address.len() != 42 || !address.starts_with("0x") {
        return None;
    }
    if !address[2..].bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}0x{}",
        chain.prefix,
        address[2..].to_ascii_lowercase()
    ))
}

/// Fixed, non-mutating mainnet RPC method set. A batch prevents per-field request explosions and
/// makes the response budget deterministic.
#[must_use]
pub fn request(chain: &Chain, address: &str) -> Option<Request> {
    let normalized = canonical_selector(chain, address)?;
    let wallet = normalized.strip_prefix(chain.prefix)?.to_owned();
    let payload = json!([
        {"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
        {"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":[wallet,"finalized"]},
        {"jsonrpc":"2.0","id":3,"method":"eth_getTransactionCount","params":[wallet,"finalized"]},
        {"jsonrpc":"2.0","id":4,"method":"eth_getCode","params":[wallet,"finalized"]}
    ]);
    Some(
        Request::post(chain.rpc_url, payload.to_string().into_bytes())
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
    )
}

fn failed(
    chain: &Chain,
    now: u64,
    kind: SourceOutcomeKind,
    status: Option<u16>,
    detail: &str,
) -> Report {
    Report {
        entities: Vec::new(),
        outcome: SourceExecutionOutcome::failed(chain.source, now, kind, status, detail),
    }
}

fn parse_hex(value: &Value, cap: usize) -> Option<&str> {
    let raw = value.as_str()?.strip_prefix("0x")?;
    if raw.is_empty()
        || raw.len() > cap
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    Some(raw)
}

/// Convert an unsigned JSON-RPC quantity without losing a 256-bit balance.
/// Uses 78 decimal digits on the stack; never a floating-point amount.
#[must_use]
pub fn quantity_decimal(value: &str) -> Option<String> {
    let hex = value.strip_prefix("0x")?;
    if hex.is_empty() || hex.len() > MAX_QUANTITY_HEX || (hex.len() > 1 && hex.starts_with('0')) {
        return None;
    }
    let mut digits = [0_u8; 78];
    for nibble in hex.bytes() {
        let mut carry = u16::try_from((nibble as char).to_digit(16)?).ok()?;
        for digit in digits.iter_mut().rev() {
            let updated = u16::from(*digit) * 16 + carry;
            *digit = (updated % 10) as u8;
            carry = updated / 10;
        }
        if carry != 0 {
            return None;
        }
    }
    let start = digits.iter().position(|digit| *digit != 0).unwrap_or(77);
    Some(
        digits[start..]
            .iter()
            .map(|d| char::from(b'0' + d))
            .collect(),
    )
}

/// Reject a partial, duplicated or foreign-chain JSON-RPC batch before admitting account evidence.
/// The caller owns the response buffer.
fn parse_batch(
    chain: &Chain,
    records: &[Value],
) -> Result<(String, String, bool), (SourceOutcomeKind, String)> {
    use SourceOutcomeKind::{Inconclusive, SchemaDrift};
    let display = chain.display;
    if records.len() != 4 {
        return Err((
            SchemaDrift,
            format!("{display} returned a partial or unexpected batch"),
        ));
    }
    let mut answers: [Option<&Value>; 4] = [None, None, None, None];
    for row in records {
        if row.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err((SchemaDrift, format!("{display} response protocol mismatch")));
        }
        if row.get("error").is_some() {
            return Err((
                Inconclusive,
                format!("{display} returned a JSON-RPC error; no account observation admitted"),
            ));
        }
        let index = row
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| id.checked_sub(1))
            .and_then(|id| usize::try_from(id).ok())
            .filter(|index| *index < 4)
            .ok_or_else(|| {
                (
                    SchemaDrift,
                    format!("{display} response identifier mismatch"),
                )
            })?;
        let result = row
            .get("result")
            .ok_or_else(|| (SchemaDrift, format!("{display} omitted a result")))?;
        if answers[index].replace(result).is_some() {
            return Err((
                SchemaDrift,
                format!("{display} duplicated a response identifier"),
            ));
        }
    }
    let [Some(chain_result), Some(balance), Some(nonce), Some(code)] = answers else {
        return Err((SchemaDrift, format!("{display} omitted a requested method")));
    };
    if parse_hex(chain_result, 16).and_then(|hex| u64::from_str_radix(hex, 16).ok())
        != Some(chain.chain_id)
    {
        return Err((
            SchemaDrift,
            format!("{display} replied for the wrong chain"),
        ));
    }
    let balance_wei = balance.as_str().and_then(quantity_decimal).ok_or_else(|| {
        (
            SchemaDrift,
            format!("{display} returned a malformed balance"),
        )
    })?;
    let outgoing_nonce = nonce.as_str().and_then(quantity_decimal).ok_or_else(|| {
        (
            SchemaDrift,
            format!("{display} returned a malformed outgoing nonce"),
        )
    })?;
    let code_hex = code
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|s| {
            s.len() <= MAX_CODE_HEX
                && s.len() % 2 == 0
                && s.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(|| {
            (
                SchemaDrift,
                format!("{display} returned malformed contract code"),
            )
        })?;
    Ok((balance_wei, outgoing_nonce, !code_hex.is_empty()))
}

/// Decode one complete public JSON-RPC batch. Unknown IDs, duplicates, a wrong chain, missing
/// fields, partial replies or a JSON-RPC error never create evidence. Internal to the core; the
/// per-chain modules reach it through [`lookup`].
fn interpret(chain: &Chain, fetched: &Fetched, selector: &str, scan_id: &str, now: u64) -> Report {
    let response = match whole_response(fetched, chain.display) {
        Ok(response) => response,
        Err(outcome) => {
            return Report {
                entities: Vec::new(),
                outcome,
            };
        }
    };
    if let Err(outcome) = answer(fetched, chain.display) {
        return Report {
            entities: Vec::new(),
            outcome,
        };
    }
    let records: Vec<Value> = match decode_json(response, chain.source, now, chain.display) {
        Ok(rows) => rows,
        Err(outcome) => {
            return Report {
                entities: Vec::new(),
                outcome,
            };
        }
    };
    let (balance_wei, outgoing_nonce, has_code) = match parse_batch(chain, &records) {
        Ok(account) => account,
        Err((kind, detail)) => return failed(chain, now, kind, Some(response.status), &detail),
    };
    let Some(normalized) = canonical_selector(chain, selector) else {
        return failed(
            chain,
            now,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            &format!("{} selector was not canonical", chain.display),
        );
    };
    let address = normalized.strip_prefix(chain.prefix).unwrap_or("");
    let code_presence = if has_code {
        "contract_code_present"
    } else {
        "no_code_at_finalized_block"
    };
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(chain.source, scan_id),
        format!(
            "{} account state at finalized block tag (read-only JSON-RPC)",
            chain.network_human
        ),
    )
    .with_attr("chain_id", chain.chain_id.to_string())
    .with_attr("network", chain.network_attr)
    .with_attr("balance_wei", balance_wei)
    .with_attr("outgoing_nonce", outgoing_nonce)
    .with_attr("code_presence", code_presence)
    .with_attr("block_tag", "finalized")
    .with_attr("rpc_origin", chain.rpc_url)
    .with_attr("source_url", chain.rpc_url)
    .with_attr(
        "explorer_url",
        format!("{}{address}", chain.explorer_prefix),
    )
    .with_attr(
        "does_not_show",
        "address ownership, identity, full transaction history, or one atomic block snapshot",
    );
    let mut entities = Vec::with_capacity(1);
    push_entity(
        &mut entities,
        EntityKind::CryptoAddress,
        &normalized,
        0.75,
        scan_id,
        evidence,
        chain.tags,
    );
    Report {
        entities,
        outcome: SourceExecutionOutcome::success(chain.source, now, 1)
            .with_http_status(response.status),
    }
}

/// Read account state without indexing services, authentication or transfers. The method is
/// read-only, and any upstream error remains explicit.
///
/// # Errors
/// Returns guarded network-boundary errors without converting them into a negative account finding.
pub fn lookup<T: Transport + ?Sized>(
    chain: &Chain,
    transport: &T,
    selector: &str,
    scan_id: &str,
    now: u64,
) -> Result<Report, Error> {
    let Some(request) = request(chain, selector) else {
        return Err(Error::invalid_value(format!(
            "expected {}0x followed by 40 hex digits",
            chain.prefix
        )));
    };
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects().paced(),
        chain.source,
        now,
    )?;
    Ok(interpret(chain, &fetched, selector, scan_id, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::OneResponse;

    /// A deliberately non-real chain, so these tests exercise the generic core rather than any
    /// shipped chain's configuration (those are covered in `base_rpc` and `eth_rpc`).
    const TEST: Chain = Chain {
        source: "test_rpc",
        display: "Test RPC",
        network_human: "Test mainnet",
        network_attr: "test_mainnet",
        rpc_url: "https://rpc.test.invalid",
        chain_id: 42,
        prefix: "test:",
        explorer_prefix: "https://explorer.test.invalid/address/",
        tags: &["test", "evm", "public_rpc", "ownership_unverified"],
    };
    const WALLET: &str = "test:0x1111111111111111111111111111111111111111";
    // chainId 0x2a = 42; balance 1e18 wei; nonce 0x2a; non-empty code.
    const BATCH: &str = r#"[
        {"jsonrpc":"2.0","id":3,"result":"0x2a"},
        {"jsonrpc":"2.0","id":1,"result":"0x2a"},
        {"jsonrpc":"2.0","id":4,"result":"0x6000"},
        {"jsonrpc":"2.0","id":2,"result":"0xde0b6b3a7640000"}
    ]"#;

    #[test]
    fn selector_normalizes_and_rejects_foreign_or_bad_input() {
        assert_eq!(canonical_selector(&TEST, WALLET).as_deref(), Some(WALLET));
        assert_eq!(canonical_selector(&TEST, &WALLET.to_uppercase()), None);
        for bad in [
            "0x1111111111111111111111111111111111111111",
            "base:0x1111111111111111111111111111111111111111",
            "test:0x111",
            "test:0x111111111111111111111111111111111111111g",
            "test:0x1111111111111111111111111111111111111111\n",
        ] {
            assert!(canonical_selector(&TEST, bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn decimal_u256_preserves_exact_wei() {
        assert_eq!(quantity_decimal("0x0").as_deref(), Some("0"));
        assert_eq!(
            quantity_decimal("0xde0b6b3a7640000").as_deref(),
            Some("1000000000000000000")
        );
        assert_eq!(
            quantity_decimal(&format!("0x{}", "f".repeat(64))).as_deref(),
            Some("115792089237316195423570985008687907853269984665640564039457584007913129639935")
        );
        assert!(quantity_decimal("0x").is_none());
        assert!(quantity_decimal("0xGG").is_none());
        for noncanonical in ["0x00", "0x01", "0x0a", "0x0001"] {
            assert!(quantity_decimal(noncanonical).is_none(), "{noncanonical}");
        }
        assert!(quantity_decimal(&format!("0x{}", "f".repeat(65))).is_none());
    }

    #[test]
    fn order_independent_batch_yields_provenance_without_claiming_ownership() {
        let found = lookup(&TEST, &OneResponse::json(200, BATCH), WALLET, "scan", 1).unwrap();
        assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
        assert_eq!(found.entities.len(), 1);
        let evidence = &found.entities[0].evidence[0];
        assert_eq!(
            evidence.attributes.get("balance_wei").unwrap(),
            "1000000000000000000"
        );
        assert_eq!(evidence.attributes.get("outgoing_nonce").unwrap(), "42");
        assert_eq!(
            evidence.attributes.get("code_presence").unwrap(),
            "contract_code_present"
        );
        assert_eq!(evidence.attributes["network"], "test_mainnet");
        assert_eq!(evidence.attributes["chain_id"], "42");
        assert_eq!(
            evidence.attributes["explorer_url"],
            "https://explorer.test.invalid/address/0x1111111111111111111111111111111111111111"
        );
        assert!(evidence.attributes["does_not_show"].contains("ownership"));
    }

    #[test]
    fn wrong_chain_duplicate_ids_and_rpc_errors_do_not_become_evidence() {
        for body in [
            BATCH.replace(r#""id":1,"result":"0x2a""#, r#""id":1,"result":"0x1""#),
            BATCH.replace(r#""id":1,"result":"0x2a""#, r#""id":1,"result":"0x02a""#),
            BATCH.replace(r#""id":3,"result":"0x2a""#, r#""id":2,"result":"0x2a""#),
            BATCH.replace("0xde0b6b3a7640000", "0x0de0b6b3a7640000"),
            BATCH.replace(
                r#""id":1,"result":"0x2a""#,
                r#""id":1,"error":{"message":"quota exceeded"}"#,
            ),
        ] {
            let result = lookup(&TEST, &OneResponse::json(200, &body), WALLET, "scan", 1).unwrap();
            assert!(result.entities.is_empty(), "{body}");
            assert!(!result.outcome.kind.is_accepted(), "{body}");
            assert!(!result.outcome.reason().contains("quota exceeded"));
        }
    }

    #[test]
    fn rate_limit_and_non_json_cannot_be_valid_zero() {
        let fixture = |status, body| {
            let fetched = fetch(
                &OneResponse::json(status, body),
                request(&TEST, WALLET).expect("valid selector"),
                None,
                &FetchOptions::no_redirects(),
                TEST.source,
                1,
            )
            .expect("fake transport fetch");
            interpret(&TEST, &fetched, WALLET, "scan", 1)
        };
        let limited = fixture(429, "rate limited");
        assert!(limited.entities.is_empty());
        assert_eq!(limited.outcome.kind, SourceOutcomeKind::RateLimited);
        let malformed = fixture(200, "{bad");
        assert!(malformed.entities.is_empty());
        assert_eq!(malformed.outcome.kind, SourceOutcomeKind::ParserDrift);
    }
}
