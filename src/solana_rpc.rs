//! Keyless, read-only Solana mainnet-beta account observations via a public JSON-RPC.
//!
//! An independent OSINT method beside the EVM legs (`base_rpc`, `eth_rpc`): no explorer index,
//! paid database, private API or account integration. One bounded batch confirms the cluster by
//! its genesis hash, reads the account at finalized commitment (lamports, owner program,
//! executable flag, data size and at most the first 355 bytes of its data), lists the newest
//! transactions that name the address (whoever signed them) and reads the first slot the node
//! still holds, which bounds that list. Only
//! the SPL Token and Token-2022 layouts and an upgradeable program's header are decoded from the
//! data, so a token account names the wallet that owns it and any delegate or close authority, a
//! mint names its mint and freeze authorities, and a multisig names its signers: on-chain control
//! relations, each a `sol:` pivot, never an identity. A public RPC is rate-limited and retains
//! only recent history, so the absence of a listed transaction does not show an address was never
//! used, and a listed one is not the address's own act.

use serde_json::{Value, json};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "solana_rpc";
pub const RPC_URL: &str = "https://solana-rpc.publicnode.com";
/// The explicit selector prefix. Every SVM chain shares Solana's address format, so a bare
/// address is never silently routed to Solana mainnet-beta.
pub const PREFIX: &str = crate::canonical::SOLANA_PREFIX;
/// Solana mainnet-beta's genesis hash, the cluster identity the batch must echo: a devnet,
/// testnet or other SVM cluster's reply is never read as mainnet-beta state.
pub const MAINNET_GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

const DISPLAY: &str = "Solana RPC";
const NETWORK: &str = "solana_mainnet_beta";
const EXPLORER_PREFIX: &str = "https://explorer.solana.com/address/";
const TAGS: &[&str] = &["solana", "svm", "public_rpc", "ownership_unverified"];
/// The account data asked for: a whole SPL multisig (355 bytes), which also covers a token
/// account (165), a mint (82) and the Token-2022 account-type byte at offset 165. Nothing wider
/// is ever requested.
const DATA_SLICE: u64 = 355;
/// The most signers an SPL multisig holds.
const MAX_MULTISIG_SIGNERS: u8 = 11;
/// The newest signatures asked for.
const SIGNATURE_LIMIT: usize = 10;
/// A transaction signature is 64 bytes, at most 88 base58 characters.
const MAX_SIGNATURE_CHARS: usize = 88;
const ADDRESS_CONFIDENCE: f64 = 0.75;
/// The wallet an SPL token account records as its owner: the account's on-chain controller.
const OWNER_CONFIDENCE: f64 = 0.70;
/// A delegate, close, mint or freeze authority or a multisig signer an SPL account records.
const AUTHORITY_CONFIDENCE: f64 = 0.60;
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const STAKE_PROGRAM: &str = "Stake11111111111111111111111111111111111111";
const VOTE_PROGRAM: &str = "Vote111111111111111111111111111111111111111";
/// The incinerator: lamports sent to it are burned each block and nobody holds its key.
const INCINERATOR: &str = "1nc1nerator11111111111111111111111111111111";
/// Addresses that name no controller: the all-zero key and the incinerator. A token account
/// "owned" by either is unusable or burned, so neither is ever a pivot, which would otherwise link
/// every unrelated burn through one entity.
const NO_CONTROLLER: [&str; 2] = [SYSTEM_PROGRAM, INCINERATOR];

/// The owner programs evidence names, each an account or loader on mainnet-beta.
const KNOWN_OWNERS: [(&str, &str); 10] = [
    (SYSTEM_PROGRAM, "System Program"),
    (TOKEN_PROGRAM, "SPL Token"),
    (TOKEN_2022_PROGRAM, "SPL Token-2022"),
    (UPGRADEABLE_LOADER, "BPF Upgradeable Loader"),
    (
        "BPFLoader2111111111111111111111111111111111",
        "BPF Loader 2",
    ),
    (
        "BPFLoader1111111111111111111111111111111111",
        "BPF Loader (deprecated)",
    ),
    (
        "NativeLoader1111111111111111111111111111111",
        "Native Loader",
    ),
    (STAKE_PROGRAM, "Stake Program"),
    (VOTE_PROGRAM, "Vote Program"),
    (
        "Config1111111111111111111111111111111111111",
        "Config Program",
    ),
];

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

/// Decode one canonical fixed-width base58 value. Reject overflow, invalid characters and
/// leading-zero aliases, so a short string cannot masquerade as a transaction signature. **Pure.**
fn decode_base58<const N: usize>(text: &str, max_chars: usize) -> Option<[u8; N]> {
    if text.is_empty() || text.len() > max_chars {
        return None;
    }
    let mut bytes = [0_u8; N];
    for symbol in text.bytes() {
        let mut carry = u32::try_from(BASE58.iter().position(|&digit| digit == symbol)?).ok()?;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let ones = text.bytes().take_while(|&symbol| symbol == b'1').count();
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    (ones == zeros).then_some(bytes)
}

/// The 32 bytes a canonical base58 address spells, or `None` for an invalid spelling. **Pure.**
fn decode_address(text: &str) -> Option<[u8; 32]> {
    decode_base58::<32>(text, 44)
}

/// The canonical base58 spelling of a 32-byte address. **Pure.**
fn encode_address(bytes: &[u8; 32]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(44);
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry != 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    let mut text = "1".repeat(zeros);
    text.extend(
        digits
            .iter()
            .rev()
            .map(|&digit| char::from(BASE58[usize::from(digit)])),
    );
    text
}

/// The address a canonical `sol:` selector names. **Pure.**
fn address_of(selector: &str) -> Option<&str> {
    selector
        .strip_prefix(PREFIX)
        .filter(|address| decode_address(address).is_some())
}

/// Explicit Solana selector: `sol:` and the canonical base58 spelling of a 32-byte address, kept
/// exactly as written because base58 is case-significant. A bare address is shared by every SVM
/// chain and is never silently routed to Solana mainnet-beta.
#[must_use]
pub fn canonical_selector(raw: &str) -> Option<String> {
    address_of(raw).map(|address| format!("{PREFIX}{address}"))
}

/// Fixed, read-only mainnet-beta batch: the cluster identity, the account at finalized commitment
/// with a bounded data slice, its newest signatures and the first block the node holds.
#[must_use]
pub fn request(selector: &str) -> Option<Request> {
    let address = address_of(selector)?;
    let payload = json!([
        {"jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]},
        {"jsonrpc":"2.0","id":2,"method":"getAccountInfo","params":[address,{
            "commitment":"finalized","encoding":"base64",
            "dataSlice":{"offset":0,"length":DATA_SLICE}
        }]},
        {"jsonrpc":"2.0","id":3,"method":"getSignaturesForAddress","params":[address,{
            "commitment":"finalized","limit":SIGNATURE_LIMIT
        }]},
        {"jsonrpc":"2.0","id":4,"method":"getFirstAvailableBlock","params":[]}
    ]);
    Some(
        Request::post(RPC_URL, payload.to_string().into_bytes())
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("user-agent", crate::http::DEFAULT_USER_AGENT),
    )
}

/// One reply of the batch: its result, or `None` where a JSON-RPC error stood in for it.
type Reply<'a> = Option<&'a Value>;

/// The four replies in request order, once the batch is complete, of one protocol, and carries
/// each identifier exactly once. A reply with both or neither of a result and an error is drift.
fn parse_batch(records: &[Value]) -> Result<[Reply<'_>; 4], String> {
    if records.len() != 4 {
        return Err(format!("{DISPLAY} returned a partial or unexpected batch"));
    }
    let mut replies: [Option<Reply<'_>>; 4] = [None; 4];
    for row in records {
        if row.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(format!("{DISPLAY} response protocol mismatch"));
        }
        let index = row
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| id.checked_sub(1))
            .and_then(|id| usize::try_from(id).ok())
            .filter(|index| *index < 4)
            .ok_or_else(|| format!("{DISPLAY} response identifier mismatch"))?;
        let reply = match (row.get("result"), row.get("error")) {
            (Some(result), None) => Some(result),
            (None, Some(_)) => None,
            _ => {
                return Err(format!(
                    "{DISPLAY} returned a reply with both or neither of a result and an error"
                ));
            }
        };
        if replies[index].replace(reply).is_some() {
            return Err(format!("{DISPLAY} duplicated a response identifier"));
        }
    }
    let [
        Some(genesis),
        Some(account),
        Some(signatures),
        Some(first_block),
    ] = replies
    else {
        return Err(format!("{DISPLAY} omitted a requested method"));
    };
    Ok([genesis, account, signatures, first_block])
}

/// An account as the finalized bank holds it, with at most [`DATA_SLICE`] bytes of its data.
struct Account {
    lamports: u64,
    owner: String,
    executable: bool,
    space: u64,
    rent_epoch: Option<u64>,
    data: Vec<u8>,
}

/// The finalized slot the account was read at, and the account there: `None` when no account
/// exists at the address. A data slice wider than asked for, or narrower than the account, is
/// drift rather than a partial read.
fn parse_account(result: &Value) -> Result<(u64, Option<Account>), String> {
    let slot = result
        .pointer("/context/slot")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{DISPLAY} omitted the slot it read the account at"))?;
    let value = result
        .get("value")
        .ok_or_else(|| format!("{DISPLAY} omitted the account value"))?;
    if value.is_null() {
        return Ok((slot, None));
    }
    let malformed = |field: &str| format!("{DISPLAY} returned a malformed account {field}");
    let lamports = value
        .get("lamports")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("balance"))?;
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .filter(|owner| decode_address(owner).is_some())
        .ok_or_else(|| malformed("owner"))?;
    let executable = value
        .get("executable")
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed("executable flag"))?;
    let space = value
        .get("space")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("data size"))?;
    let data = match value
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([Value::String(encoded), Value::String(encoding)]) if encoding == "base64" => {
            crate::base64::decode_standard(encoded)
        }
        _ => None,
    }
    .filter(|data| u64::try_from(data.len()).ok() == Some(space.min(DATA_SLICE)))
    .ok_or_else(|| malformed("data slice"))?;
    Ok((
        slot,
        Some(Account {
            lamports,
            owner: owner.to_owned(),
            executable,
            space,
            rent_epoch: value.get("rentEpoch").and_then(Value::as_u64),
            data,
        }),
    ))
}

/// `lamports` as an exact SOL amount with all nine decimals; never a float. **Pure.**
fn sol(lamports: u64) -> String {
    format!(
        "{}.{:09}",
        lamports / LAMPORTS_PER_SOL,
        lamports % LAMPORTS_PER_SOL
    )
}

/// The address at `offset` in an account's data. **Pure.**
fn pubkey_at(data: &[u8], offset: usize) -> Option<String> {
    let bytes: [u8; 32] = data.get(offset..offset.checked_add(32)?)?.try_into().ok()?;
    Some(encode_address(&bytes))
}

/// The little-endian `u64` at `offset` in an account's data. **Pure.**
fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Bytes that are not the SPL layout being decoded.
struct NotLayout;

/// Whether the SPL `COption` at `offset` holds a value: a four-byte tag, 0 for none and 1 for
/// some. Any other tag is not the layout, so `None`. **Pure.**
fn option_tag(data: &[u8], offset: usize) -> Option<bool> {
    match data.get(offset..offset.checked_add(4)?)? {
        [0, 0, 0, 0] => Some(false),
        [1, 0, 0, 0] => Some(true),
        _ => None,
    }
}

/// The address an SPL `COption<Pubkey>` at `offset` holds, if any. **Pure.**
fn optional_pubkey(data: &[u8], offset: usize) -> Result<Option<String>, NotLayout> {
    match option_tag(data, offset) {
        Some(false) => Ok(None),
        Some(true) => pubkey_at(data, offset + 4).map(Some).ok_or(NotLayout),
        None => Err(NotLayout),
    }
}

/// An initialized SPL token account's base layout, which Token and Token-2022 share.
struct TokenAccount {
    mint: String,
    owner: String,
    amount: u64,
    delegate: Option<String>,
    frozen: bool,
    /// The rent-exempt reserve of a wrapped-SOL account, `None` for any other token.
    native_reserve: Option<u64>,
    delegated_amount: u64,
    close_authority: Option<String>,
}

/// An initialized SPL mint's base layout, which Token and Token-2022 share.
struct TokenMint {
    mint_authority: Option<String>,
    supply: u64,
    decimals: u8,
    freeze_authority: Option<String>,
}

/// An initialized SPL multisig, which Token and Token-2022 share: `required` of its `signers`
/// must sign.
struct TokenMultisig {
    required: u8,
    signers: Vec<String>,
}

/// What an SPL program's account is, decoded only where both programs define the layout.
enum TokenState {
    Account(TokenAccount),
    Mint(TokenMint),
    Multisig(TokenMultisig),
}

/// The token account at the start of `data`, or `None` when it is not initialized or not the
/// layout. **Pure.**
fn token_account(data: &[u8]) -> Option<TokenAccount> {
    let frozen = match data.get(108)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    Some(TokenAccount {
        mint: pubkey_at(data, 0)?,
        owner: pubkey_at(data, 32)?,
        amount: u64_at(data, 64)?,
        delegate: optional_pubkey(data, 72).ok()?,
        frozen,
        native_reserve: if option_tag(data, 109)? {
            Some(u64_at(data, 113)?)
        } else {
            None
        },
        delegated_amount: u64_at(data, 121)?,
        close_authority: optional_pubkey(data, 129).ok()?,
    })
}

/// The mint at the start of `data`, or `None` when it is not initialized or not the layout.
/// **Pure.**
fn token_mint(data: &[u8]) -> Option<TokenMint> {
    if *data.get(45)? != 1 {
        return None;
    }
    Some(TokenMint {
        mint_authority: optional_pubkey(data, 0).ok()?,
        supply: u64_at(data, 36)?,
        decimals: *data.get(44)?,
        freeze_authority: optional_pubkey(data, 46).ok()?,
    })
}

/// The multisig at the start of `data`: `m` required and `n` valid signers (each 1 to 11), an
/// initialized flag, then eleven signer slots of which the first `n` are live. `None` when it is
/// not initialized or not the layout. **Pure.**
fn token_multisig(data: &[u8]) -> Option<TokenMultisig> {
    let (&required, &count, &initialized) = (data.first()?, data.get(1)?, data.get(2)?);
    let signers = 1..=MAX_MULTISIG_SIGNERS;
    if initialized != 1 || !signers.contains(&required) || !signers.contains(&count) {
        return None;
    }
    let signers = (0..usize::from(count))
        .map(|slot| pubkey_at(data, 3 + 32 * slot))
        .collect::<Option<Vec<_>>>()?;
    Some(TokenMultisig { required, signers })
}

/// What `account` is to the SPL Token or Token-2022 program that owns it, by its size: a token
/// account is 165 bytes and a mint 82 in both programs, a multisig 355; a longer Token-2022
/// account carries extensions after a type byte at offset 165 (1 a mint, 2 a token account).
/// `None` for any other owner or an unrecognised layout. **Pure.**
fn token_state(account: &Account) -> Option<TokenState> {
    let extensible = match account.owner.as_str() {
        TOKEN_PROGRAM => false,
        TOKEN_2022_PROGRAM => true,
        _ => return None,
    };
    let data = account.data.as_slice();
    match account.space {
        165 => token_account(data).map(TokenState::Account),
        82 => token_mint(data).map(TokenState::Mint),
        355 => token_multisig(data).map(TokenState::Multisig),
        space if extensible && space > 165 => match data.get(165)? {
            1 => token_mint(data).map(TokenState::Mint),
            2 => token_account(data).map(TokenState::Account),
            _ => None,
        },
        _ => None,
    }
}

/// The account's class, from its executable flag, its decoded SPL state and its owner program.
/// **Pure.**
fn account_class(account: &Account, token: Option<&TokenState>) -> &'static str {
    if account.executable {
        return "program";
    }
    match token {
        Some(TokenState::Account(_)) => return "token_account",
        Some(TokenState::Mint(_)) => return "token_mint",
        Some(TokenState::Multisig(_)) => return "token_multisig",
        None => {}
    }
    match account.owner.as_str() {
        SYSTEM_PROGRAM if account.space == 0 => "native_sol_account",
        SYSTEM_PROGRAM => "system_owned_data_account",
        TOKEN_PROGRAM | TOKEN_2022_PROGRAM => "token_program_account",
        STAKE_PROGRAM => "stake_account",
        VOTE_PROGRAM => "vote_account",
        UPGRADEABLE_LOADER => "program_data_or_buffer",
        _ => "program_owned_account",
    }
}

/// The program-data account an upgradeable program's header names. **Pure.**
fn program_data(account: &Account) -> Option<String> {
    if !account.executable
        || account.owner != UPGRADEABLE_LOADER
        || account.data.get(..4) != Some(&[2, 0, 0, 0][..])
    {
        return None;
    }
    pubkey_at(&account.data, 4)
}

/// The name of a well-known owner program. **Pure.**
fn owner_name(owner: &str) -> Option<&'static str> {
    KNOWN_OWNERS
        .iter()
        .find(|(program, _)| *program == owner)
        .map(|(_, name)| *name)
}

/// One transaction listed for the address: any finalized transaction that names it, whoever
/// signed it. `id` is its base58 signature and `err` the RPC's failure verbatim.
struct Signature<'a> {
    id: &'a str,
    slot: u64,
    block_time: Option<i64>,
    err: Option<&'a Value>,
    memo: Option<&'a str>,
}

/// The newest transactions naming the address that the node holds, how many listed ones could not
/// be read, and the first slot the node holds, which bounds the list.
struct History<'a> {
    signatures: Vec<Signature<'a>>,
    unreadable: usize,
    first_available_slot: Option<u64>,
}

/// The recent history, or the outcome kind and reason it was not read: a JSON-RPC error is a
/// non-answer, a reply that is not a list is drift. It is enrichment: its absence never fails the
/// account observation, and an empty list never claims the address was unused.
fn parse_history<'a>(
    signatures: Reply<'a>,
    first_block: Reply<'a>,
) -> Result<History<'a>, (SourceOutcomeKind, &'static str)> {
    let rows = signatures
        .ok_or((
            SourceOutcomeKind::Inconclusive,
            "returned a JSON-RPC error for the transactions naming the address",
        ))?
        .as_array()
        .ok_or((
            SourceOutcomeKind::SchemaDrift,
            "returned a malformed transaction list",
        ))?;
    let mut history = History {
        signatures: Vec::new(),
        unreadable: 0,
        first_available_slot: first_block.and_then(Value::as_u64),
    };
    for row in rows.iter().take(SIGNATURE_LIMIT) {
        match parse_signature(row) {
            Some(signature) => history.signatures.push(signature),
            None => history.unreadable += 1,
        }
    }
    Ok(history)
}

/// One listed transaction, or `None` when a field is missing or malformed: every row carries its
/// signature, slot, block time (null when unknown), error (null on success) and memo (null when
/// none). **Pure.**
fn parse_signature(row: &Value) -> Option<Signature<'_>> {
    let id = row
        .get("signature")?
        .as_str()
        .filter(|text| decode_base58::<64>(text, MAX_SIGNATURE_CHARS).is_some())?;
    let block_time = match row.get("blockTime")? {
        Value::Null => None,
        time => Some(time.as_i64()?),
    };
    let err = match row.get("err")? {
        Value::Null => None,
        err => Some(err),
    };
    let memo = match row.get("memo")? {
        Value::Null => None,
        memo => Some(memo.as_str()?),
    };
    Some(Signature {
        id,
        slot: row.get("slot")?.as_u64()?,
        block_time,
        err,
        memo,
    })
}

/// `evidence` with the recent history: every listed transaction verbatim (signature, slot, block
/// time, error, memo) and its counts. A row that could not be read is counted, and then the newest
/// and oldest listed transaction are not claimed, since the unreadable one may be either; the
/// oldest time is claimed only when every listed transaction carries one. **Pure.**
fn with_history(mut evidence: Evidence, history: &History<'_>) -> Evidence {
    if let Some(slot) = history.first_available_slot {
        evidence = evidence.with_attr("history_first_available_slot", slot.to_string());
    }
    evidence = evidence
        .with_attr("recent_transaction_limit", SIGNATURE_LIMIT.to_string())
        .with_attr(
            "recent_transactions_listed",
            history.signatures.len().to_string(),
        );
    if history.unreadable != 0 {
        evidence = evidence.with_attr(
            "recent_transactions_unreadable",
            history.unreadable.to_string(),
        );
    }
    if history.signatures.is_empty() {
        return evidence;
    }
    let records: Vec<Value> = history
        .signatures
        .iter()
        .map(|signature| {
            json!({
                "signature": signature.id,
                "slot": signature.slot,
                "block_time_utc": signature.block_time.map(crate::timefmt::format_unix),
                "err": signature.err,
                "memo": signature.memo,
            })
        })
        .collect();
    let failed = history
        .signatures
        .iter()
        .filter(|s| s.err.is_some())
        .count();
    evidence = evidence
        .with_attr("recent_failed_transactions", failed.to_string())
        .with_attr("recent_transactions", Value::from(records).to_string());
    let latest = history.signatures.iter().reduce(|latest, next| {
        if next.slot > latest.slot {
            next
        } else {
            latest
        }
    });
    let (Some(latest), 0) = (latest, history.unreadable) else {
        return evidence;
    };
    evidence = evidence
        .with_attr("latest_listed_signature", latest.id)
        .with_attr("latest_listed_slot", latest.slot.to_string());
    if let Some(time) = latest.block_time {
        evidence = evidence.with_attr(
            "latest_listed_transaction_utc",
            crate::timefmt::format_unix(time),
        );
    }
    let times: Option<Vec<i64>> = history.signatures.iter().map(|s| s.block_time).collect();
    if let Some(earliest) = times.and_then(|times| times.into_iter().min()) {
        evidence = evidence.with_attr(
            "earliest_listed_transaction_utc",
            crate::timefmt::format_unix(earliest),
        );
    }
    evidence
}

/// `evidence` with an SPL token account's or mint's decoded fields. **Pure.**
fn with_token(evidence: Evidence, account: &Account, token: &TokenState) -> Evidence {
    let program = if account.owner == TOKEN_2022_PROGRAM {
        "spl_token_2022"
    } else {
        "spl_token"
    };
    let evidence = evidence.with_attr("token_program", program);
    match token {
        TokenState::Account(held) => {
            let reserve = held.native_reserve.map(|lamports| lamports.to_string());
            evidence
                .with_attr("token_mint", &held.mint)
                .with_attr("token_account_owner", &held.owner)
                .with_attr("token_amount_raw", held.amount.to_string())
                .with_attr(
                    "token_account_state",
                    if held.frozen { "frozen" } else { "initialized" },
                )
                .with_attr(
                    "token_native_sol",
                    held.native_reserve.is_some().to_string(),
                )
                .with_optional_attrs([("token_native_reserve_lamports", reserve.as_deref())])
                .with_attr("token_delegate", held.delegate.as_deref().unwrap_or("none"))
                .with_attr(
                    "token_delegated_amount_raw",
                    held.delegated_amount.to_string(),
                )
                .with_attr(
                    "token_close_authority",
                    held.close_authority.as_deref().unwrap_or("none"),
                )
        }
        TokenState::Mint(mint) => evidence
            .with_attr(
                "token_mint_authority",
                mint.mint_authority.as_deref().unwrap_or("none"),
            )
            .with_attr(
                "token_freeze_authority",
                mint.freeze_authority.as_deref().unwrap_or("none"),
            )
            .with_attr("token_supply_raw", mint.supply.to_string())
            .with_attr("token_decimals", mint.decimals.to_string()),
        TokenState::Multisig(multisig) => evidence
            .with_attr("token_multisig_required", multisig.required.to_string())
            .with_attr(
                "token_multisig_signer_count",
                multisig.signers.len().to_string(),
            )
            .with_attr(
                "token_multisig_signers",
                Value::from(multisig.signers.clone()).to_string(),
            ),
    }
}

/// One address an SPL account records in a controlling `role`, as its own `sol:` pivot.
struct Pivot<'a> {
    address: &'a str,
    role: &'static str,
    tag: &'static str,
    confidence: f64,
}

/// `address` in a controlling `role`, when the account records one. **Pure.**
fn pivot<'a>(
    address: Option<&'a str>,
    role: &'static str,
    tag: &'static str,
    confidence: f64,
) -> Option<Pivot<'a>> {
    Some(Pivot {
        address: address?,
        role,
        tag,
        confidence,
    })
}

/// The controlling addresses `token` records: a token account's owner, delegate and close
/// authority, a mint's mint and freeze authorities, a multisig's live signers. **Pure.**
fn pivots(token: &TokenState) -> Vec<Pivot<'_>> {
    match token {
        TokenState::Account(held) => [
            pivot(
                Some(held.owner.as_str()),
                "token_account_owner",
                "solana-token-account-owner",
                OWNER_CONFIDENCE,
            ),
            pivot(
                held.delegate.as_deref(),
                "token_delegate",
                "solana-token-delegate",
                AUTHORITY_CONFIDENCE,
            ),
            pivot(
                held.close_authority.as_deref(),
                "token_close_authority",
                "solana-token-close-authority",
                AUTHORITY_CONFIDENCE,
            ),
        ]
        .into_iter()
        .flatten()
        .collect(),
        TokenState::Mint(mint) => [
            pivot(
                mint.mint_authority.as_deref(),
                "token_mint_authority",
                "solana-mint-authority",
                AUTHORITY_CONFIDENCE,
            ),
            pivot(
                mint.freeze_authority.as_deref(),
                "token_freeze_authority",
                "solana-freeze-authority",
                AUTHORITY_CONFIDENCE,
            ),
        ]
        .into_iter()
        .flatten()
        .collect(),
        TokenState::Multisig(multisig) => multisig
            .signers
            .iter()
            .filter_map(|signer| {
                pivot(
                    Some(signer.as_str()),
                    "token_multisig_signer",
                    "solana-multisig-signer",
                    AUTHORITY_CONFIDENCE,
                )
            })
            .collect(),
    }
}

/// Add `pivot`, recorded by the account at `address`, as a `sol:` address of its own. An address
/// that names no controller ([`NO_CONTROLLER`]) is skipped; it stays in the evidence verbatim.
fn push_pivot(
    entities: &mut Vec<Entity>,
    pivot: &Pivot<'_>,
    address: &str,
    slot: u64,
    scan_id: &str,
) {
    if NO_CONTROLLER.contains(&pivot.address) {
        return;
    }
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "{} recorded by Solana account {PREFIX}{address} at finalized slot {slot}; an on-chain control relation, not an identity",
            pivot.role
        ),
    )
    .with_attr("network", NETWORK)
    .with_attr("role", pivot.role)
    .with_attr("recorded_by", format!("{PREFIX}{address}"))
    .with_attr("slot", slot.to_string())
    .with_attr("commitment", "finalized")
    .with_attr("rpc_origin", RPC_URL)
    .with_attr("source_url", RPC_URL)
    .with_attr("explorer_url", format!("{EXPLORER_PREFIX}{}", pivot.address))
    .with_attr(
        "does_not_show",
        "who controls this address, an identity, or any relation beyond the recorded role",
    );
    let tags = [TAGS, &[pivot.tag]].concat();
    push_entity(
        entities,
        EntityKind::CryptoAddress,
        &format!("{PREFIX}{}", pivot.address),
        pivot.confidence,
        scan_id,
        evidence,
        &tags,
    );
}

/// The queried address's evidence: the account at `slot` when one exists, its decoded SPL state,
/// and the recent history when it was read. **Pure.**
fn address_evidence(
    address: &str,
    slot: u64,
    account: Option<&Account>,
    token: Option<&TokenState>,
    history: Option<&History<'_>>,
    scan_id: &str,
) -> Evidence {
    let summary = match account {
        Some(account) => format!(
            "Solana mainnet-beta {} holding {} SOL at finalized slot {slot} (read-only JSON-RPC)",
            account_class(account, token),
            sol(account.lamports)
        ),
        None => format!(
            "Solana mainnet-beta address with no account at finalized slot {slot}, but named by recent transactions (read-only JSON-RPC)"
        ),
    };
    let evidence = Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
        .with_attr("network", NETWORK)
        .with_attr("genesis_hash", MAINNET_GENESIS_HASH)
        .with_attr("commitment", "finalized")
        .with_attr("slot", slot.to_string())
        .with_attr("rpc_origin", RPC_URL)
        .with_attr("source_url", RPC_URL)
        .with_attr("explorer_url", format!("{EXPLORER_PREFIX}{address}"))
        .with_attr(
            "does_not_show",
            "address ownership, identity, who signed, paid for or wrote the memo of any listed transaction (a listed transaction is any finalized one that names the address, whoever signed it), transaction history before the node's first available slot, token accounts the address owns, or one atomic snapshot across the batch",
        );
    let evidence = match account {
        Some(account) => {
            let rent_epoch = account.rent_epoch.map(|epoch| epoch.to_string());
            let program_data = program_data(account);
            let evidence = evidence
                .with_attr("account_state", "exists")
                .with_attr("account_class", account_class(account, token))
                .with_attr("balance_lamports", account.lamports.to_string())
                .with_attr("balance_sol", sol(account.lamports))
                .with_attr("owner_program", &account.owner)
                .with_attr("executable", account.executable.to_string())
                .with_attr("data_size", account.space.to_string())
                .with_optional_attrs([
                    ("owner_program_name", owner_name(&account.owner)),
                    ("rent_epoch", rent_epoch.as_deref()),
                    ("program_data_address", program_data.as_deref()),
                ]);
            match token {
                Some(token) => with_token(evidence, account, token),
                None => evidence,
            }
        }
        None => evidence.with_attr("account_state", "no_account"),
    };
    match history {
        Some(history) => with_history(evidence, history),
        None => evidence,
    }
}

/// The observation a complete, decoded batch supports, or the outcome kind and reason that
/// refuse it. Unknown identifiers, duplicates, another cluster, a malformed account or a JSON-RPC
/// error on the cluster identity or the account never create evidence; an unreadable signature
/// list only drops the recent history, and says so in the outcome.
fn observe(
    records: &[Value],
    selector: &str,
    scan_id: &str,
    now: u64,
    status: u16,
) -> Result<Report, (SourceOutcomeKind, String)> {
    use SourceOutcomeKind::{Inconclusive, SchemaDrift};
    let address = address_of(selector)
        .ok_or_else(|| (SchemaDrift, format!("{DISPLAY} selector was not canonical")))?;
    let [genesis, account, signatures, first_block] =
        parse_batch(records).map_err(|detail| (SchemaDrift, detail))?;
    let (Some(genesis), Some(account)) = (genesis, account) else {
        return Err((
            Inconclusive,
            format!("{DISPLAY} returned a JSON-RPC error; no account observation admitted"),
        ));
    };
    if genesis.as_str() != Some(MAINNET_GENESIS_HASH) {
        return Err((
            SchemaDrift,
            format!("{DISPLAY} replied for a cluster other than Solana mainnet-beta"),
        ));
    }
    let (slot, account) = parse_account(account).map_err(|detail| (SchemaDrift, detail))?;
    let history = parse_history(signatures, first_block);
    // With no account, only a history read in full and empty proves the address unused within the
    // node's ledger: a drained wallet is deleted at zero lamports, so an unread or unreadable
    // history must never become a clean zero.
    if account.is_none() {
        match &history {
            Err((kind, why)) => {
                return Err((
                    *kind,
                    format!(
                        "{DISPLAY} {why} and holds no account at finalized slot {slot}, so an unused address is unproven"
                    ),
                ));
            }
            Ok(history) if history.signatures.is_empty() && history.unreadable != 0 => {
                return Err((
                    SchemaDrift,
                    format!(
                        "{DISPLAY} listed only malformed transactions and holds no account at finalized slot {slot}"
                    ),
                ));
            }
            Ok(history) if history.signatures.is_empty() => {
                let ledger = history.first_available_slot.map_or_else(
                    || " the node holds (it did not report its first slot)".to_owned(),
                    |first| format!(" since slot {first}, the first the node holds"),
                );
                return Ok(Report {
                    entities: Vec::new(),
                    outcome: SourceExecutionOutcome::valid_zero(SOURCE, now)
                        .with_http_status(status)
                        .with_detail(format!(
                            "no account at finalized slot {slot} and no transaction naming the address{ledger}; older history is not retained by this node, and token accounts the address may own are not searched"
                        )),
                });
            }
            Ok(_) => {}
        }
    }
    let detail = match &history {
        Ok(history) if history.unreadable != 0 => Some(format!(
            "{} listed transaction(s) were malformed and not read",
            history.unreadable
        )),
        Ok(_) => None,
        Err((_, why)) => Some(format!("{DISPLAY} {why}; recent transactions not read")),
    };
    let history = history.ok();

    let mut entities = Vec::new();
    let mut outcome = {
        let token = account.as_ref().and_then(token_state);
        let evidence = address_evidence(
            address,
            slot,
            account.as_ref(),
            token.as_ref(),
            history.as_ref(),
            scan_id,
        );
        push_entity(
            &mut entities,
            EntityKind::CryptoAddress,
            &format!("{PREFIX}{address}"),
            ADDRESS_CONFIDENCE,
            scan_id,
            evidence,
            TAGS,
        );
        if let Some(token) = &token {
            for pivot in pivots(token) {
                push_pivot(&mut entities, &pivot, address, slot, scan_id);
            }
        }
        merge_by_uid(&mut entities);
        SourceExecutionOutcome::success(SOURCE, now, entities.len())
    }
    .with_http_status(status);
    if let Some(detail) = detail {
        outcome = outcome.with_detail(detail);
    }
    Ok(Report { entities, outcome })
}

/// Decode one public JSON-RPC answer: a transport failure, a non-answer status or a body that is
/// not JSON keeps the boundary's own outcome; anything else is judged by [`observe`].
fn interpret(fetched: &Fetched, selector: &str, scan_id: &str, now: u64) -> Report {
    let refused = |outcome| Report {
        entities: Vec::new(),
        outcome,
    };
    let response = match whole_response(fetched, DISPLAY) {
        Ok(response) => response,
        Err(outcome) => return refused(outcome),
    };
    if let Err(outcome) = answer(fetched, DISPLAY) {
        return refused(outcome);
    }
    let records: Vec<Value> = match decode_json(response, SOURCE, now, DISPLAY) {
        Ok(rows) => rows,
        Err(outcome) => return refused(outcome),
    };
    observe(&records, selector, scan_id, now, response.status).unwrap_or_else(|(kind, detail)| {
        refused(SourceExecutionOutcome::failed(
            SOURCE,
            now,
            kind,
            Some(response.status),
            &detail,
        ))
    })
}

/// Read a Solana mainnet-beta account without indexing services, authentication or transfers.
/// Every method is read-only, and any upstream error remains explicit.
///
/// # Errors
/// Returns guarded network-boundary errors without converting them into a negative account finding.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    selector: &str,
    scan_id: &str,
    now: u64,
) -> Result<Report, Error> {
    let Some(request) = request(selector) else {
        return Err(Error::invalid_value(
            "expected sol: followed by a base58 Solana address of 32 bytes",
        ));
    };
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now,
    )?;
    Ok(interpret(&fetched, selector, scan_id, now))
}

#[cfg(test)]
mod tests;
