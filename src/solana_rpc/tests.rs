use super::*;
use crate::test_support::OneResponse;

// Synthetic addresses ([0x11; 32], [0x22; 32], ...) and their base58 spellings, computed by an
// independent encoder, so no test fixture names a real person's wallet.
const WALLET: &str = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const OWNER: &str = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
const DELEGATE: &str = "4Ss5JMkXAD9Z7cktFEdrqeMuT6jGMF1pVozTyPHZ6zT4";
const CLOSE_AUTHORITY: &str = "5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5";
const TOKEN_ACCOUNT: &str = "93MB2qRDNVLxbmmPuYpLdAqn3u2x9ZhaVZK5wELHueP8";
const TOKEN_2022_ACCOUNT: &str = "AByCTxLPRZPoyK22KdMxa3xkCbcNbeNWzVeEvh6UcJs9";
const SIGNATURE_NEW: &str =
    "2hxGyn4y9Mjkii76BqmxVoNYbTs3tw97bmtZRXnDoZPAw7VZTWhhk1aV11DtFgYGVibPaty4PQLHVLaKrT24NxGU";
const SIGNATURE_OLD: &str =
    "33k8aLHMyRtJfT8Jpovwzm3euxSG5KZwKXffudwGN54QX8nsYpF3VQtnCc4ruRFKbTiGW5MsTtCYPQVPd92Gewim";

// Public mainnet-beta accounts, verbatim from the RPC: the USDC (SPL Token) and PYUSD
// (Token-2022, with extensions) mints and the SPL Token program itself.
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const PYUSD_MINT: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
const USDC_MINT_ACCOUNT: &str = r#"{"data":["AQAAAJj+huiNm+Lqi8HMpIeLKYjCQPUrhCS/tA7Rot3LXhmbfJMV0DyEGwAGAQEAAABicKqKWcWUBbRShshncubNEm6bil06OFNtN/e0FOi2Zw==","base64"],"executable":false,"lamports":557389803855,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":82}"#;
const PYUSD_MINT_ACCOUNT: &str = r#"{"data":["AQAAAJPkMU4Y+uEbsZMeeiiX9ljfNXCarVZ7fbwaCVSmePpUl6ecZk+EAgAGAQEAAAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAIAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwwAIAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwEAbAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKxeFMmHvarhTKmfwU4ZarTEpP88HzxIKtbmhVwZUjcArAAAAAAAAAABdAgAAAAAAAAAAAAAAAAAAAABdAgAAAAAAAAAAAAAAAAAAAAAEAEEAFw==","base64"],"executable":false,"lamports":2078412093,"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb","rentEpoch":18446744073709551615,"space":866}"#;
const TOKEN_PROGRAM_ACCOUNT: &str = r#"{"data":["AgAAACfxkLHTr5i4znFMROjK3/n4/EXLjl+sQgLv+BENl903","base64"],"executable":true,"lamports":230130698,"owner":"BPFLoaderUpgradeab1e11111111111111111111111","rentEpoch":18446744073709551615,"space":36}"#;

const WALLET_ACCOUNT: &str = r#"{"data":["","base64"],"executable":false,"lamports":39869364,"owner":"11111111111111111111111111111111","rentEpoch":18446744073709551615,"space":0}"#;
// An SPL Token account: mint USDC, owner OWNER, 1234567 base units, delegate DELEGATE approved
// for 500, frozen, no close authority.
const TOKEN_ACCOUNT_STATE: &str = r#"{"data":["xvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWEiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIofWEgAAAAAAAQAAADMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzAgAAAAAAAAAAAAAAAPQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":165}"#;
// A Token-2022 account with the ImmutableOwner extension (170 bytes: type byte 2 at offset 165,
// then the extension's empty TLV entry):
// mint PYUSD, owner OWNER, 4759614 base units, initialized, close authority CLOSE_AUTHORITY.
const TOKEN_2022_ACCOUNT_STATE: &str = r#"{"data":["F5JIO2yKKoe3Rx2BT5WR+TlchAqc49n01bp9OkuKdJ4iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIj6gSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAEREREREREREREREREREREREREREREREREREREREREREAgcAAAA=","base64"],"executable":false,"lamports":2074080,"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb","rentEpoch":18446744073709551615,"space":170}"#;
// An initialized SPL Token multisig ([0x99; 32]): 2 of the 3 signers OWNER, DELEGATE and
// CLOSE_AUTHORITY must sign; the other eight signer slots are empty.
const MULTISIG: &str = "BLbDu5FZUdSfLrGejhuaWw5iMJBo3j3TVRyPv9rfJyMA";
const MULTISIG_STATE: &str = r#"{"data":["AgMBIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0REREREREREREREREREREREREREREREREREREREREREAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","base64"],"executable":false,"lamports":3361680,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":355}"#;
// SPL Token accounts of the USDC mint: one whose delegate is OWNER's spelling with one letter's
// case changed (another key), one owned by the incinerator, and a wrapped-SOL account (mint
// So111…112) of OWNER holding 1 SOL with its 2039280-lamport rent-exempt reserve.
const VARIANT_DELEGATE_STATE: &str = r#"{"data":["xvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWEiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIofWEgAAAAAAAQAAACiJp0+4zSg59PSYINCDXR40Hp1LUiDTxYZ/JiIiIiIiAQAAAAAAAAAAAAAAAPQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":165}"#;
const INCINERATOR_OWNED_STATE: &str = r#"{"data":["xvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWEAM5ByjTQRYHm9yRG//wDb1E0uzcz3nKbhADjhAAAAAE0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":165}"#;
const WRAPPED_SOL_STATE: &str = r#"{"data":["BpuIV/6rgYT7aH9jRhjANdrEOdwa6ztVmKDwAAAAAAEiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIgDKmjsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEAAADwHR8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":18446744073709551615,"space":165}"#;
// The newest signature succeeded with a memo, the older one failed; listed newest first.
const SIGNATURES: &str = r#"[
    {"blockTime":1793329229,"confirmationStatus":"finalized","err":null,"memo":"[5] hello","signature":"2hxGyn4y9Mjkii76BqmxVoNYbTs3tw97bmtZRXnDoZPAw7VZTWhhk1aV11DtFgYGVibPaty4PQLHVLaKrT24NxGU","slot":463125553,"transactionIndex":351},
    {"blockTime":1793329000,"confirmationStatus":"finalized","err":{"InstructionError":[2,{"Custom":1}]},"memo":null,"signature":"33k8aLHMyRtJfT8Jpovwzm3euxSG5KZwKXffudwGN54QX8nsYpF3VQtnCc4ruRFKbTiGW5MsTtCYPQVPd92Gewim","slot":463125000,"transactionIndex":7}
]"#;

/// A complete batch, in an order unlike the request's, around `account` and `signatures`.
fn batch(account: &str, signatures: &str) -> String {
    format!(
        r#"[
        {{"jsonrpc":"2.0","id":4,"result":462544720}},
        {{"jsonrpc":"2.0","id":1,"result":"{MAINNET_GENESIS_HASH}"}},
        {{"jsonrpc":"2.0","id":3,"result":{signatures}}},
        {{"jsonrpc":"2.0","id":2,"result":{{"context":{{"apiVersion":"4.3.2","slot":463125419}},"value":{account}}}}}
    ]"#
    )
}

fn selector(address: &str) -> String {
    format!("{PREFIX}{address}")
}

fn observe(address: &str, body: &str) -> Report {
    lookup(&OneResponse::json(200, body), &selector(address), "scan", 1).expect("fake transport")
}

fn entity<'a>(report: &'a Report, address: &str) -> &'a Entity {
    let value = selector(address);
    report
        .entities
        .iter()
        .find(|entity| entity.raw_value == value)
        .unwrap_or_else(|| panic!("no entity for {value}"))
}

fn attr<'a>(entity: &'a Entity, key: &str) -> &'a str {
    entity.evidence[0].attributes.get(key).map_or_else(
        || panic!("no {key} on {}", entity.raw_value),
        String::as_str,
    )
}

#[test]
fn base58_round_trips_and_accepts_one_spelling_per_address() {
    assert_eq!(encode_address(&[0x11; 32]), WALLET);
    assert_eq!(decode_address(WALLET), Some([0x11; 32]));
    assert_eq!(
        encode_address(&[0xff; 32]),
        "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"
    );
    let mut leading_zeros = [0x42; 32];
    leading_zeros[..2].fill(0);
    let spelled = "11EH35iwPKLStGzN7teRVgpQoBZGNdqYo9XX3mWsh5T";
    assert_eq!(encode_address(&leading_zeros), spelled);
    assert_eq!(decode_address(spelled), Some(leading_zeros));
    assert_eq!(decode_address(SYSTEM_PROGRAM), Some([0; 32]));
    for (program, _) in KNOWN_OWNERS {
        let bytes = decode_address(program).expect(program);
        assert_eq!(encode_address(&bytes), program);
    }
    assert!(decode_address(MAINNET_GENESIS_HASH).is_some());
    for bad in [
        String::new(),
        "1".repeat(31),
        "1".repeat(33),
        // 44 characters, so the leading-`1` rule rejects it rather than the length guard.
        format!("1{TOKEN_PROGRAM}"),
        "z".repeat(44),
        "z".repeat(45),
        format!("{}0", &WALLET[..43]),
        format!("{}O", &WALLET[..43]),
        format!("{}I", &WALLET[..43]),
        format!("{}l", &WALLET[..43]),
    ] {
        assert!(decode_address(&bad).is_none(), "{bad}");
    }
}

#[test]
fn selector_is_explicit_and_kept_exactly_as_written() {
    let wallet = selector(USDC_MINT);
    assert_eq!(
        canonical_selector(&wallet).as_deref(),
        Some(wallet.as_str())
    );
    for bad in [
        USDC_MINT.to_owned(),
        format!("SOL:{USDC_MINT}"),
        format!("sol: {USDC_MINT}"),
        format!("sol:{USDC_MINT}\n"),
        "sol:0x1111111111111111111111111111111111111111".to_owned(),
        "eth:0x1111111111111111111111111111111111111111".to_owned(),
        "sol:".to_owned(),
    ] {
        assert!(canonical_selector(&bad).is_none(), "{bad}");
        assert!(request(&bad).is_none(), "{bad}");
    }
}

#[test]
fn request_is_one_bounded_read_only_batch() {
    let request = request(&selector(WALLET)).expect("valid selector");
    assert_eq!(request.url, RPC_URL);
    let body: Value = serde_json::from_slice(&request.body).expect("json body");
    let methods: Vec<&str> = body
        .as_array()
        .expect("batch")
        .iter()
        .map(|row| row["method"].as_str().expect("method"))
        .collect();
    assert_eq!(
        methods,
        [
            "getGenesisHash",
            "getAccountInfo",
            "getSignaturesForAddress",
            "getFirstAvailableBlock"
        ]
    );
    assert_eq!(body[1]["params"][0], WALLET);
    assert_eq!(body[1]["params"][1]["commitment"], "finalized");
    assert_eq!(body[1]["params"][1]["encoding"], "base64");
    assert_eq!(body[1]["params"][1]["dataSlice"]["offset"], 0);
    assert_eq!(body[1]["params"][1]["dataSlice"]["length"], 355);
    assert_eq!(body[2]["params"][1]["limit"], 10);
    assert_eq!(body[2]["params"][1]["commitment"], "finalized");
}

#[test]
fn sol_is_exact_to_the_lamport() {
    assert_eq!(sol(0), "0.000000000");
    assert_eq!(sol(1), "0.000000001");
    assert_eq!(sol(39_869_364), "0.039869364");
    assert_eq!(sol(1_000_000_000), "1.000000000");
    assert_eq!(sol(u64::MAX), "18446744073.709551615");
}

#[test]
fn wallet_balance_owner_and_recent_history_become_provenance_not_ownership() {
    let found = observe(WALLET, &batch(WALLET_ACCOUNT, SIGNATURES));
    assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(found.entities.len(), 1);
    let wallet = entity(&found, WALLET);
    assert_eq!(wallet.kind, EntityKind::CryptoAddress);
    assert!(wallet.tags.iter().any(|tag| tag == "ownership_unverified"));
    for (key, value) in [
        ("network", "solana_mainnet_beta"),
        ("genesis_hash", MAINNET_GENESIS_HASH),
        ("commitment", "finalized"),
        ("slot", "463125419"),
        ("account_state", "exists"),
        ("account_class", "native_sol_account"),
        ("balance_lamports", "39869364"),
        ("balance_sol", "0.039869364"),
        ("owner_program", SYSTEM_PROGRAM),
        ("owner_program_name", "System Program"),
        ("executable", "false"),
        ("data_size", "0"),
        ("rent_epoch", "18446744073709551615"),
        ("history_first_available_slot", "462544720"),
        ("recent_transaction_limit", "10"),
        ("recent_transactions_listed", "2"),
        ("recent_failed_transactions", "1"),
        ("latest_listed_signature", SIGNATURE_NEW),
        ("latest_listed_slot", "463125553"),
        ("latest_listed_transaction_utc", "2026-10-30T03:00:29Z"),
        ("earliest_listed_transaction_utc", "2026-10-30T02:56:40Z"),
        (
            "explorer_url",
            "https://explorer.solana.com/address/29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2",
        ),
        ("source_url", RPC_URL),
    ] {
        assert_eq!(attr(wallet, key), value, "{key}");
    }
    // Every listed transaction verbatim, its memo and error tied to its own signature.
    let records: Value = serde_json::from_str(attr(wallet, "recent_transactions")).unwrap();
    assert_eq!(
        records,
        json!([
            {"signature": SIGNATURE_NEW, "slot": 463_125_553, "block_time_utc": "2026-10-30T03:00:29Z",
             "err": null, "memo": "[5] hello"},
            {"signature": SIGNATURE_OLD, "slot": 463_125_000, "block_time_utc": "2026-10-30T02:56:40Z",
             "err": {"InstructionError": [2, {"Custom": 1}]}, "memo": null},
        ])
    );
    // A listed transaction names the address; it is not shown to be the address's own act.
    assert!(attr(wallet, "does_not_show").contains("whoever signed it"));
    assert!(attr(wallet, "does_not_show").contains("ownership"));
    assert!(attr(wallet, "does_not_show").contains("first available slot"));
    assert!(wallet.evidence[0].summary.contains("0.039869364 SOL"));
}

#[test]
fn a_token_account_names_its_controllers_but_not_its_shared_mint() {
    let found = observe(TOKEN_ACCOUNT, &batch(TOKEN_ACCOUNT_STATE, "[]"));
    assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
    let account = entity(&found, TOKEN_ACCOUNT);
    for (key, value) in [
        ("account_class", "token_account"),
        ("owner_program_name", "SPL Token"),
        ("token_program", "spl_token"),
        ("token_mint", USDC_MINT),
        ("token_account_owner", OWNER),
        ("token_amount_raw", "1234567"),
        ("token_account_state", "frozen"),
        ("token_native_sol", "false"),
        ("token_delegate", DELEGATE),
        ("token_delegated_amount_raw", "500"),
        ("token_close_authority", "none"),
        ("recent_transactions_listed", "0"),
    ] {
        assert_eq!(attr(account, key), value, "{key}");
    }
    assert!(
        !account.evidence[0]
            .attributes
            .contains_key("latest_listed_signature")
    );

    let owner = entity(&found, OWNER);
    assert!((owner.confidence - OWNER_CONFIDENCE).abs() < f64::EPSILON);
    assert_eq!(attr(owner, "role"), "token_account_owner");
    assert_eq!(attr(owner, "recorded_by"), selector(TOKEN_ACCOUNT));
    assert!(
        owner
            .tags
            .iter()
            .any(|tag| tag == "solana-token-account-owner")
    );
    assert!(attr(owner, "does_not_show").contains("identity"));
    let delegate = entity(&found, DELEGATE);
    assert_eq!(attr(delegate, "role"), "token_delegate");
    assert!((delegate.confidence - AUTHORITY_CONFIDENCE).abs() < f64::EPSILON);
    // The mint is shared by every holder of the token, so it stays an attribute, never a pivot
    // that would correlate unrelated holders.
    assert_eq!(found.entities.len(), 3);
    assert!(
        !found
            .entities
            .iter()
            .any(|entity| entity.raw_value.contains(USDC_MINT))
    );
}

#[test]
fn token_2022_layouts_are_told_apart_by_their_type_byte() {
    let held = observe(TOKEN_2022_ACCOUNT, &batch(TOKEN_2022_ACCOUNT_STATE, "[]"));
    let account = entity(&held, TOKEN_2022_ACCOUNT);
    for (key, value) in [
        ("account_class", "token_account"),
        ("token_program", "spl_token_2022"),
        ("token_mint", PYUSD_MINT),
        ("token_account_owner", OWNER),
        ("token_amount_raw", "4759614"),
        ("token_account_state", "initialized"),
        ("token_delegate", "none"),
        ("token_close_authority", CLOSE_AUTHORITY),
        ("data_size", "170"),
    ] {
        assert_eq!(attr(account, key), value, "{key}");
    }
    assert_eq!(
        attr(entity(&held, CLOSE_AUTHORITY), "role"),
        "token_close_authority"
    );
    assert_eq!(held.entities.len(), 3);

    let mint = observe(PYUSD_MINT, &batch(PYUSD_MINT_ACCOUNT, "[]"));
    let pyusd = entity(&mint, PYUSD_MINT);
    for (key, value) in [
        ("account_class", "token_mint"),
        ("token_program", "spl_token_2022"),
        (
            "token_mint_authority",
            "AxJkHRY3puoofyj7Pn512M1SGBgWroXMkEdNPQypkzbu",
        ),
        (
            "token_freeze_authority",
            "2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk",
        ),
        ("token_supply_raw", "708426512246679"),
        ("token_decimals", "6"),
        ("data_size", "866"),
    ] {
        assert_eq!(attr(pyusd, key), value, "{key}");
    }
    assert_eq!(
        attr(
            entity(&mint, "AxJkHRY3puoofyj7Pn512M1SGBgWroXMkEdNPQypkzbu"),
            "role"
        ),
        "token_mint_authority"
    );
    assert_eq!(mint.entities.len(), 3);
}

#[test]
fn a_mint_names_its_mint_and_freeze_authorities() {
    let found = observe(USDC_MINT, &batch(USDC_MINT_ACCOUNT, "[]"));
    let mint = entity(&found, USDC_MINT);
    for (key, value) in [
        ("account_class", "token_mint"),
        ("token_program", "spl_token"),
        (
            "token_mint_authority",
            "BJE5MMbqXjVwjAF7oxwPYXnTXDyspzZyt4vwenNw5ruG",
        ),
        (
            "token_freeze_authority",
            "7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar",
        ),
        ("token_supply_raw", "7745221095166844"),
        ("token_decimals", "6"),
        ("balance_sol", "557.389803855"),
    ] {
        assert_eq!(attr(mint, key), value, "{key}");
    }
    let freeze = entity(&found, "7dGbd2QZcCKcTndnHcTL8q7SMVXAkp688NTQYwrRCrar");
    assert_eq!(attr(freeze, "role"), "token_freeze_authority");
    assert!(
        freeze
            .tags
            .iter()
            .any(|tag| tag == "solana-freeze-authority")
    );
    assert_eq!(found.entities.len(), 3);
}

#[test]
fn an_upgradeable_program_names_its_program_data_without_pivots() {
    let program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let found = observe(program, &batch(TOKEN_PROGRAM_ACCOUNT, "[]"));
    assert_eq!(found.entities.len(), 1);
    let account = entity(&found, program);
    for (key, value) in [
        ("account_class", "program"),
        ("executable", "true"),
        ("owner_program_name", "BPF Upgradeable Loader"),
        (
            "program_data_address",
            "3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2",
        ),
    ] {
        assert_eq!(attr(account, key), value, "{key}");
    }
}

#[test]
fn no_account_and_no_recent_signature_is_a_clean_zero_bounded_by_the_ledger() {
    let found = observe(WALLET, &batch("null", "[]"));
    assert!(found.entities.is_empty());
    assert_eq!(found.outcome.kind, SourceOutcomeKind::ValidZero);
    let reason = found.outcome.reason();
    assert!(reason.contains("since slot 462544720"), "{reason}");
    assert!(
        reason.contains("token accounts the address may own are not searched"),
        "{reason}"
    );
    assert!(reason.contains("older history is not retained"), "{reason}");
}

#[test]
fn a_closed_account_with_recent_signatures_is_still_observed() {
    let found = observe(WALLET, &batch("null", SIGNATURES));
    assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
    let wallet = entity(&found, WALLET);
    assert_eq!(attr(wallet, "account_state"), "no_account");
    assert_eq!(attr(wallet, "recent_transactions_listed"), "2");
    assert!(
        !wallet.evidence[0]
            .attributes
            .contains_key("balance_lamports")
    );
}

#[test]
fn another_cluster_or_a_broken_batch_never_becomes_evidence() {
    let good = batch(WALLET_ACCOUNT, SIGNATURES);
    let account_row = format!(
        r#"{{"jsonrpc":"2.0","id":2,"result":{{"context":{{"apiVersion":"4.3.2","slot":463125419}},"value":{WALLET_ACCOUNT}}}}}"#
    );
    use SourceOutcomeKind::{Inconclusive, SchemaDrift};
    for (body, kind) in [
        // Devnet's genesis hash: another cluster's state is not mainnet-beta's.
        (
            good.replace(
                MAINNET_GENESIS_HASH,
                "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
            ),
            SchemaDrift,
        ),
        (good.replace(r#""id":4,"#, r#""id":2,"#), SchemaDrift),
        (good.replace(r#""id":4,"#, r#""id":5,"#), SchemaDrift),
        (
            good.replace(&format!(",\n        {account_row}"), ""),
            SchemaDrift,
        ),
        (
            good.replace(r#""jsonrpc":"2.0","id":1"#, r#""jsonrpc":"1.0","id":1"#),
            SchemaDrift,
        ),
        // A JSON-RPC error on the cluster identity or the account is a non-answer, not drift.
        (
            good.replace(
                &format!(r#""result":"{MAINNET_GENESIS_HASH}""#),
                r#""error":{"code":-32005,"message":"quota exceeded"}"#,
            ),
            Inconclusive,
        ),
        (
            good.replace(
                &account_row,
                r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32005,"message":"quota exceeded"}}"#,
            ),
            Inconclusive,
        ),
        (
            good.replace(
                &format!(r#""result":"{MAINNET_GENESIS_HASH}""#),
                &format!(
                    r#""result":"{MAINNET_GENESIS_HASH}","error":{{"message":"quota exceeded"}}"#
                ),
            ),
            SchemaDrift,
        ),
        (
            good.replace(r#""lamports":39869364"#, r#""lamports":"39869364""#),
            SchemaDrift,
        ),
        (
            good.replace(
                r#""owner":"11111111111111111111111111111111""#,
                r#""owner":"0x0""#,
            ),
            SchemaDrift,
        ),
        (good.replace(r#""space":0"#, r#""space":165"#), SchemaDrift),
        (
            good.replace(r#""data":["","base64"]"#, r#""data":["","base58"]"#),
            SchemaDrift,
        ),
        (
            good.replace(r#""slot":463125419"#, r#""slot":-1"#),
            SchemaDrift,
        ),
    ] {
        let found = observe(WALLET, &body);
        assert!(found.entities.is_empty(), "{body}");
        assert_eq!(found.outcome.kind, kind, "{body}");
        assert!(!found.outcome.reason().contains("quota exceeded"), "{body}");
    }
}

#[test]
fn an_unreadable_signature_list_keeps_the_account_and_says_so() {
    let errored = batch(WALLET_ACCOUNT, "[]").replace(
        r#"{"jsonrpc":"2.0","id":3,"result":[]}"#,
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Request blocked"}}"#,
    );
    let found = observe(WALLET, &errored);
    assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
    assert!(
        found
            .outcome
            .reason()
            .contains("recent transactions not read")
    );
    let wallet = entity(&found, WALLET);
    assert_eq!(attr(wallet, "balance_lamports"), "39869364");
    assert!(
        !wallet.evidence[0]
            .attributes
            .contains_key("recent_transactions_listed")
    );

    // One unreadable row: the readable one is kept and the gap counted, but neither the newest
    // nor the oldest listed activity is claimed, since the unreadable row may be either.
    let malformed = SIGNATURES.replace(r#""slot":463125000"#, r#""slot":"late""#);
    let found = observe(WALLET, &batch(WALLET_ACCOUNT, &malformed));
    assert!(
        found
            .outcome
            .reason()
            .contains("1 listed transaction(s) were malformed")
    );
    let wallet = entity(&found, WALLET);
    assert_eq!(attr(wallet, "recent_transactions_listed"), "1");
    assert_eq!(attr(wallet, "recent_transactions_unreadable"), "1");
    assert!(attr(wallet, "recent_transactions").contains(SIGNATURE_NEW));
    assert!(!attr(wallet, "recent_transactions").contains(SIGNATURE_OLD));
    for claimed in [
        "latest_listed_signature",
        "latest_listed_transaction_utc",
        "earliest_listed_transaction_utc",
    ] {
        assert!(
            !wallet.evidence[0].attributes.contains_key(claimed),
            "{claimed}"
        );
    }
    // Without an account the same partial history is still observed activity.
    let found = observe(WALLET, &batch("null", &malformed));
    assert_eq!(found.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(attr(entity(&found, WALLET), "account_state"), "no_account");
}

#[test]
fn with_no_account_an_unread_history_never_becomes_a_clean_zero() {
    // A drained wallet is deleted at zero lamports, so `value: null` alone does not show an
    // address unused: only a history read in full and empty does.
    let blocked = batch("null", "[]").replace(
        r#"{"jsonrpc":"2.0","id":3,"result":[]}"#,
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Request blocked"}}"#,
    );
    let found = observe(WALLET, &blocked);
    assert!(found.entities.is_empty());
    assert_eq!(found.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert!(!found.outcome.reason().contains("Request blocked"));
    let unreadable = SIGNATURES
        .replace(r#""slot":463125553"#, r#""slot":"463125553""#)
        .replace(r#""slot":463125000"#, r#""slot":"463125000""#);
    let found = observe(WALLET, &batch("null", &unreadable));
    assert!(found.entities.is_empty());
    assert_eq!(found.outcome.kind, SourceOutcomeKind::SchemaDrift);
    // A reply that is not a list is drift, never a retryable non-answer.
    let list = batch("null", r#"{"signatures":[]}"#);
    assert_eq!(
        observe(WALLET, &list).outcome.kind,
        SourceOutcomeKind::SchemaDrift
    );
}

#[test]
fn the_all_zero_key_names_no_controller() {
    // A delegate recorded as the all-zero key stays in the evidence verbatim but is no pivot.
    let zero_delegate = TOKEN_ACCOUNT_STATE.replace(
        "xvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWEiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIofWEgAAAAAAAQAAADMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzAgAAAAAAAAAAAAAAAPQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "xvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWEiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIofWEgAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAPQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    let found = observe(TOKEN_ACCOUNT, &batch(&zero_delegate, "[]"));
    assert_eq!(
        attr(entity(&found, TOKEN_ACCOUNT), "token_delegate"),
        SYSTEM_PROGRAM
    );
    assert_eq!(found.entities.len(), 2, "the account and its owner only");
    assert!(
        !found
            .entities
            .iter()
            .any(|entity| entity.raw_value == selector(SYSTEM_PROGRAM))
    );
}

#[test]
fn an_uninitialized_mint_is_not_decoded() {
    let blank = USDC_MINT_ACCOUNT.replace(
        "AQAAAJj+huiNm+Lqi8HMpIeLKYjCQPUrhCS/tA7Rot3LXhmbfJMV0DyEGwAGAQEAAABicKqKWcWUBbRShshncubNEm6bil06OFNtN/e0FOi2Zw==",
        "AQAAAJj+huiNm+Lqi8HMpIeLKYjCQPUrhCS/tA7Rot3LXhmbfJMV0DyEGwAGAAEAAABicKqKWcWUBbRShshncubNEm6bil06OFNtN/e0FOi2Zw==",
    );
    let found = observe(USDC_MINT, &batch(&blank, "[]"));
    assert_eq!(found.entities.len(), 1);
    let mint = entity(&found, USDC_MINT);
    assert_eq!(attr(mint, "account_class"), "token_program_account");
    assert!(
        !mint.evidence[0]
            .attributes
            .contains_key("token_mint_authority")
    );
}

#[test]
fn a_multisig_names_its_live_signers_once_initialized() {
    let found = observe(MULTISIG, &batch(MULTISIG_STATE, "[]"));
    let multisig = entity(&found, MULTISIG);
    for (key, value) in [
        ("account_class", "token_multisig"),
        ("token_program", "spl_token"),
        ("token_multisig_required", "2"),
        ("token_multisig_signer_count", "3"),
        ("data_size", "355"),
    ] {
        assert_eq!(attr(multisig, key), value, "{key}");
    }
    assert_eq!(
        attr(multisig, "token_multisig_signers"),
        format!(r#"["{OWNER}","{DELEGATE}","{CLOSE_AUTHORITY}"]"#)
    );
    // Only the three live signer slots become pivots; the eight empty ones do not.
    assert_eq!(found.entities.len(), 4);
    for signer in [OWNER, DELEGATE, CLOSE_AUTHORITY] {
        let signer = entity(&found, signer);
        assert_eq!(attr(signer, "role"), "token_multisig_signer");
        assert!(
            signer
                .tags
                .iter()
                .any(|tag| tag == "solana-multisig-signer")
        );
    }

    let blank = MULTISIG_STATE.replace(r#""AgMB"#, r#""AgMA"#);
    let found = observe(MULTISIG, &batch(&blank, "[]"));
    assert_eq!(found.entities.len(), 1);
    assert_eq!(
        attr(entity(&found, MULTISIG), "account_class"),
        "token_program_account"
    );
    // The bounds are checked on their own: neither a required count above eleven nor zero valid
    // signers would otherwise fail to decode, since the slots exist for both.
    let mut bounds = [0_u8; 355];
    bounds[..3].copy_from_slice(&[2, 3, 1]);
    assert!(token_multisig(&bounds).is_some());
    bounds[..3].copy_from_slice(&[12, 3, 1]);
    assert!(token_multisig(&bounds).is_none(), "at most eleven required");
    bounds[..3].copy_from_slice(&[0, 3, 1]);
    assert!(token_multisig(&bounds).is_none(), "at least one required");
    bounds[..3].copy_from_slice(&[1, 0, 1]);
    assert!(token_multisig(&bounds).is_none(), "at least one signer");
}

#[test]
fn unknown_or_uninitialized_token_layouts_mint_no_pivot() {
    let parsed = |state: &str| {
        let (_, account) = parse_account(
            &serde_json::from_str::<Value>(&format!(
                r#"{{"context":{{"slot":1}},"value":{state}}}"#
            ))
            .unwrap(),
        )
        .unwrap();
        account.unwrap()
    };
    // Token-2022's type byte 3 is neither a mint nor a token account.
    let extended = parsed(TOKEN_2022_ACCOUNT_STATE);
    let mut unknown = extended.data.clone();
    unknown[165] = 3;
    assert!(
        token_state(&Account {
            data: unknown,
            ..parsed(TOKEN_2022_ACCOUNT_STATE)
        })
        .is_none()
    );
    // An uninitialized token account records no owner.
    let mut blank = parsed(TOKEN_ACCOUNT_STATE);
    blank.data[108] = 0;
    assert!(token_state(&blank).is_none());
    // A delegate tag other than 0 or 1 is not the layout.
    let mut tagged = parsed(TOKEN_ACCOUNT_STATE);
    tagged.data[72] = 2;
    assert!(token_state(&tagged).is_none());
    // The legacy program has no extensions, so a 170-byte account is not one of its layouts.
    let mut legacy = parsed(TOKEN_2022_ACCOUNT_STATE);
    legacy.owner = TOKEN_PROGRAM.to_owned();
    assert!(token_state(&legacy).is_none());
    // Another program's 165-byte account is never read as a token account.
    let mut foreign = parsed(TOKEN_ACCOUNT_STATE);
    foreign.owner = VOTE_PROGRAM.to_owned();
    assert!(token_state(&foreign).is_none());
    assert_eq!(account_class(&foreign, None), "vote_account");
}

#[test]
fn rate_limit_and_non_json_cannot_be_valid_zero() {
    let fixture = |status, body| {
        let fetched = fetch(
            &OneResponse::json(status, body),
            request(&selector(WALLET)).expect("valid selector"),
            None,
            &FetchOptions::no_redirects(),
            SOURCE,
            1,
        )
        .expect("fake transport fetch");
        interpret(&fetched, &selector(WALLET), "scan", 1)
    };
    let limited = fixture(429, "rate limited");
    assert!(limited.entities.is_empty());
    assert_eq!(limited.outcome.kind, SourceOutcomeKind::RateLimited);
    let malformed = fixture(200, "{bad");
    assert!(malformed.entities.is_empty());
    assert_eq!(malformed.outcome.kind, SourceOutcomeKind::ParserDrift);
}

#[test]
fn addresses_that_differ_only_in_case_stay_two_pivots() {
    // Base58 has no checksum, so a delegate spelled as the owner with one letter's case changed
    // is another key: it must stay its own entity, never fold into the owner.
    const VARIANT: &str = "3jF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
    assert_ne!(decode_address(VARIANT), decode_address(OWNER));
    let found = observe(TOKEN_ACCOUNT, &batch(VARIANT_DELEGATE_STATE, "[]"));
    assert_eq!(found.entities.len(), 3);
    assert_eq!(attr(entity(&found, OWNER), "role"), "token_account_owner");
    assert_eq!(attr(entity(&found, VARIANT), "role"), "token_delegate");
    assert_ne!(entity(&found, OWNER).uid, entity(&found, VARIANT).uid);
}

#[test]
fn a_token_account_burned_to_the_incinerator_names_no_controller() {
    let found = observe(TOKEN_ACCOUNT, &batch(INCINERATOR_OWNED_STATE, "[]"));
    assert_eq!(
        attr(entity(&found, TOKEN_ACCOUNT), "token_account_owner"),
        INCINERATOR
    );
    assert_eq!(found.entities.len(), 1, "the incinerator is never a pivot");
}

#[test]
fn a_wrapped_sol_account_keeps_its_reserve() {
    let found = observe(TOKEN_ACCOUNT, &batch(WRAPPED_SOL_STATE, "[]"));
    let held = entity(&found, TOKEN_ACCOUNT);
    assert_eq!(attr(held, "token_native_sol"), "true");
    assert_eq!(attr(held, "token_native_reserve_lamports"), "2039280");
    assert_eq!(
        attr(held, "token_mint"),
        "So11111111111111111111111111111111111111112"
    );
    let plain = observe(TOKEN_ACCOUNT, &batch(TOKEN_ACCOUNT_STATE, "[]"));
    let plain = entity(&plain, TOKEN_ACCOUNT);
    assert_eq!(attr(plain, "token_native_sol"), "false");
    assert!(
        !plain.evidence[0]
            .attributes
            .contains_key("token_native_reserve_lamports")
    );
}

#[test]
fn a_listed_row_missing_a_field_or_with_a_bad_signature_is_unreadable() {
    for (malformed, why) in [
        (SIGNATURES.replace(r#""err":null,"#, ""), "no err field"),
        (
            SIGNATURES.replace(r#""memo":"[5] hello","#, ""),
            "no memo field",
        ),
        (
            SIGNATURES.replace(r#""blockTime":1793329229,"#, ""),
            "no blockTime field",
        ),
        (
            SIGNATURES.replace(SIGNATURE_NEW, &format!("{}0", &SIGNATURE_NEW[1..])),
            "a signature outside base58",
        ),
        (
            SIGNATURES.replace(SIGNATURE_NEW, &"2".repeat(89)),
            "a signature too long",
        ),
    ] {
        let found = observe(WALLET, &batch(WALLET_ACCOUNT, &malformed));
        let wallet = entity(&found, WALLET);
        assert_eq!(attr(wallet, "recent_transactions_unreadable"), "1", "{why}");
        assert_eq!(attr(wallet, "recent_transactions_listed"), "1", "{why}");
    }
}

#[test]
fn the_oldest_listed_time_is_claimed_only_when_every_row_has_one() {
    let untimed = SIGNATURES.replace(r#""blockTime":1793329000"#, r#""blockTime":null"#);
    let found = observe(WALLET, &batch(WALLET_ACCOUNT, &untimed));
    let wallet = entity(&found, WALLET);
    assert_eq!(
        attr(wallet, "latest_listed_transaction_utc"),
        "2026-10-30T03:00:29Z"
    );
    assert!(
        !wallet.evidence[0]
            .attributes
            .contains_key("earliest_listed_transaction_utc")
    );
}
