# Independent OSINT method: Base wallet account observation

This module reproduces a **method**, not a paid enrichment service, provider
database, wallet login, agent rail, or private lookup backend. It implements
passive, read-only public blockchain account intelligence in Rust.

## Capability and integration

- src/base_rpc.rs generates one fixed JSON-RPC batch to the public Base
  mainnet endpoint, using only eth_chainId, eth_getBalance,
  eth_getTransactionCount, and eth_getCode. There are no transaction
  submission methods, private keys or third-party enrichment credentials.
- src/crypto_cli.rs dispatches the existing crypto lookup between Bitcoin
  (unchanged) and Base. The explicit base: prefix prevents an arbitrary
  EVM address being misrepresented as Base.
- src/lookup_modules.rs and src/module.rs expose base_rpc to the
  existing module selector, scan planner, and Web UI source listings.
- src/scan_route.rs lets auto scans recognize the explicit base: prefix.
- src/lookup_save.rs maintains exact evidence provenance in saved ledgers.
- src/web_ui.html offers the same crypto scan type with the new selector
  guidance; the API and CLI use the existing shared lookup executor.

## Use

    huntsman-recon crypto base:0x1111111111111111111111111111111111111111
    huntsman-recon crypto base:0x1111111111111111111111111111111111111111 --save evidence.json
    huntsman-recon scan base:0x1111111111111111111111111111111111111111
    huntsman-recon scan -k crypto base:0x1111111111111111111111111111111111111111
    huntsman-recon verify evidence.json

The existing Web UI at http://127.0.0.1:8080 accepts a crypto
scan containing base:0x plus forty hexadecimal characters. The embedded
HTTP API shares the same lookup flow and HTTP egress policy as the CLI.

## Interpretation and safety

A successful response records source, time, finalized block **tag**,
chain ID 8453, exact balance in wei (256-bit decimal without floating
point), outgoing nonce and presence of deployed contract code. Those fields
are **state observations**, not proof of legal ownership, attribution,
identity, beneficial control, historical transactions or a zero-activity
history. A contract can hold funds; a user can use several accounts.

The RPC batch spans methods whose responses may be evaluated at slightly
different finalized blocks; no atomic snapshot or block-number claim is
made. The client rejects missing/duplicate method replies, a wrong chain,
invalid hexadecimal, truncated responses, provider failures, WAFs or rate
limits as **inconclusive**, never as a clean negative.

The Base public endpoint is rate-limited and intended for modest
development/light-read traffic, not an unrestricted bulk enumerator.
This source adds **zero** required runtime crates or paid API entitlements.
It does not enumerate transaction transfers: that would require bounded
historical indexing, a suitably permissioned explorer API, or a separately
authorized archive node.

## Verification

Offline fake-transport tests cover the actual POST body, chain isolation,
out-of-order method replies, decimal precision including max U256,
duplicate IDs, malformed responses, error redaction, throttling, and
saved-route integration. Live connectivity depends on the external public
RPC and the operator's network: do not substitute a mocked test for an
uptime claim.

Reference: https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_getTransactionCount
