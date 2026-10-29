- `crypto eth:0xADDRESS` (and `scan -k crypto eth:0x…`, the Web UI New Scan picker, and saved
  scans) now runs a keyless Ethereum mainnet account lookup beside the existing Bitcoin and Base
  legs, closing the gap that left Ethereum — the most widely used EVM chain — with no coverage. It
  reads the finalized balance (exact wei), outgoing nonce and contract-code presence from a public
  Ethereum JSON-RPC endpoint, with no key, no indexing service, no full-history claim and no
  ownership assertion; a bare `0x` address is never silently routed to a chain — only an explicit
  `eth:` (or `base:`) selector is. The Base and Ethereum clients (`base_rpc`, `eth_rpc`) are now
  thin per-chain wrappers over one chain-parameterised `evm_rpc` core, so the request batch, the
  fail-closed decoding (wrong-chain, duplicate-id, partial-batch and JSON-RPC-error rejection) and
  the 256-bit wei provenance live in a single place instead of being duplicated per chain.
