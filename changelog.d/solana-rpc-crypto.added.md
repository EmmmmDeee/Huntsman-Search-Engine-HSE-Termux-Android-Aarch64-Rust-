- `crypto sol:ADDRESS` (and `scan -k crypto sol:…`, an inferred `scan sol:…`, the Web UI New Scan
  picker, and saved crypto scans) now reads a Solana mainnet-beta account through the new keyless
  `solana_rpc` client: one bounded, read-only JSON-RPC batch, accepted only when the reply's genesis
  hash is mainnet-beta's, that keeps the exact lamports and SOL balance, the owner program and an
  account class (native SOL account, token account, mint, multisig, program), decodes the SPL Token
  and Token-2022 account, mint and multisig layouts — a token account's mint, raw amount, frozen
  state, wrapped-SOL reserve and the wallet that owns it with any delegate or close authority, a
  mint's supply, decimals and mint and freeze authorities, a multisig's required count and signers,
  each controlling address its own `sol:` pivot (so a mint resolves to its authority and an
  authority multisig to its signers), with a "New Scan of this" button in the Web UI — and lists the
  newest transactions naming the address that the node retains, each with its signature, slot,
  time, error and memo verbatim, named for what they are: transactions naming the address, whoever
  signed them. The shared mint stays an attribute and neither the all-zero key nor the incinerator
  is ever a pivot, so unrelated holders and burns are never correlated; a Solana address keeps its
  letter case in its entity identity (base58 has no checksum); an unreadable transaction list drops
  only that enrichment, and with no account it is inconclusive or drift, never a clean zero; no
  address is attributed to an owner. The crypto front-end now routes every chain through one
  exhaustive table that scan inference shares, and a prefixed selector's saved target is typed
  `HSE_CRYPTO_ADDRESS` rather than `BITCOIN_ADDRESS`.
