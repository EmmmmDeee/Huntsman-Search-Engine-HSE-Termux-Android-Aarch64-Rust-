- `crypto ADDRESS` (and `scan -k crypto`, saved scans and `/api/lookup`) now asks blockchain.info
  for a Bitcoin address's 20 most recent transactions with its summary, in the same single
  request. The address gains the first and last sampled transaction times. Every address it
  transacted with in them becomes a lead naming its role: `paid_by`, `paid_to`, or `co_input`
  (the common-input heuristic, at lower confidence). Each lead also names the transaction
  hash, its UTC time, its block height or `unconfirmed`, and the exact satoshis. At most 16 legs
  per side of a transaction and 64 counterparties are kept. A malformed transaction is skipped
  and counted, never losing the account summary. Each lead states that sharing a transaction is
  not common ownership, and no wallet owner is identified.
