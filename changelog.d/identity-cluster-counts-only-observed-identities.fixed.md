- The AU-002 identity-cluster correlation (Critical: identities of at least two kinds that
  plausibly belong to one person) no longer fires on identities that name no person. A
  registration record's role contacts were counted: an AS, address or domain scan's RDAP abuse
  desk, operator role mailbox and switchboard (`abuse@cloudflare.com`, `rir@cloudflare.com` and
  one telephone for AS13335; a .com registrar's abuse mailbox and telephone for any domain) made
  an identity cluster on their own. So did a person guessed from an e-mail's local part: a
  corporate `jane.doe@` address alone, with the name "Jane Doe" derived from it, was a Critical
  cluster. The rule now leaves out a person, like a username, any of whose records was inferred; a
  mailbox or telephone only a registration record names (tagged `abuse-contact` or
  `whois-contact`), unless another source observed it too; and a role or infrastructure mailbox
  (`abuse@`, `hostmaster@`, a provider's own address) wherever it was found. Saved scans are
  rescored when they are correlated again.
