- The AU-002 identity-cluster correlation (Critical: identities of at least two kinds that
  plausibly belong to one person) no longer fires on contacts that name no person. A registration
  record's contacts were counted: an AS, address or domain scan's RDAP abuse desk, operator role
  mailbox and switchboard (`abuse@cloudflare.com`, `rir@cloudflare.com` and one telephone for
  AS13335; a .com registrar's abuse mailbox and telephone for any domain) made an identity cluster
  on their own. So did a person guessed from an e-mail's local part: a corporate `jane.doe@`
  address alone, with the name "Jane Doe" derived from it, was a Critical cluster. The rule now
  leaves out a contact a registration record publishes as a group or an organisation, or as an
  abuse desk it does not call an individual, while no other corroborating source observed it: a
  telephone's numbering plan and a lookup's echo of its selector observe no one, so a crawl that
  looks the contact up leaves it out too, unless a keyed source (Numverify, Whoxy) answers for it.
  RDAP contacts now carry their jCard kind (`contact_kind`) for this, and a contact published as an
  individual, or with no kind (as AFNIC publishes its desks), is a person's and still counts. A
  name every record of which was inferred from an address is left out, as a handle any record of
  which was guessed already was, but one a source observed for the address (a key server's or
  Gravatar's) counts. A role mailbox (`abuse@`, `hostmaster@`, `info@`) found anywhere is left out
  unless it is the operator's own seed. Whether there are more of a kind than one person holds is
  judged on every identity observed, role contacts included, so a page listing many mailboxes stays
  no cluster. Saved scans are rescored when they are correlated again: one saved before this has no
  `contact_kind`, so of its registration contacts only abuse desks and role mailboxes are left out.
  The first scan a continuous target collects after this can raise a HIGH alert for AU-002 at its
  new counts, as the scan before it is compared with the correlations it was saved with; correlate
  that scan again first to avoid it.
