- A `people NAME` scan (and `scan -k people NAME`, the Web UI people scan and saved people scans)
  now also queries the keyless **SEC EDGAR** register, beside the ASIC person/company registers,
  Wikidata and the ACNC charity register, so a people scan reaches US securities filers — public
  issuers and the officers, directors and 10% owners who file insider forms 3, 4 and 5. EDGAR's
  full-text search resolves the queried name to the Central Index Keys of the filers whose published
  name actually matches, and each matched filer's submissions profile is folded in as a **candidate**
  (a filing-index name match, never a confirmed identity of the queried person): the filer as a
  `Person` or `Organisation`, its official **website** as a `Domain` and `Url` lead into the wired
  domain-recon cluster (crt.sh, certspotter, DNS, RDAP, Wayback, Common Crawl), its business and
  mailing **address** the geocoder can forward-geocode, and its **LEI** kept verbatim as a correlation
  key that joins the GLEIF leg. Its CIK, tickers, exchanges, SIC, category and former names ride as
  evidence; every published field is kept verbatim and nothing is redacted.
- EDGAR needs no API key or login. Its only fair-access requirement is a declared, contactable
  User-Agent (a missing or generic one is refused), so the client sends an honest tool-identifying
  User-Agent naming the project — never a browser impersonation and never a person's private contact.
- Evidence integrity is fail-closed, reusing the shared `fetch` boundary: a challenge page, a
  truncated body or an uncontracted/unreadable envelope is schema drift, never evidence; only a filer
  whose published name matches the queried name as whole words becomes a candidate, so a loose
  full-text rank never fabricates an unrelated filer (a co-filed issuer is not attributed to a
  person-name query); a submissions document whose own CIK is not the requested one is schema drift,
  never attributed; and an empty search is an honest clean zero (most people have no EDGAR presence),
  never a failure. The filer candidates carry the shared **name-search lead** tag, so a recursive scan
  keeps a name-matched filer as a visible lead but never auto-dispatches it onto a potentially
  unrelated third party, whatever the operator's expansion floor. Within the composed people lookup
  each filer's identity is scoped by its CIK, so same-name strangers across registers never merge or
  inflate corroboration.
- This adds the new keyless `sec_edgar` source client, wired into the People scan module list, run by
  `people_cli` beside the existing legs (now an eight-leg catalogue), with its saved-ledger provenance
  attributed to `src/sec_edgar.rs`.
