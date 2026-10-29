- A `people NAME` scan (and `scan -k people NAME`, the Web UI people scan and saved people scans)
  that names a charity or not-for-profit now also queries the keyless **ACNC Charity Register** on
  `data.gov.au`, beside the ASIC person/company registers and Wikidata, so a people scan reaches
  Australia's register of registered charities. It adds the charity **organisation** (a register name
  match, never a confirmed identity of the queried person), its **ABN** (a precise Australian
  business number kept as an `AbnAcn` correlation key — the ASIC and GLEIF legs key on the 9-digit
  ACN, so an 11-digit ABN does not auto-join those), its official **website** (a `Domain` lead into the
  wired domain-recon cluster — crt.sh, certspotter, DNS, RDAP, Wayback and Common Crawl), and its
  registered **address** with a postcode-derived **coordinate** for geocoding. Every published field —
  size, purposes, beneficiaries and operating states — is kept verbatim as evidence; nothing is
  redacted. Evidence integrity is fail-closed, reusing the shared `ckan` helpers: only a record whose
  charity name actually matches the queried name (a whole-word token match on the legal or an
  alternate name) becomes an entity, so a loose full-text rank never fabricates an unrelated charity;
  a `success: false` envelope is schema drift, never a clean zero; a malformed ABN is dropped rather
  than minted. The website `Domain` is tagged a shared **name-search lead** — the same attribution
  guard the Wikidata people leg uses — so a recursive scan keeps a name-matched charity's site as a
  visible lead but never auto-dispatches it onto a potentially unrelated third party, whatever the
  operator's expansion floor. This adds the new keyless `acnc` source client, wired into the People scan
  module list, run by `people_cli` beside the existing legs, with its saved-ledger provenance
  attributed to `src/acnc.rs`.
