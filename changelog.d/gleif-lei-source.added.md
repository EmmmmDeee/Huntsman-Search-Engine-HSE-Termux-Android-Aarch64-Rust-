- `gleif LEI|NAME` (also in the module catalogue) is a new keyless source: it looks up a legal
  entity on the public GLEIF Legal Entity Identifier register -- a 20-character LEI, or a company
  name resolved to its top matching record -- and wires three previously dangling pathways to a real
  producer: the `gleif_lei` source id the correlator's `identity_registry` family references, the
  `LEI` structured-field type, and the `legal_entity_identifier` (P1278) pivot Wikidata emits. It
  reads GLEIF's public API (`/api/v1/lei-records/{LEI}`, or `?filter[fulltext]=` for a name). A record
  is accepted only when the response envelope is a `lei-records` object whose id is exactly the
  requested LEI (a mismatch is schema drift, an unknown LEI or an empty search a clean zero). The
  registered legal name is an `Organisation` (a candidate, never a confirmed identity), its legal and
  headquarters addresses are `Address` pivots the geocoder can forward-geocode, and an Australian
  entity's local registration number is a checksum-validated `AbnAcn` that feeds the ASIC director
  correlation. Every register field is kept verbatim as evidence; nothing is redacted and no
  classification is invented.
