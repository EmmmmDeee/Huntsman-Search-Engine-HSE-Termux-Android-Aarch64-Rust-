- The operator-configured Nominatim and Wikibase origins (`HUNTSMAN_NOMINATIM_BASE_URL`,
  `HUNTSMAN_WIKIDATA_BASE_URL`) are checked by one rule, `canonical::is_https_origin`: `https://`,
  a qualified hostname whose every label is a DNS label, an optional nonzero decimal port, and no
  path, userinfo, query or fragment. Wikidata previously had its own weaker copy that let through
  an empty label, a hyphen-led label or a malformed port (`https://example..org`,
  `https://-x.example.org`, `https://example.org:abc`); those are now refused with the same
  message as before, so a mistyped origin never reaches the guarded transport. The rule has its own
  tests.
- The dossier HTML view and the `meta_scan` web pages escape text through one
  `textnorm::escape_html` instead of two private copies of the same five replacements; the output
  is byte-for-byte the same. XML writers (GEXF, XLSX) keep their own rules, which differ.
