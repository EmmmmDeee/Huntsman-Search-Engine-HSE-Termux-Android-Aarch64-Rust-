- A crawl now asks each keyed breach source about an address once. The e-mail lookup folds every
  configured breach leg in, so the separate breach pass of the same address asked them all again:
  `scan --recurse` never skipped that pass, and a saved scan (`scans run`, the Web UI, `sf`)
  skipped it only when a breach row's label was the module's own name, which HIBP's
  (`hibp_account`) is not. A saved scan whose modules asked HIBP but none of `stolen_tax`,
  `oathnet` or `dehashed` (whose rows otherwise triggered the skip) sent every address to HIBP
  twice, and so did every `scan --recurse` with a breach key set. Both now skip the pass by one rule (`lookup_modules::BreachPasses`), which reads each
  row's label as its module.
