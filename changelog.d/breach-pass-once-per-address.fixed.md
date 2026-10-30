- A crawl now asks each keyed breach source about an address once. The e-mail lookup folds every
  configured breach leg in, so the separate breach pass of the same address asked them all again:
  `scan --recurse` never skipped that pass, and a saved scan (`scans run`, the Web UI, `sf`)
  skipped it only when a breach row's label was the module's own name, which HIBP's
  (`hibp_account`) is not. With HIBP alone configured, every address in a scan was sent to HIBP
  twice. Both now skip the pass by one rule (`lookup_modules::BreachPasses`), which reads each
  row's label as its module.
