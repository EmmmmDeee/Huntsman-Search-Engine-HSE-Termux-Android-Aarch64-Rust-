- More checks that were written out twice now have one home each. Output is unchanged.
  - An outcome kind and a health action are named by `SourceOutcomeKind::as_str` and
    `SourceHealthAction::as_str` in `classify`, `fetch`, outcome rows, scan log lines, the web
    query report and the `seeknow` commands, which each took the label from a JSON round-trip,
    with three different fallbacks that could never be reached. (`scan --recurse`'s outcome table
    still prints the Rust variant names.)
  - Local `search` decides that a name is a domain or one of its subdomains with
    `domains::is_or_subdomain_of`.
  - `doctor`'s Termux `PREFIX` check uses the app-data root that Termux detection owns.
  - ATT&CK relation coverage folds through `attack::fold_relation_techniques`, and leaf coverage
    divides with `metrics::fraction`.
  - HIBP's SHA-1 path pads through the same buffer builder as MD4, the one the test holding the
    padded password copy to one allocation pins.
  - The challenge-page checks in `search`'s unit test and in `huntsman-recon check` now use a body
    that holds the query term, so they fail if `search_response` stops refusing a challenge page.
