- More checks that were written out twice now have one home each. Output is unchanged.
  - An outcome kind and a health action are named by `SourceOutcomeKind::as_str` and
    `SourceHealthAction::as_str`. `classify`, `fetch`, outcome rows, scan log lines, the web
    query report and the `seeknow` commands each took the label from a JSON round-trip, with
    three different fallbacks that could never be reached.
  - Local `search` decides that a name is a domain or one of its subdomains with
    `domains::is_or_subdomain_of`.
  - `doctor`'s Termux `PREFIX` check uses the app-data root that Termux detection owns.
  - ATT&CK relation coverage folds through `attack::fold_relation_techniques`, and leaf coverage
    divides with `metrics::fraction`.
  - HIBP's SHA-1 path pads through the same buffer builder as MD4, so the test that holds the
    padded password copy to one allocation covers both.
  - The challenge-page checks in `search`'s unit test and in `huntsman-recon check` now use a body
    that holds the query term, so they fail if `search_response` stops refusing a challenge page.
