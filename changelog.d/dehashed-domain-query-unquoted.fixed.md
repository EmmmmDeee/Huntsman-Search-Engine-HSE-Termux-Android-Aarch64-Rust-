- Fixed: every DeHashed domain search failed against the live v2 API, which refuses a quoted
  domain (`domain:"x"`) with HTTP 400 "Issue with query format". A domain is now sent unquoted, which
  the API reads exactly; email and username stay quoted, since an unquoted email is a fuzzy match
  (1,982,342 records instead of the address's 5,182).
- `tests/dehashed_live.rs`: an opt-in (`--ignored`) acceptance test of the DeHashed client, decoder
  and collector against the live API with a real key, checked against the raw response.
