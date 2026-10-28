- HIBP and DeHashed keys now reach a request only as a `fetch::Credential` built from the
  operator-configured slot and pinned to the provider's origin (`https://haveibeenpwned.com:443`,
  `https://api.dehashed.com:443`), as every other keyed source already did: `fetch` puts the key
  on the request only while it goes to that origin, strips it from any other hop and scrubs it
  from diagnostics. The two clients no longer set the header themselves, and a boundary test
  refuses any production code but `src/fetch.rs` that puts a secret on a request. Requests,
  results, errors and exit codes are unchanged.
