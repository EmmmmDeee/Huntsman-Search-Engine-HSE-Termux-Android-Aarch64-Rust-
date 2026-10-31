- An e-mail lookup no longer reports its own guesses as an identity cluster. The usernames and
  the name it reads off an address's local part (`janedoe`, `jdoe`, `Jane Doe` from
  `jane.doe@acme.example`) are readings of the address, but the relation graph keyed them by
  handle like any observed account, so `AliasOf` and `IdentifiedBy` edges bound the address to its
  own guesses, and a profile link a source found under a guessed handle (`github.com/jdoe` on the
  address's Gravatar) was bound to the guess as the same identity. Every such lookup raised a High
  transitive identity closure (AU-060, "3 entities joined by identity-binding relations") and a
  corroboration gap (AU-063) over the address and what was read from it. An entity every record of
  which a source that observes no one read off another value (the address parser, the handle
  variants) now keys no identity relation; the guesses stay in the report as derived leads. An
  address a profile publishes is an observation, though read from its text, and still aliases its
  account, as does an account a source observed under a guessed handle. The address or handle the
  operator asked about is no guess: it keys its handle as before, whether or not a source has
  observed it yet. A crawl that follows a guessed handle still binds it through that lookup's echo
  of it, which the crawl keeps.
