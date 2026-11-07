- Dubai and UAE OSINT. `phone` reads a `+971` number against the UAE numbering plan (`phone_ae`,
  the ranges Google's libphonenumber records for the UAE): a fixed line's area and the emirates in
  it (`04` is Dubai, `AE-DU`), a mobile range or a toll-free, universal access, shared-cost or
  premium-rate range, with its local and international forms. An area is where the exchange is,
  not an address, and no operator is inferred. Every phone scan's Sources table now names four
  plans, each answering for its own numbers.
- A number written in Arabic-Indic or Persian digits, with the direction marks of right-to-left
  text around it, is read as its ASCII digits by `phone`, `scan` and the classifier behind
  `investigate`, so `+٩٧١ ٤ ٣١٢ ٣٤٥٦` in an Arabic document is the number `+97143123456`.
- `id` validates a UAE Emirates ID number (`784-YYYY-NNNNNNN-C`, Luhn-checked) and a UAE IBAN (`AE`
  and 21 digits, mod 97-10 checked), offline; a valid check digit shows a number is well formed,
  not who holds it, and no bank name is guessed from an institution identifier.
- `gleif --jurisdiction AE-DU NAME` resolves a name among Dubai-registered entities on GLEIF's
  keyless register, and `--country AE` among entities with a UAE legal address (GLEIF records many
  Dubai entities under the federal `AE` jurisdiction); Arabic legal names are searched as written.
- `people-discover --region ae` (and `"region": "ae"` on `POST /api/people/discover`) scopes the
  official-register search to the Dubai Financial Services Authority's public register of DIFC
  firms and individuals (`dfsa.ae`), and `sources` offers that register, as a search scoped to its
  site, for a person or organisation. Both are unverified leads.
