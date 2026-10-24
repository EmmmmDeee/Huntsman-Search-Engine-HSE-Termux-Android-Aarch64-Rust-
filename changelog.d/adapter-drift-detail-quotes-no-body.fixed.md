- A Shodan, Netlas, OTX, RIPEstat or Robtex answer of an unexpected shape no longer copies a value
  from the response into the failed lookup's detail, which is printed and saved in the ledger.
  A Shodan answer with `"ports":["443"]` was recorded as `shodan: unexpected response shape:
  invalid type: string "443", expected u16`; it is now `shodan: unexpected response shape: data
  error`, naming only the kind of error, as the other API sources already do. A Robtex domain
  record of the wrong shape used to say `unexpected record shape: …` and now says `unexpected
  response shape: data error`. The outcome is still `schema_drift`.
