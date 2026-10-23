- `case-check` refuses a claim class outside its five classes, so a misspelt
  `verified_primary_record` backed only by a first-party page no longer passes unflagged and
  missing from the unresolved claims. Case, source and claim IDs must be plain identifiers, so
  one holding a newline can no longer forge a line of the printed audit such as
  `external_claims=verified`, and a source `url` that is present must be an `https://` string.
