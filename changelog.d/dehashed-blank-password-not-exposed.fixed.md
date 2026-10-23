- A `DeHashed` record whose password or hash field is blank, empty or `false` (`"password": ""`,
  `"hashed_password": []`, `{}`, `[""]`) no longer counts as an exposed password. Any value but
  `null` used to: `exposure ADDR`, `email ADDR` and scans printed `password_exposed=true` on its
  `dehashed_breach` row, tagged the address `password-at-risk` and saved `password_exposed=true`,
  and `dehashed search` printed and saved `has_password=true` / `has_hashed_password=true`. These
  now read `false`, as `OathNet` already judged the same field; a record with a real value is
  unchanged.
