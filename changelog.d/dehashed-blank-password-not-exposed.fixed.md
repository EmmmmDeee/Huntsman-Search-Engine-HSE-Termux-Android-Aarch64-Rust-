- A `DeHashed` record whose password or hash field is blank, empty or `false` (`"password": ""`,
  `"hashed_password": []`, `{}`, `[""]`) no longer counts as an exposed password. Any value but
  `null` used to: `exposure ADDR`, `email ADDR` and scans printed `password_exposed=true` on its
  `dehashed_breach` row, tagged the address `password-at-risk` and saved `password_exposed=true`,
  and `dehashed search` printed and saved `has_password=true` / `has_hashed_password=true`. These
  now read `false`, as `OathNet` judges a blank string, `false` or an empty list or object. A
  list counts only when one of its elements holds something, so `[""]` is not exposed on
  `DeHashed`, though `OathNet` still counts any non-empty list. A record with a real value is
  unchanged.
