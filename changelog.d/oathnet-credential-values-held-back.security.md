- `exposure`, `email` and `username` lookups and scans no longer print or save an `OathNet`
  record's password, hash or salt when the field is not named exactly `password`,
  `password_hash` or `salt`, or when it sits inside a list or object. A field whose name holds
  `pass`, `pwd`, `hash` or `salt` in any case, at the top level or in `extra`
  (`hashed_password`, `User_PWD`), is now a credential: it stays in `fields=` and sets
  `password_exposed=true` and the `password-at-risk` tag, but has no `oathnet_value` row and no
  `value_<field>` attribute. A field whose list or object holds such a key at any depth
  (`credentials={"password":"x"}`) stays in `fields=` with its value held back the same way. The
  match fails closed, so a field that only looks like a credential, such as `passport`, is
  treated as one.
