- `exposure`, `email` and `username` lookups and scans no longer print or save the value of an
  `OathNet` field whose name holds `pass`, `pwd`, `hash` or `salt` in any case, at the top level
  or in `extra` (`hashed_password`, `User_PWD`), nor of a list or object holding such a field at
  any depth (`credentials={"password":"x"}`). Before, only fields named exactly `password`,
  `password_hash` or `salt` were held back. Such a field has no `oathnet_value` row and no
  `value_<field>` attribute; its name stays in `fields=` unless it is a name `fields=` leaves
  out. When the credential holds a value, as a field or inside a list or object, it sets
  `password_exposed=true`, the `password-at-risk` tag and the `PASSWORD_COMPROMISED` element,
  even under a name `fields=` leaves out (`Pass=word`, `user-password`). A `pass` that begins
  `passport` does not count, so `passport_number` is kept as a value, while `passphrase`,
  `user_pass` and `Passwd` are credentials. A field named otherwise, such as `credentials` or
  `pw` holding a string or a list of strings, is printed and saved as before.
