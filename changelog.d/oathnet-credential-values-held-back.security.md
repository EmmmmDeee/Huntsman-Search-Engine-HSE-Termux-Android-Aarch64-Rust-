- `exposure`, `email` and `username` lookups and scans no longer print or save the value of an
  `OathNet` field whose name holds `pass`, `pwd`, `hash` or `salt` in any case, at the top level
  or in `extra` (`hashed_password`, `User_PWD`), nor of a list or object holding such a field at
  any depth (`credentials={"password":"x"}`). Before, only fields named `password`,
  `password_hash` or `salt` (in any case) were held back, and a list or object was printed
  whole. Such a field has no `oathnet_value` row and no `value_<field>` attribute; its name stays
  in `fields=` unless it is a name `fields=` leaves out. A `pass` that begins `passport` does not
  count, so `passport_number` is kept as a value. A field named otherwise, such as `credentials`
  or `pw` holding a string or a list of strings, is printed and saved as before.
- A record now sets `password_exposed=true`, the `password-at-risk` tag and the
  `PASSWORD_COMPROMISED` element when a key whose words name a password holds a value, as a
  field or inside a list or object, even under a name `fields=` leaves out. A word counts when,
  trailing digits dropped, it begins `password`, `passwd`, `passwort`, `passphrase` or `passcode`
  (`Passwd`, `hashed_password`), is `pwd`, `pwdhash`, `passhash`, `userpass` or `salt`
  (`User_PWD`, `salt1`), or is `pass` or `hash` alone or beside another such word or one such as
  `user`, `old` or `md5` (`user_pass`, `pass_md5`, `salted_hash`). Words split at camel case and
  capital runs (`USERPass`). A key that describes a password (`pwdLastSet`,
  `password_changed_at`, `password_hint`) and one that only holds a marker (`passenger_name`,
  `boarding_pass`, `compass`, `hashtags`, `file_hash`) are held back but say no password was
  exposed. Before, only `password`, `password_hash` and `salt` fields set it.
