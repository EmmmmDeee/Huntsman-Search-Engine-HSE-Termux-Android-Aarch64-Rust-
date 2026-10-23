- `help exposure` describes what `exposure ADDR` prints. It said a leg without its key reports
  `auth_required` (it reports `not_configured`), left out the `title` column of an
  `oathnet_breach` row and the `oathnet_value` rows (`field=value`, one per distinct
  non-credential value an `OathNet` breach's records hold), and claimed no record value other
  than a username or address is shown or kept. It now names those rows and their bounds (at
  most 64 field types per breach database, each named in ASCII letters, digits and `_` within
  48 bytes, and at most 64 values per field; a value over 1024 bytes is left out, never cut),
  and says what is held back: the value of a field whose name holds `pass` (other than as the
  start of `passport`), `pwd`, `hash` or `salt`, and of a list or object holding such a field.
