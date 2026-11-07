- `exposure` and the email lookups now find a DeHashed key kept in the legacy private
  `~/.config/dehashed/api_key` file, as `dehashed search` always has. Before, a key kept only
  there made the lookups report DeHashed as not configured, though `dehashed search` used the same
  key. Every DeHashed path now resolves the key one way: the shared keys file, then the
  environment, then that file, honoured only while it is private.
