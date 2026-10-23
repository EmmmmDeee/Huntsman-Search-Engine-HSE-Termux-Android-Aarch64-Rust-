- `sources @HANDLE` routes the handle as written, without its leading `@`. The routes were built
  from the handle with every `.`, `_` and `-` removed and lowercased, so `sources @octo-cat`
  printed `https://github.com/search?q=octocat&type=users` and exact-phrase searches for
  `"octocat"`, a different account, and `@Ada.Lovelace` searched for `adalovelace`. They now
  print `q=octo-cat&type=users` and `q=%22octo-cat%22`. The planned username routes of
  `GET /api/analyze` and the web UI (`planned[].url`) change the same way; `planned[].value` is
  still the canonical handle. When one analysis is given two spellings of the same canonical
  handle (`@octocat @octo-cat`), it keeps one seed but routes each spelling as written, in either
  order; before, only one spelling was routed. Header lines and `sources` route counts do not
  change.
