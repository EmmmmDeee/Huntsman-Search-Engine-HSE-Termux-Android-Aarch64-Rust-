- `sources @HANDLE` routes the handle as written, without its leading `@`. The routes were built
  from the handle with every `.`, `_` and `-` removed and lowercased, so `sources @octo-cat`
  printed `https://github.com/search?q=octocat&type=users` and exact-phrase searches for
  `"octocat"`, a different account, and `@Ada.Lovelace` searched for `adalovelace`. They now
  print `q=octo-cat&type=users` and `q=%22octo-cat%22`. The planned username routes of
  `GET /api/analyze` and the web UI (`planned[].url`) change the same way; `planned[].value` is
  still the canonical handle. Header lines and route counts do not change.
