- A `username HANDLE` lookup (and username scans) now also asks two keyless game-site accounts,
  each an exact-identity JSON API: **Chess.com** (`api.chess.com/pub/player/{handle}`) and
  **Lichess** (`lichess.org/api/user/{handle}`). Each confirms the handle case-insensitively by the
  document's own username or canonical id, reads a plain 404 as a clean "no such account", a
  challenge page as a wall and any other shape as drift, and keeps the account's profile URL,
  title, country or flag, join and last-seen times, game counts and status flags as verbatim
  evidence. The display or real name and any absolute link or Twitch channel the account
  self-declares become low-confidence, `self-reported` candidate leads — never a confirmed
  identity. Both run beside the thirteen existing legs, paced, redirects disabled.
