- `username HANDLE` and username scans now look the handle up on Telegram's public page
  (`t.me/HANDLE`), keyless, in one request. The page is read as a channel, group, bot or
  published profile, and its title, verified badge, counts and description are kept as evidence.
  Addresses and links in the description become candidate leads, and a link to another Telegram
  name becomes a pivot. An unowned handle and a private account show the same placeholder page,
  so that answer is inconclusive, never "no such account". A `t.me/NAME` link found on another
  profile is now linked to the matching Telegram username.
