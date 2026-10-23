- `username` asks its five public-profile sources (GitHub, Bluesky, Keybase, Wikipedia,
  Mastodon) at once instead of one after another, so a lookup takes as long as its slowest source:
  about 0.14 s instead of 0.4 to 1.0 s for one handle on a fast link, and five 200 ms sources
  answer in about 200 ms rather than a second. The report is unchanged: answers are folded in the
  same fixed order. The five near-identical per-source collectors are now one table.
