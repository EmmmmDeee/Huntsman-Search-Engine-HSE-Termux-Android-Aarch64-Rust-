- `plan` and `investigate` no longer read a six-digit number as an Australian business number.
  `plan 123456` was accepted as an `abn_acn` seed at 0.95 with the signal `checksum`, and
  `investigate "order 123456 shipped"` listed `123456` as an `abn_acn` entity, although six digits
  (or `062-000`) is the shape of a BSB, which has no checksum. Such a value is now unsupported:
  `plan` exits 65 with "no actionable seeds" and `investigate` drops it. An ABN or ACN typed with
  spaces is now stored bare, so `plan "51 824 753 556" 51824753556` gives one seed,
  `51824753556`, not two.
- A bare IPv6 address is an `ip_address`. `plan 2606:4700:4700::1111` exited 65 with "no
  actionable seeds", `investigate` dropped the address and `sources` printed "no actionable source
  routes". The address is now accepted at 0.92 (signal `parsed`) in its compressed lower-case
  form, so `2606:4700:4700:0:0:0:0:1111` is the same seed, and `sources` lists its IP routes.
  `investigate` reads one that ends in `::`, such as `fe80::`, whole, even before a full stop.
  Eight groups of two hex digits, such as the Fibre Channel WWN
  `50:06:01:60:3b:20:19:88`, are an identifier, not an address, and stay unsupported, as does
  an address that compresses to that shape, such as `0010:0020:0030:0040:0050:0060:0070:0080`
  (`10:20:30:40:50:60:70:80`), so a stored address always reads back as one. In free
  text, a token of hex digits joined by or ending in `::`, such as `add::bad` or `cafe::`, is now
  also read as an address.
- `investigate` finds an email address or URL written in angle brackets.
  `investigate "From: Ada Lovelace <ada@example.com>"` printed `entities=0` and now lists
  `ada@example.com` as an `email` entity at 0.85. `<https://example.com>` is read the same way,
  and the Bluesky and Keybase bio readers pick these up too. A bracket followed by a full stop
  (`<ada@example.com>.`) is still missed.
- An AS number is stored without leading zeros, however many it has, and must fit in 32 bits.
  `plan AS013335 AS13335` gave two seeds and now gives one, `as13335`, and `plan AS00000013335`,
  refused before, is that seed too, as `scan` reads it. `plan AS4294967296` was accepted and is
  now unsupported (exit 65).
- An all-uppercase bech32 Bitcoin address, such as `BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4`,
  is a `crypto_address` stored in lower case, as `scan -k crypto` already read it; `plan` refused
  it. A `bc1` value with an uppercase `B`, `I` or `O` after the prefix, letters bech32 does not
  use, is no longer a `crypto_address`.
- A MAC address written with mixed `:` and `-` separators, such as `00:1A-2B:3C-4D:5E`, is a
  `mac_address` (`00:1a:2b:3c:4d:5e`), as `scan` already read it as a BSSID; `plan` refused it.
- A seed that starts with `@` but is not a valid handle is unsupported. `plan @` was accepted as a
  username (exit 0), and `plan "@Ada Lovelace"` became the username `@ada lovelace`; both now exit
  65 with "no actionable seeds". `sources` no longer routes such a value (`@josé`, `@foo!`, or a
  handle over 40 characters) and exits 65 with "no actionable source routes".
- `GET /api/analyze`, behind the web UI's analysis form, reads seeds as `plan` does, so each
  change above to what `plan` takes applies there too: an IPv6 address, an uppercase bech32
  address or a mixed-separator MAC address is listed in `accepted`, and a BSB, an `@` value that
  is not a handle or `AS4294967296` in `rejected`, as "not a kind of seed the spine takes".
