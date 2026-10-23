- A `/regex/` search (`scans search`, the serve page's search box, `GET /api/scans/search`) or a
  correlation rule's `regex` value with more than 64 nested groups, such as a run of 100,000 `(`,
  is refused with `groups nested too deeply` and reported like any other bad pattern: an error
  from `scans search`, a 400 from the API, a rule error for the rule file. It used to recurse once
  per `(` until the stack overflowed and the whole process aborted, which under `serve` dropped
  every connection. Patterns nested 64 deep or less are unchanged.
- A character class now counts once per item in it toward the 20,000-instruction limit on a
  pattern. `[` with 30,000 letters then `]{19999}` (about 30 KB, so it fits in a search request)
  used to be accepted and copied the whole class once per repetition, about 4.8 GB, and a smaller
  count made every search over saved scans crawl. It is now refused with `compiles to more than
  20000 instructions`, as is `[a-z0-9]{10000}`. One-item classes such as `\d{10000}`, and every
  shipped Spiderfoot rule, compile as before.
- `{,n}` and `{,}` repeat 0 to n times and 0 or more times, as Python's `re` reads them:
  `/^ab{,2}c$/` now finds `abc`, where it used to look for the literal text `ab{,2}c`. `{}` and a
  bound too large for 32 bits are still literal text.
- `\Z` matches only at the very end of a value, as in Python: `/OpenSSH\Z/` no longer finds a
  value ending in `OpenSSH` and a newline. `$` still matches just before a final newline.
