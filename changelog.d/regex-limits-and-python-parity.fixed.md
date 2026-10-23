- A `/regex/` search (`scans search`, the serve page's search box, `GET /api/scans/search`) or a
  correlation rule's `regex` value with more than 64 nested groups is refused with `groups nested
  too deeply` and reported like any other bad pattern: an error from `scans search`, a 400 from
  the API, a rule error for the rule file. It used to recurse once per `(` until the stack
  overflowed and the whole process aborted. A run of 100,000 `(` did it in `scans search`; under
  `serve` about 10,000, short enough to fit in a search request, overflowed the 4 MiB stack a
  search runs on and dropped every connection; and a rule file, at most 64 KiB, holds a run long
  enough to do it too. Patterns nested 64 deep or less are unchanged.
- A character class now counts once per item in it toward the 20,000-instruction limit on a
  pattern. `[` with 30,000 letters then `]{19999}` (about 30 KB, so it fits in a search request)
  used to be accepted and copied the whole class once per repetition, about 4.8 GB, and a smaller
  count made every search over saved scans crawl. It is now refused with `compiles to more than
  20000 instructions`, as is `[a-z0-9]{10000}`. One-item classes such as `\d{10000}`, and every
  shipped Spiderfoot rule, compile as before.
- A pattern now compiles in time bounded by its length plus the 20,000-instruction limit. A
  counted repeat of a part that matches only empty text, such as `(?:a{0}){4294967295}`, used to
  be expanded that many times for nothing. That one took over 20 seconds, and
  `(?:(?:a{0}){4294967295}){4294967295}` never finished: `scans search` with it, or loading a
  rule with it, hung, and under `serve` each such search held a connection and a core for good.
  A repeated part is also compiled once and then copied, where each copy used to compile it
  again, so thousands of `a{0}` inside a part repeated 19,998 times no longer take seconds.
  Every pattern compiles to the same program and matches as before.
- `{,n}` and `{,}` repeat 0 to n times and 0 or more times, as Python's `re` reads them:
  `/^ab{,2}c$/` now finds `abc`, where it used to look for the literal text `ab{,2}c`. `{}` and a
  bound too large for 32 bits are still literal text. After `^`, `$`, `\b`, `\B`, `\A`, `\Z` or
  `(?i)` they are refused with `nothing to repeat`, as in Python, where `/^{,2}/` used to look for
  the start and the literal text `{,2}`. After an empty group such as `()` or `(?:)` they are
  also refused with `nothing to repeat`, as `*`, `+`, `?` and `{n}` already were there, although
  Python accepts all of them; `/(){,2}/` used to look for the literal text `{,2}`.
- `\Z` matches only at the very end of a value, as in Python: `/OpenSSH\Z/` no longer finds a
  value ending in `OpenSSH` and a newline. `$` still matches just before a final newline.
