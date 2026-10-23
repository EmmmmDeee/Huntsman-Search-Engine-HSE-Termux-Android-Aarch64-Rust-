- An HTML numeric reference into `&#128;`-`&#159;` reads as the Windows-1252 character a page
  meant, as browsers read it, so `it&#146;s` is `it’s` rather than a C1 control code, and `&#0;`
  is U+FFFD instead of a NUL. XML references keep XML's rules.
- `serve` answers a lookup still running with `504 Gateway Timeout`, not `504 Error`.
- The per-host circuit breaker treats `host.` and `host` as one host, so the trailing-dot
  spelling of a rate-limited host is paced with it.
