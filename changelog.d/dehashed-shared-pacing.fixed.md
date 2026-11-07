- DeHashed searches now share one budget per process, at DeHashed's documented rate, and a rate
  limit pauses the next search instead of sending it. Each lookup used to build its own budget,
  so concurrent lookups, a batch scan, a recursive crawl and the web UI each spent their own.
  That budget was also HIBP's ten a minute, not DeHashed's ten a second.
  - **The 429 pause.** A 429 used to be reported and then ignored: the next search went out at
    once. Searches now go through `fetch`'s per-host breaker. A 429 pauses DeHashed for its
    `Retry-After`, or the breaker's cool-down, and five failures in a row open the breaker.
  - **What a paused search says.** It sends nothing and reports "paused after an earlier rate
    limit or failures; nothing was sent".
  - **The limiter's home.** It moves from `hibp::rate_limit` to `rate_limit`, since two providers
    use it; `hibp::rate_limit` still names it.
