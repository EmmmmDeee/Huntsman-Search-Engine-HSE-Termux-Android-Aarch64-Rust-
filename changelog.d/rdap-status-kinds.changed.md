- The rdap outcome row now types an HTTP status as fetch types the response, the way sources that
  read their response through `fetch::answer` do. A registry's 401 used to be `upstream4xx` and is
  now `auth_required`, a 403 without a challenge page used to be `upstream4xx` and is now
  `auth_rejected`, a 408 used to be `upstream4xx` and is now `ttfb_timeout`, and a status below
  200 or at 600 and above is now `protocol_drift` (it was `upstream4xx` or `upstream5xx`). A 429
  whose body reads as a challenge page is now `rate_limited` with its `Retry-After`, not
  `bot_waf`. Every other status keeps its kind.
- A domain the registry answers 404 for is a validated zero whose detail names the registry that
  answered, `not registered at https://rdap.verisign.com/com/v1/domain/example.com`, the last hop
  after a referral, as a registered domain's `record URL` detail does. It used to say `not
  registered with the registry the IANA bootstrap names`, which after a referral named the wrong
  registry.
