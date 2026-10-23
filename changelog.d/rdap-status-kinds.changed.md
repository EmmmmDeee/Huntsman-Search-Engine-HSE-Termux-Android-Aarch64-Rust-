- The rdap outcome row now types an HTTP status the way every other source does. A registry's
  401 used to be `upstream4xx` and is now `auth_required`, a 408 used to be `upstream4xx` and is
  now `ttfb_timeout`, and a status below 200 or at 600 and above is now `protocol_drift`
  (it was `upstream4xx` or `upstream5xx`). Every other status keeps its kind.
