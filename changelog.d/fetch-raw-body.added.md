- `fetch URL --raw-body` writes only the response body's exact bytes, and only for a complete
  HTTP 200 that is not a challenge page, so a public source can be kept byte for byte.
  `scripts/termux-hybrid-evidence.sh` builds a private Termux evidence receipt on it.
