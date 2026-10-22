- `textnorm::find_ascii_ci` and `textnorm::rfind_word_ascii_ci`, which nothing called outside
  their own test. The one ASCII-case-insensitive search is now `value_syntax::find_ascii_ci`, over
  the byte-level `value_syntax::find_ascii_ci_bytes` that `web_query` and `scan_search` also use.
- `dnsbl::reversed`, which wrote the same labels as `dns::reverse_name` without its zone. Both
  now use `dns::reversed_labels`, and the names a blocklist is asked are unchanged.
