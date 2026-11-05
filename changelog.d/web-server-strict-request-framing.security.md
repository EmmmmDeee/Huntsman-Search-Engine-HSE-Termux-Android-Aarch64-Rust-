- The web server now answers 400 to a request that two HTTP parsers could frame differently:
  a header line with no colon, whitespace in a field name, a second `Host`, or a
  `Content-Length` that is repeated or not all digits (Rust's integer parser also took a
  leading `+`). Before, it skipped such lines or kept the first value. A body length near the
  integer limit no longer overflows the reader's bound.
