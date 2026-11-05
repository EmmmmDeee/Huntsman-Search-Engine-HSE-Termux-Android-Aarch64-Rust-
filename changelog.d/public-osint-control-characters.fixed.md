- The public news and notices searches drop a result whose URL or title holds a control
  character, or whose title is only whitespace, and a reply left with no usable result is
  schema drift, not an empty answer. A news reply that reports a nonzero total but lists no
  articles is schema drift too, as it already was for notices, where before it read as a
  verified zero. Web-search hits with a control character in the URL are dropped as well.
