- `docmeta` reads a PDF through one lexer that knows literal strings, hex strings and `%`
  comments, so a trailer key written inside a string or comment is not a key: an `/Encrypt` there
  no longer flags the file encrypted and hides its `/Info`, a forged `/Info N G R` there no longer
  takes over the current `info:*` values or invents `info-prior:*` revisions, and a `>>` or `(` in
  a comment no longer cuts a dictionary short or swallows it. Only a dictionary's top-level keys
  count. The trailer pass reads the newest 64 `trailer` and `startxref` keywords within one scan
  budget, so a file of countless unclosed `trailer <<` is read in linear time (about 860 KB of them
  took 13 s before; 4 MiB now takes milliseconds) and the real trailer after them still decides.
- `docmeta` reads an XMP list by walking its children in order and stops at the first one that is
  not a text `rdf:li`, so a packet of lists that are never itemised before one distant close is
  read in linear time: a 1 MiB such packet took 21 s in a debug build and now takes milliseconds.
  The memoised close-tag searches this made unnecessary are gone.
