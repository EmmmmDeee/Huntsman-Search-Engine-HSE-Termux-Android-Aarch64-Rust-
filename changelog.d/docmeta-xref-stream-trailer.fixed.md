- `docmeta` reads the `/Info` of a PDF 1.5+ file that writes its trailer as a cross-reference
  stream (no `trailer` keyword), which reported no `/Info` at all once `/Info` and `/Encrypt`
  were scoped to explicit trailers. Only the `/Type /XRef` dictionary a `startxref` offset points
  at counts, so an object that merely looks like one still selects nothing.
