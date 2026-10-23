- `docmeta` and `/api/inspect` read a PDF text string without a byte-order mark as
  PDFDocEncoding, as PDF 32000 defines it, so `/Author (Jos\351 Mu\361oz)` reads `José Muñoz`
  instead of `Jos� Mu�oz`, and the encoding's quotes, dashes and ligatures read as themselves.
  A string after PDF 2.0's UTF-8 mark, or valid UTF-8 written without one, still reads as UTF-8.
  A backslash before an end of line in a literal string joins the lines, as the format says,
  instead of keeping the line break.
