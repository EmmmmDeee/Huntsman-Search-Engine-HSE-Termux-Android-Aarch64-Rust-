- A file's embedded metadata can no longer exhaust a phone's memory. Since the `exif` and
  `docmeta` readers began turning the identifiers in metadata values into entities, a 4.1 MB file
  crafted to carry 301,368 distinct email addresses across 512 fields gave `docmeta` 301,369
  entities, a 1.26 GiB peak and 93 MB of output. The web inspect view, `investigate --file` and
  `reverse-image` read files the same way. Each reader now takes at most 256 such entities from one
  file and records how many more the file held as `metadata_identifiers_omitted` on the document
  entity. The same file now gives 257 entities and a 30 MiB peak, in 0.2 seconds instead of 4.2.
