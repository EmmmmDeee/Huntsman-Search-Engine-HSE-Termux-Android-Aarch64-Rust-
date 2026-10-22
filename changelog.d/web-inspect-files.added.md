- The web UI's **Inspect** tab reads a file picked on the phone through `POST /api/inspect`: the
  `exif` and `docmeta` parsers the CLI commands use, keyless and offline, as one report of the
  file's EXIF tags, XMP fields and edit history, PDF `/Info` with the values an edit replaced, PNG
  text chunks and any embedded GPS position, which **Investigate** prefills as a network scan
  without starting it. The route is guarded like a lookup and checks every request's head before
  reading its body, so only one upload of at most 64 MiB is held in memory at a time.
