- `exif` reads a PNG's `eXIf` chunk, so the camera tags and GPS position a PNG embeds become
  evidence and a coordinates entity, in the CLI and in the Inspect tab; before, a PNG was refused
  as "not a JPEG, TIFF or WebP image" while `docmeta` documented the block as left to `exif`, so
  neither read it. A truncated chunk is reported as malformed, as for WebP. `exif` and `docmeta`
  now walk PNG chunks through one shared walker.
- The Inspect tab marks the tables as the previous file's whenever an attempt fails, including
  when the page refuses the file itself (none picked, or over 64 MiB); before, the last file's
  results stayed up unmarked beside the new file's name.
- Tests now pin `/api/inspect`'s real handler, which keeps `docmeta`'s findings when `exif` cannot
  read a file and merges the two into one document, and prove the upload gate refuses a head
  before reading its body: the previous test passed with the gate deleted.
- The PNG chunk walk is bounded by the file, not by a count of 4096 chunks: libpng writes 8 KiB
  `IDAT` chunks, so a PNG over about 34 MB with its `eXIf` or text chunks after its image data
  was reported as having none.
