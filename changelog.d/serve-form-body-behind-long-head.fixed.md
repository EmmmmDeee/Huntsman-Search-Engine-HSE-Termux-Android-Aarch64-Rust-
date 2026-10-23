- `serve` reads a Settings form body of up to 25 KiB whole however long the request's head is.
  Head and body were cut at 33 KiB together, so a large key import sent behind a long `Cookie`
  header (which another local app on `127.0.0.1` can set) lost its end and was refused as larger
  than the limit it was within.
