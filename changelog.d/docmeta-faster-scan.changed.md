- `docmeta` scans a file for its markers eight bytes at a time and reads a PDF's trailers once,
  so a 60 MB PDF is read in about 100 ms instead of 800 ms (x86 release build; a phone is slower
  by the same factor), and no input is slower than before. Dependency-free, safe Rust.
