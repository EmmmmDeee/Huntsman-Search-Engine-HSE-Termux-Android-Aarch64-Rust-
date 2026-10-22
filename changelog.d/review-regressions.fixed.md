- `docmeta` reads a JPEG's ExtendedXMP whole: Photoshop splits an XMP packet that outgrew 64 KB
  (a long `photoshop:DocumentAncestors` list) across `APP1` segments, and each segment's header sat
  inside the packet text, so a split between list items dropped the whole list. The segments are
  cut out and each packet is rebuilt from its chunks in offset order, which also repairs splits
  inside a close tag and chunks stored out of order. `exif` and `docmeta` share one JPEG segment
  walker.
- An XML comment or processing instruction between an XMP list's items is skipped again rather
  than dropping the whole property (such as `dc:creator` or `dc:subject`).
- A PDF's trailer dictionaries each get their own scan window again: junk `trailer <<` lines, even
  inside stream data, could use up a shared budget before the cross-reference-stream trailer that
  names `/Info` was read. The newest 64 trailers kept are counted only among `trailer` lines that
  open a dictionary and `startxref` lines that give an offset, so text lines that start with the
  word "trailer" no longer push a linearized file's `/Info` trailer out.
- `serve` holds the one inspection place until an inspection's answer is written, freeing the file
  itself once the answer is built, and bounds that write by the upload's 90 s deadline: freeing the
  place early let slow readers hold many answers in memory at once. `exif` and `docmeta` now share
  one output bound (512 fields of at most 8 KiB each), so a 57 KB TIFF whose 4096 tags all render
  the same 8 KiB array of numbers no longer yields a report of some 235 MB.
