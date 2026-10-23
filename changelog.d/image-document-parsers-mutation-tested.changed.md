- `exif` and `docmeta` are now tested against corrupted files. 3,000 corruptions each of a
  well-formed JPEG, TIFF, WebP and PNG with EXIF, and of an XMP-bearing JPEG and a PDF with an
  `/Info` dictionary, are each read or refused without a panic. The corruptions are a changed
  byte, a count or offset set to an extreme, a truncation, or a repeated stretch. The harness was
  checked by planting an unchecked slice in the EXIF reader, which it caught.
