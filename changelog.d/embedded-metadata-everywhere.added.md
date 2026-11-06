- A file's embedded metadata is read the same way everywhere a file comes in: the `exif` and
  `docmeta` commands, the web UI's inspect view, `investigate --file` and `reverse-image`. Beside
  the fields, the document entity and the GPS position the two readers already gave, every email
  address, link, domain, IP address or phone number written into a field people write (an author,
  rights, contact, comment or description field) now becomes an entity of its own, attributed to
  the file and the field it was written in, so it pivots like any other lead. A value a camera or
  a program writes for itself (a serial number, an identifier, a version string, a time, its edit
  history) is read only for an email address or a link: a lens serial number or Adobe's
  `x:xmptk` toolkit version is never taken for a phone number. Metadata is only read, never
  removed or rewritten.
- The `exif` reader shows the text people write into a picture that is not stored as ASCII: a
  `UserComment` by its character code (UCS-2 in the block's byte order or its byte-order mark,
  ASCII, or undefined read as UTF-8) and Windows' `XPTitle`, `XPComment`, `XPAuthor`,
  `XPKeywords` and `XPSubject` (UCS-2), where it used to show their bytes in hex. It also names
  `ImageUniqueID`, `OffsetTime*`, `SubSecTime*`, `ImageTitle`, `Photographer` and `ImageEditor`.
- `investigate --file` now reads a photo, a PDF or any other file that is not text, up to 64 MiB,
  for its embedded metadata, where it used to refuse anything that was not UTF-8. A text file is
  read as before, and for its embedded metadata too when it carries any; a text file over 1 MiB is
  still refused.
