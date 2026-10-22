- `docmeta` reads a PDF whose trailers are packed with `/Info` references in linear time: each
  reference was checked against every other, so sixteen 256 KiB trailers took minutes and a
  17 MB file over an hour, holding `serve`'s one inspection place all the while. The newest eight
  distinct references, all a report ever uses, are collected newest first instead.
- `exif` shares its 512 fields between the image, camera and GPS directories, so a first directory
  padded with junk tags no longer hides the capture time, serial numbers and GPS fields after it,
  and a file holding more fields says how many were not kept (`exif_fields_omitted`).
- A metadata value is bounded by the length it renders at, counting each escaped control
  character at the length of its escape, so a 14 KB TIFF of control bytes no longer renders a
  21 MB report. A long list of numbers shows whole numbers followed by its count, never a number
  cut part way through.
- A key save whose request ended before its head did is refused for that, not as a badly encoded
  form.
