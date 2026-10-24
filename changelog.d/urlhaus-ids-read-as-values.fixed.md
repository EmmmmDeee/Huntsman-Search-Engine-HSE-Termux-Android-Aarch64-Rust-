- URLhaus (with `HUNTSMAN_ABUSECH_KEY`) reads a URL's id and the host's URL count the way every
  other source reads a provider value. A blank id left an empty item in `url_ids` (ids `""` and
  `121320` read `,121320`), and an id padded with spaces was kept beside the same id unpadded;
  both now read `121320`. A URL count padded with spaces (`" 120 "`) was ignored and replaced by
  the number of URLs listed; it is now read as 120.
