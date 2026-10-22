- `query` decodes each character reference in a result link once, as HTML reads it: a link holding
  `&#233;` keeps its path (as `é`) instead of being cut at the `#`, and `&amp;#38;` is the text
  `&#38;`, which starts the link's fragment, instead of being decoded a second time into `&`.
- `docmeta` reads XMP values by XML's rules. It decodes the five named entities and the numeric
  references to characters XML allows, so `&#169;` reads as `©` and the `&#xA;` a multi-line
  `dc:description` is written with becomes the line feed it stands for (escaped in the report,
  like every control character), where both were kept as written. `&nbsp;`, `&#X41;`, `&#+65;`,
  `&#0;` and `&#xD800;` stay as written. Whitespace a reference decodes to is trimmed from a
  value's ends as literal whitespace is, so a value ending in `&#xA;` keeps no line feed and a
  list item that is only `&#32;` is dropped.
