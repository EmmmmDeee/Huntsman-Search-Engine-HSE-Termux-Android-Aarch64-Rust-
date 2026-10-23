- A correlation rule file's folded strip scalar (`>-`) whose last line is indented more than the
  first, such as `headline: >-` over `  Open port` and `    {source.data}`, no longer ends in a
  newline. It used to read as `"Open port\n  {source.data}\n"`; it now reads as
  `"Open port\n  {source.data}"`, as PyYAML reads Spiderfoot's rules. This changes a string
  headline, a headline object's text and an `exact` or `regex` method value. Meta names and
  descriptions were already trimmed.
