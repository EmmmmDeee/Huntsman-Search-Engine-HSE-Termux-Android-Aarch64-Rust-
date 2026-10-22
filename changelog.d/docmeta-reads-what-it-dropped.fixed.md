- `docmeta` reads the `/Info` dictionary a PDF's trailer names, from the object's newest
  definition, instead of the last `/Title` anywhere in the file: an outline bookmark or an
  incrementally added object is no longer reported as the document's title, an `/Info` held in a
  compressed object stream yields no guess, and an encrypted PDF's `/Info` is flagged as
  `pdf:Encrypted` instead of shown as ciphertext. The XMP scan reads every packet a file embeds,
  attributes on any element (the struct shorthand `xmpMM:History` events and `xmpMM:DerivedFrom`
  are written in, and the `x:xmptk` toolkit), the members of structured properties and
  `rdf:resource` values, where a typical Photoshop or GIMP packet previously yielded no field at
  all; a property stated more than once keeps each distinct value, so every history event's action,
  software agent and time survives, and disagreeing GPS positions assert no coordinates. A hostile
  packet is scanned in linear time: a 1 MiB packet of unclosed tags took minutes and now takes
  milliseconds.
- `docmeta` reveals what an edit retracted: when an incremental update replaced or removed a PDF
  `/Info` value, the superseded value still stored in the file is reported as `info-prior:Key`,
  and `pdf:InfoRevisions` counts the revisions read. The module now maps to ATT&CK T1589.003
  (authors) and T1592.002 (creator tools and history agents) besides T1591.001 (GPS).
