- An `inspect` scan no longer raises the MEDIUM correlation "high corroboration: 2 corroborating
  source(s) for document" on every file. `exif` and `docmeta` (and the APK readers) parse the
  bytes the operator supplied; two of them agreeing — even that a photo has *no* metadata — is one
  file read twice, not two sources observing an entity. They now count as one source and
  corroborate nothing, like the other offline readings, so a document's confidence and the AU-003
  rule rest only on sources that observed it. A real collector beside them still counts.
