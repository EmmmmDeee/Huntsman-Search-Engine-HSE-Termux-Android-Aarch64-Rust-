- People lookups and person scans match the name against the OFAC Specially Designated Nationals
  list (with its alias table) and the UN Security Council Consolidated List, keyless and kept on the
  device: each list is downloaded at most once a day through the threat feeds' download-and-keep
  machinery and matched locally, so a lookup sends nothing about who is looked up. A listing that
  carries every word of the name is a Document lead with its whole listing kept verbatim; a list that
  cannot be read is reported, never a clean zero.
- Fixed: a list or feed that is XML (it opens with its root element) was read as an HTML page served
  in its place and refused; a list may now declare its XML root.
