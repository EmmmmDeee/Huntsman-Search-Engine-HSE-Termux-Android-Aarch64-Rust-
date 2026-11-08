- The XposedOrNot breach lookup now also surfaces public paste exposure from the same keyless
  response: an address that appears only in public pastes (no breach) is reported as exposure with
  a paste_count, where before it read as a clean zero. When both are present, the finding names the
  breach and paste counts. No extra request and no paste content is kept — only the documented
  count. The existing breach output is unchanged.
