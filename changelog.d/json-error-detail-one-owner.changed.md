- The text a decode failure reports for a provider body that is not the documented JSON shape —
  the serde error's category and position, never its message, which can quote the body — comes
  from one `fetch::json_error_detail` for every source. OATHNET, WiGLE and the stolen-tax lookup
  each had a verbatim private copy; they now delegate, and their messages are unchanged.
