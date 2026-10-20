- Reject saved-scan stop requests for foreign or unknown process owners with an
  explicit conflict before changing the scan row or local cancellation state.
  Cross-process cancellation remains unsupported; local worker stops are unchanged.
