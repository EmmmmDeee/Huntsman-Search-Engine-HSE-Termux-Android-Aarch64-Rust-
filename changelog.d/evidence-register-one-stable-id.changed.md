- The evidence register and its matrix derive their record ids through one
  `evidence_register::stable_record_id` (prefix, then twenty hex digits of SHA-256 over kind, NUL,
  value) instead of two private copies; the `HSE-` and `HSE-MX-` ids are byte-for-byte unchanged
  and now pinned by a test.
