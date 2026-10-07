# Phone Differential Fixture Provenance

Capability: `phone_offline`  
Oracle commit: `7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58`

The fixture in `tests/fixtures/differential/` is a deterministic offline oracle for the restored `phone_intl` and `phone_au` subset. It is intentionally narrower than the complete historical phone pipeline.

The selected inputs are anchored in the preserved legacy tests and module behavior:

- `legacy/hse-monolith-v1.41.0/src/modules/phone_au/tests.rs`
  - `0412 345 678` → canonical `+61412345678`, mobile.
  - `+61 2 9876 5432` and `(02) 9876 5432` → canonical `+61298765432`, fixed-line AU classification.
  - `0061 412 345 678` → AU national extraction `412345678`.
  - `+44 20 7183 8750` → rejected by the AU-specific module.
- `legacy/hse-monolith-v1.41.0/src/modules/phone_intl/tests.rs`
  - `+1 876 456 7890` → longest prefix `1876`, Jamaica.
  - `+44 20 7183 8750` → United Kingdom.
  - explicit `+` and `00` forms are accepted; ambiguous bare national numbers are not.

The golden records preserve only the legacy entity identity and source attribution required by the asymmetric comparator. Additional reconstructed evidence is allowed, but a legacy phone result may not disappear, shorten, or move to a different legacy source without an explicit reviewed exception.

This is a source-anchored deterministic oracle. It does **not** claim a live-provider receipt, restore `phone_geo`, or prove the entire historical phone capability.
