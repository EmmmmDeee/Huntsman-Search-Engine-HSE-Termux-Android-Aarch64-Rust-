- `apk FILE` and the offline APK-upload API no longer crash on a crafted signing certificate whose
  validity time holds a multi-byte character where the year's digits belong (a `UTCTime` such as
  `1é101000000Z`). Reading the year sliced the text by bytes, through the middle of the character,
  and panicked. A certificate time is now read only when it is ASCII digits and a `Z`; any other
  time is left out as unreadable, as a malformed one already was. A regression test in
  `src/apk_intel/signer.rs` panics on the previous code.
- One rule for each shared check, with no change in behaviour:
  - coordinates go through `geohash::valid_coordinate`, or the new `geohash::valid_fix` when a
    device writes (0, 0) for no fix;
  - certificate OIDs go through `x509::oid_text`;
  - calendar months go through `timefmt::month_days`;
  - bounded query and record text goes through `textnorm::is_bounded_text`;
  - host-in-domain checks go through `domains::is_or_subdomain_of` and `is_proper_subdomain_of`;
  - hex rendering goes through `base64::base16_lower` and `base16_upper`.

  Each replaces a copy of the same logic in the module that used it.
