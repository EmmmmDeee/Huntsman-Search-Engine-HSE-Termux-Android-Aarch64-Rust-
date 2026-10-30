- A phone number now has one canonical form everywhere it is read: a scan's selector, the
  entities its sources report, the classifier and RDAP contacts. `phone_intl::canonicalize`
  (used by scans and `phone`) and `value_syntax::canonical_phone` (used by entity keys, the
  classifier and the RDAP legs) were two rules that disagreed:
  - A number written with a `00` international prefix (`0044 20 7946 0958`) was `+442079460958` as a
    selector, but an observed copy of it kept its raw spelling as its key, so one number became
    two phone entities and was never corroborated.
  - A number with an extension (`+1 415 555 2671 ext 22`) was joined into a made-up number
    (`+1415555267122`) and saved as a phone. It is now refused, as a scan already refused it.
  - A `+61` number that Australia's numbering plan cannot hold is refused by both, instead of
    being accepted as a generic international number by scans.
  - A number written after Australia's `0011` international prefix (`0011 44 20 7946 0958`) is
    `+442079460958`; a scan read it as the made-up `+11442079460958`.
  - A `+1` number must have the North American plan's ten digits after the `1`, so a
    zero-padded identifier (`001234567890`) is no phone, and two numbers run together
    (`+44 +1 415 555 2671`) are refused rather than joined.
  `value_syntax::canonical_phone` is the rule, and `phone_intl::canonicalize` calls it.
