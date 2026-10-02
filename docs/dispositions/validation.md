| legacy path | lines | decision | new module | defect found / evidence or reason |
| --- | ---: | --- | --- | --- |
| core/validation/confusable.rs | 263 | MERGED | src/validation.rs | Rebuilt invisible-strip, skeleton, mixed-script, and gibberish checks; merged the pairwise lookalike primitives from util/confusable here so the duplicate confusable logic cannot drift again. |
| core/validation/domain.rs | 40 | MERGED | src/validation.rs | Rebuilt `is_onion_url` on the shared host parser instead of a standalone string split. |
| core/validation/email.rs | 112 | MERGED | src/validation.rs, src/identity.rs, src/domains.rs | Role-mailbox detection now delegates to the shared local-part authority; canonical email/domain handling is merged into `identity.rs`. |
| core/validation/ip.rs | 209 | MERGED | src/validation.rs | Rebuilt reserved/documentation/bogon and CDN-edge gates, including IPv4-mapped IPv6 parity. |
| core/validation/mod.rs | 56 | REBUILT | src/validation.rs | Reassembled the offline validation surface without the monolith's `EntityKind` dependency by using a local `ValueKind`. |
| core/validation/phone.rs | 195 | MERGED | src/validation.rs, src/address_au.rs, src/identity.rs | Rebuilt strict E.164 validation plus AU canonicalisation delegation; keeps foreign E.164 intact and merges canonical phone handling into `identity.rs`. |
| core/validation/placeholder.rs | 387 | MERGED | src/validation.rs | Rebuilt placeholder/privacy/fragment/residence gates as one offline authority. |
| core/validation/report.rs | 29 | MERGED | src/validation.rs | `ValidationReport` rebuilt unchanged in spirit. |
| core/validation/tests.rs | 605 | MERGED | src/* module tests | Ported representative regression and differential assertions into the rebuilt modules' unit tests instead of copying the monolith's entity-path test file verbatim. |
| util/confusable.rs | 136 | MERGED | src/validation.rs | Rebuilt homoglyph skeleton, Levenshtein distance, and lookalike detection. |
| util/phone/mod.rs | 58 | MERGED | src/validation.rs | Rebuilt `scan_phones` as the shared E.164 scanner. |
| util/domains/mod.rs | 694 | REBUILT | src/domains.rs | Kept the curated multi-label suffix table (explicit PSL decision) and rebuilt the pure domain/freemail/role/platform/VN/DNS helpers. |
| util/domains/tests.rs | 454 | MERGED | src/domains.rs tests | Ported representative invariants and regression cases. |
| util/url_util/mod.rs | 117 | MERGED | src/domains.rs | Rebuilt absolute-HTTP, host extraction, and tracking-parameter gates in the shared domain helper module. |
| util/url_util/tests.rs | 118 | MERGED | src/domains.rs tests | Ported representative host/query/IPv6/tracking assertions. |
| util/str_util/mod.rs | 654 | REBUILT | src/textnorm.rs | Rebuilt the pure text/UTF-8/ASCII folding helpers without extra dependencies; substituted loop-based invariant tests for the monolith's memchr/proptest setup. |
| util/str_util/tests.rs | 446 | MERGED | src/textnorm.rs tests | Ported representative unit and invariant checks. |
| util/bsb/mod.rs | 137 | MERGED | src/au_id.rs | Existing rebuilt BSB logic retained; longest-prefix institution table already matched the monolith's pure capability. |
| util/abn/mod.rs | 296 | MERGED | src/au_id.rs | Added the missing company-form and owner-splitting helpers to the existing ABN/ACN/BSB module. |
| util/abn/tests.rs | 224 | MERGED | src/au_id.rs tests | Ported representative company and identifier assertions. |
| util/address_au/mod.rs | 971 | REBUILT | src/address_au.rs | Rebuilt the pure AU address/state/postcode/phone/domain/network helpers without regex/AC automata dependencies; preserved the documented postcode, line-type, and domain-state fixes. |
| util/address_au/tests.rs | 650 | MERGED | src/address_au.rs tests | Ported representative address, postcode, phone, domain, and operator regressions. |
| util/postcode_au/mod.rs | 266 | REBUILT | src/postcode_au.rs | Rebuilt the pure JSON parser, offline gazetteer centroid lookup, and shape gate, then migrated the newly in-scope postcode fetch path onto the shared `crate::http::{Request, Response, Transport}` boundary. |
| util/postcode_au/tests.rs | 148 | MERGED | src/postcode_au.rs tests | Ported representative parse/offline-centroid/shape assertions. |
| util/uid/mod.rs | 23 | REBUILT | src/uid.rs | The current crate has no `core::entity::scan_id`; rebuilt a unique 64-hex SHA-256-based scan-id helper with time+counter mixing. |
| util/uid/tests.rs | 24 | MERGED | src/uid.rs tests | Ported the legacy shape/uniqueness assertions. |
| util/domain_vn/mod.rs | 101 | MERGED | src/domains.rs | Rebuilt the VN registrant classifier with the shared AU category vocabulary. |
| util/domain_vn/tests.rs | 100 | MERGED | src/domains.rs tests | Ported representative VN suffix cases. |
| util/dns.rs | 224 | REBUILT | src/dns.rs | Kept the pure label/RNAME helpers and moved the runtime resolver path onto the shared `crate::http::Transport` boundary with ordered DoH failover across Cloudflare/Quad9/Google so the newly in-scope path stays separately unit-testable. |
| core/xml.rs | 53 | REBUILT | src/xml.rs | Rebuilt the one-pass XML escaper that drops XML-illegal controls instead of double-escaping or preserving them. |

Policy-change note (network/credentials now allowed):
- Newly in scope and rebuilt behind injectable boundaries:
  - `util/postcode_au` online postcode lookup path via `src/postcode_au.rs::localities_with` on `crate::http::Transport`
  - `util/dns` resolver-pool/failover path via `src/dns.rs::{resolver_config, resolve_with_pool}` on `crate::http::Transport`
- Pure parsing, scoring, and policy remain separately unit-testable; tests use fakes and do not perform live network calls.
- No credential values are logged or embedded in tests/artifacts; these boundaries carry plain request/response data only.
- Redundancies removed during the shared-HTTP refactor: identity/email/phone canonicalisation now delegates to the shared canonical/validation owners; postcode shape/range checks now live in `src/postcode_au.rs`; DNS label/RNAME helpers now live only in `src/dns.rs`.
