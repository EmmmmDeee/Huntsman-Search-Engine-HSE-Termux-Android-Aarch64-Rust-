# Rhinser Drive specification reconciliation

## Source identity

The user-provided Drive specification is `HSE_RHINSER_SCHEMA_INTEGRATION.md`,
file ID `1XZIidvx5HnUV8ACo905rlFScBhxNHXhh`. Its Rust blocks are proposed
pseudocode, not executable source or evidence of implemented capabilities.
The Drive file `https://www.dro.txt` points to a Dropbox transfer that the
connector could not resolve. The three originals were recovered separately
from the connected Dropbox account on 3 November 2026 (Australia/Brisbane).

Downloaded bytes independently match the existing parity ledger:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| rhinse-osint.apk | 5378708 | e6be6b6bbff2128cf72a34d1a64d25fbaf7c121a0ce803e60e45bdb97f363036 |
| Rhinser.apk | 223156 | 6a41162f2cf1d59a8689c01a685cd6cde06752c57a02b7177ef009bed7c9593a |
| RHINSE-SCAN-DETECT.apk | 33870 | 30833ef95b4f504cd4db0919bfc5dc6743590d9e33d25ed424fc1cb1d42d68c4 |

ZIP inspection found 908, 25 and 17 members respectively. This is byte and
archive verification, not Android execution or complete method-body analysis.
The OSINT APK's catalogue has 11 categories and 83 tools. All original tool IDs
are retained in Huntsman; URL and query-template changes require separate review.
An entry in the directory is not a functioning collector.

## Requirements and evidence boundaries

| Drive proposal | Canonical implementation or disposition |
| --- | --- |
| Bluetooth/NFC imports | `rhinser_native`: bounded operator-submitted fixtures; no sensor authentication |
| APDU/NDEF inspection | Reuse `rhinser_nfc`; no radio access or payload export |
| BER-TLV saved captures | Route the `tlv` capture event to `rhinser_tlv::inspect_tlv`, the same parser as the direct CLI |
| Cases, notes, bookmarks and settings | Reuse `rhinser_workspace`; browser editing is still incomplete |
| Public-source directory | Reuse `rhinser_catalog` and its existing authenticated browser endpoint |
| Ownership, pairing and exact distance | Do not derive these facts from proximity, MAC prefixes, names or RSSI |
| Breach/merchant history and risk scores | Require separately retrieved, attributable evidence; example values are not observations |
| Cryptographic confidence | A supplied cryptogram does not verify a card, holder or transaction; no fixed proof score |
| Android NFC/Bluetooth callbacks | Requires an independently permissioned companion and physical rootless-device verification |
| Card writing/emulation and remote execution | No implementation or parity assertion in this read-only import change |

The capture envelope remains explicitly unverified, even when syntax validation
succeeds. A TLV event reports only tag structure, preserving the existing parser's
8192-byte, 128-field and nesting limits. Malformed input rejects the whole capture.
No database, async runtime, new dependency, runtime LLM or root privilege is added.

See `RHINSER_FUNCTIONAL_PARITY.md` for the broader parity ledger. Neither this
reconciliation nor a passing fixture closes the original application's remaining
Android, UI, hardware or evidence-source verification requirements.
