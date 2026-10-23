# Public-business OSINT case evidence gate

This phase makes case inputs independently auditable without creating a second network stack. The offline command:

~~~sh
huntsman-recon case-check examples/vero-case-evidence.json examples/vero-case-advert.txt
~~~

reads at most 256 KiB of JSON and 16 KiB of original text. The original text must match all three recorded values: byte length, literal text, and SHA-256. The verifier requires unique source/claim IDs, resolvable claim references, an ORIGINAL provenance entry, and an official registry-type source for any claim classified verified_primary_record. It retains unverified, not_stated, and inference_not_verified claims as unresolved.

The example input originates from the user-supplied Bendigo recruitment advertisement, which did not supply a year, original posting URL or posting timestamp. A Thursday 8 October calendar match cannot establish a year. The case describes claims about Vero Investigation Group's corporate identity and published contacts, but the sample fixture is not an independent verification of the claimed business facts.

## Boundaries and adverse cases

- Exact source text is preserved. A different newline, encoding or advertisement text fails the hash.
- Source identifiers are metadata, not self-authenticating evidence; a malicious file can forge both data and hash. This is an integrity and referential-consistency gate, not cryptographic attestation of provenance.
- A verified_primary_record claim requires a source labelled government_registry or government_holder_record, but labels in JSON are not authoritative. Check the actual government record independently and retain its capture time.
- A government guidance page does **not** count as a holder-specific licence verification.
- No licence, employment biography, author identity, surveillance activity or assignment year is affirmed by passing this gate.
- Input files are local; this command neither makes network requests nor reads credentials.
- The collector in the previous standalone package used external curl; that implementation has deliberately **not** been imported into Huntsman's rootless Rust runtime. Future live collection must reuse the existing guarded HTTP transport and its egress policy, not shell out.
- This command does not schedule or execute unattended collection. A dedicated, authorised periodic workflow would require a separate implementation and live acceptance tests.

## Acceptance

Run from the checkout:

~~~sh
cargo run --locked -- case-check examples/vero-case-evidence.json examples/vero-case-advert.txt
cargo test --locked
cargo run --locked -p xtask -- gate full
~~~

For changes affecting Android, require Android cross-build CI and the real-device Termux acceptance harness from docs/REPAIR_PROTOCOL.md. The host gate alone is not handset proof.
