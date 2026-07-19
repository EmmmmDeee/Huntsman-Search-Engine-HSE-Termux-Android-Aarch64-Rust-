//! `cargo-fuzz` target: `cert_intel`'s hand-rolled DER scanner against
//! arbitrary bytes (a live TLS peer certificate is fully attacker-controlled
//! — see `huntsman_search_engine::modules::cert_intel::fuzz_entry_parse_der`'s
//! own doc comment for the full rationale and history). Run locally with:
//!
//! ```sh
//! mkdir -p corpus/cert_der
//! cp ../src/modules/cert_intel/testdata/selfsigned.der corpus/cert_der/seed_selfsigned.der
//! cargo +nightly fuzz run cert_der corpus/cert_der
//! ```
//!
//! Seed from the project's existing real-certificate fixture rather than a
//! duplicated corpus (`docs/CONVENTIONS.md` §3, single-sourced data) — but
//! copy it into `corpus/cert_der/` first, never pass
//! `../src/modules/cert_intel/testdata` itself as the corpus argument:
//! libFuzzer treats every directory on its command line as read *and write*
//! (it saves newly-discovered inputs back into it), so fuzzing against the
//! source fixture directory in place would litter it with generated files.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    huntsman_search_engine::modules::cert_intel::fuzz_entry_parse_der(data);
});
