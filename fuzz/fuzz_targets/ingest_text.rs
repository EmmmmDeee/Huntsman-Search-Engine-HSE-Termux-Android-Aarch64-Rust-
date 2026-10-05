//! `cargo-fuzz` target: the `hse ingest` text-extraction pipeline against
//! arbitrary bytes.
//!
//! The second fuzz target in this crate, and it covers a different threat than
//! `cert_der`. That one takes bytes off a TLS socket; this one takes a whole
//! *document* an operator pointed the tool at — a crawled page, a breach dump,
//! an OCR'd image, an imported file. Nothing upstream constrains those bytes,
//! and ingesting a hostile file must not be able to crash the tool.
//!
//! Why this surface specifically:
//!
//! - It is byte-index-sensitive. Confidence boosting slices a window of context
//!   around each match, and byte-slicing a multi-byte string is the classic way
//!   to panic on input someone else chose. `util::str_util::char_window` rounds
//!   both ends to a char boundary to prevent exactly that — unproven against
//!   inputs nobody thought to write down until now.
//! - Its extraction layer was rewritten wholesale in #350: the four
//!   length-specific hash regexes became one maximal-hex-token pass classified
//!   by exact length, and IPv6 extraction was added behind an
//!   `Ipv6Addr::from_str` gate plus a neighbour check. New parsing code over
//!   untrusted text is where a corpus earns its keep.
//! - `from_utf8_lossy`, not a UTF-8 validity gate, so the fuzzer reaches the
//!   replacement-character and multi-byte boundaries a valid-UTF-8-only corpus
//!   never generates. That mirrors what the real ingest path does.
//!
//! Run locally with:
//!
//! ```sh
//! mkdir -p corpus/ingest_text
//! printf 'a@b.com 2001:db8::1 5d41402abc4b2a76b9719d911017c592 @handle https://x.io' \
//!   > corpus/ingest_text/seed_mixed
//! cargo +nightly fuzz run ingest_text corpus/ingest_text
//! ```
//!
//! Seed into a throwaway `corpus/ingest_text/` rather than any directory in the
//! source tree: libFuzzer treats every directory on its command line as read
//! *and write*, saving newly-discovered inputs back into it, so pointing it at
//! real fixtures would litter them with generated files.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    huntsman_search_engine::util::entity_extractor::fuzz_entry_extract_text(data);
});
