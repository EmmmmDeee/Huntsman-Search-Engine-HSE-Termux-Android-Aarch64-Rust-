use super::*;

    #[test]
    fn extract_addresses_never_panics_on_multibyte_after_reconstructed_address() {
        // Regression: the postcode-lookahead reconstructs the address as
        // "City, State" (a ", " separator), so when the source text used
        // different punctuation the string is NOT a literal substring and
        // `find` returns None. The old `unwrap_or(0) + r.len()` fallback then
        // indexed at a byte offset (18) unrelated to the text — here it lands
        // inside the 3-byte '€', slicing mid-codepoint and panicking. The
        // address itself is still extracted; only the (skipped) postcode
        // lookahead differs.
        let addrs = extract_addresses_from_text("Nundah,Queensland€xx");
        assert!(
            addrs.iter().any(|a| a == "Nundah, Queensland"),
            "address still extracted, no panic: {addrs:?}"
        );

        // The real-world payload that crashed a live scan: an en-dash (U+2013)
        // in a SOHO real-estate page title. Must not panic.
        let _ = extract_addresses_from_text(
            "SOHO Galleries – Sydney Art Gallery, New South Wales and beyond",
        );

        // Positive path intact: a clean address with a trailing postcode still
        // gains the postcode-qualified variant.
        let with_pc = extract_addresses_from_text("Lives in Gatton, QLD 4343 now");
        assert!(
            with_pc.iter().any(|a| a == "Gatton, QLD 4343"),
            "postcode still attaches on clean input: {with_pc:?}"
        );
    }
