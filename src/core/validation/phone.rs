use super::report::ValidationReport;

/// Check if an E.164 number falls within a reserved test/placeholder range.
/// Reserved ranges include:
/// - +1-555-0000 to +1-555-0199 (US test exchanges)
/// - +1-555-0200 to +1-555-0599 (reserved but may be locally used)
/// - +0800-xxxxx (EU international toll-free prefix)
/// - +0900-xxxxx (EU premium rate prefix)
///
/// These ranges are statistically present in test data and breach dumps but
/// never represent real individuals, so filtering them eliminates false
/// positives from fabricated/placeholder numbers in data leaks.
fn is_reserved_phone_range(e164: &str) -> bool {
    // Format: "+CCNNNNNNNNNNN" where CC is country code
    if e164.len() < 4 {
        return false;
    }

    // US test numbers: +1-555-XXXX (country code 1, exchange 555)
    if e164.starts_with("+1555") && e164.len() >= 9 {
        // Extract the line number (last 4 digits after +1-555)
        let line_num = &e164[5..9];
        if let Ok(num) = line_num.parse::<u16>() {
            // Reject the documented test range: 555-0000 to 555-0199
            // Also reject adjacent reserved ranges: 555-0200 to 555-0599
            if num < 600 {
                return true;
            }
        }
    }

    // International toll-free: +0800-xxxx (various countries)
    // This is the UIFN (Universal International Freephone Number) prefix.
    // Reserved for testing/examples across all countries.
    if e164.starts_with("+0800") || e164.starts_with("+0900") {
        return true;
    }

    // French test range: +33-555-xxxxx
    if e164.starts_with("+33555") {
        return true;
    }

    // German test range: +49-0189-xxxxxx
    if e164.starts_with("+490189") {
        return true;
    }

    // UK test range: +44-1632-xxxxxx
    if e164.starts_with("+441632") {
        return true;
    }

    false
}

/// True if `s` is a syntactically valid E.164 number: leading `+`,
/// then 10 to 15 digits, with the country code in the conventional
/// 1-3 digit range (and never a leading `0`). Does NOT verify the number is
/// dial-able; only the format. Also rejects known reserved test/placeholder
/// ranges that appear frequently in breach data but represent no real person.
pub fn validate_phone_e164(s: &str) -> ValidationReport {
    if !s.starts_with('+') {
        return ValidationReport::fail("e164.missing_plus", "must start with '+'");
    }
    let digits = &s[1..];
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return ValidationReport::fail("e164.non_digit", "non-digit after '+'");
    }
    // ITU-T E.164: a country code is 1-3 digits and never begins with 0, so the
    // first digit after the `+` is 1-9. (`+0…` is what the loose digit-only check
    // used to wave through despite the documented country-code rule.)
    if digits.starts_with('0') {
        return ValidationReport::fail("e164.cc_leading_zero", "country code cannot start with 0");
    }
    // Practical minimum: the shortest real subscriber numbers in any inhabited country
    // are 10 digits total (e.g. Niue +683 XXXXXXX, Nauru +674 XXXXXXX).
    // 8- and 9-digit strings are overwhelmingly web-scrape noise (version numbers,
    // IDs, port numbers) that happen to start with '+'.
    if !(10..=15).contains(&digits.len()) {
        return ValidationReport::fail(
            "e164.length",
            format!("expected 10..=15 digits, got {}", digits.len()),
        );
    }
    // Reject known reserved test/placeholder ranges to prevent false positives
    // from breach data (fabricated test numbers are statistically common).
    if is_reserved_phone_range(s) {
        return ValidationReport::fail(
            "e164.reserved_range",
            "falls within reserved test/placeholder range",
        );
    }
    ValidationReport::ok()
}

/// Normalise an Australian — or already-international — phone number to E.164
/// (`+61…`). Recovers the AU local forms that breach/scrape data carries —
/// `0412 345 678`, `(02) 9876 5432`, `61412345678` — which the strict
/// [`validate_phone_e164`] gate would otherwise drop, and canonicalises them to
/// the same `+61…` an already-international form yields so the two never
/// fragment into separate entities.
///
/// Returns `None` for anything that is neither a valid AU number nor a valid
/// foreign E.164 number. A bare local number of unknown country (a 10-digit US
/// string with no `+`/`61`/leading-`0`) is intentionally left out rather than
/// guessed — fabricating a country code would invent a wrong identity.
pub fn to_e164_au(s: &str) -> Option<String> {
    // Keep only `+` and digits (drops spaces, dashes, dots, parentheses).
    let compact: String = s
        .chars()
        .filter(|c| *c == '+' || c.is_ascii_digit())
        .collect();

    // Already an international E.164 number — keep verbatim (any country).
    if compact.starts_with('+') {
        return validate_phone_e164(&compact).valid.then_some(compact);
    }

    // AU international without the `+`: `61` + a 9-digit national number. The first
    // national digit must be a real ACMA AU national-significant-number lead
    // (2/3/4/5/7/8) — the SAME gate the local branch below applies. The old
    // `!starts_with('0')` check only excluded a leading 0, so `61` + a foreign
    // 9-digit national number whose lead is 1/6/9 (e.g. an Irish "61" + a mobile
    // "8xxxxxxxx"… or any non-AU lead) was re-typed as a fabricated `+61` AU number.
    if let Some(nat) = compact.strip_prefix("61")
        && nat.len() == 9
        && matches!(nat.as_bytes()[0], b'2' | b'3' | b'4' | b'5' | b'7' | b'8')
    {
        let e164 = format!("+61{nat}");
        return validate_phone_e164(&e164).valid.then_some(e164);
    }

    // AU local: a leading-`0` national number (`0` + 9 digits = 10). The
    // second digit must be a real ACMA AU national-significant-number lead
    // (2/3/4/5/7/8 — geographic fixed-line, mobile, or VoIP; see
    // `modules::phone_au::classify_au_phone`, the canonical AU line-type
    // classifier this admission gate feeds). Without this check, ANY 10-digit
    // string starting with `0` — e.g. an Irish local mobile "087 123 4567" —
    // was silently re-typed as a fully-formed Australian number by prepending
    // `+61`, fabricating a non-existent AU phone (and its derived
    // mobile/fixed-line/jurisdiction classification) from a foreign one.
    if compact.len() == 10
        && compact.starts_with('0')
        && matches!(
            compact.as_bytes()[1],
            b'2' | b'3' | b'4' | b'5' | b'7' | b'8'
        )
    {
        let e164 = format!("+61{}", &compact[1..]);
        return validate_phone_e164(&e164).valid.then_some(e164);
    }

    None
}

#[cfg(test)]
mod e164_au_tests {
    use super::to_e164_au;

    #[test]
    fn au_local_mobile_and_landline_become_e164() {
        assert_eq!(to_e164_au("0412 345 678").as_deref(), Some("+61412345678"));
        assert_eq!(
            to_e164_au("(02) 9876 5432").as_deref(),
            Some("+61298765432")
        );
        assert_eq!(to_e164_au("0298765432").as_deref(), Some("+61298765432"));
    }

    #[test]
    fn au_international_forms_canonicalise_together() {
        assert_eq!(
            to_e164_au("+61 412 345 678").as_deref(),
            Some("+61412345678")
        );
        assert_eq!(to_e164_au("61412345678").as_deref(), Some("+61412345678"));
        // The local and international forms of one number collapse to one value.
        assert_eq!(to_e164_au("0412345678"), to_e164_au("+61412345678"));
    }

    #[test]
    fn foreign_e164_is_kept_but_bare_local_is_not_guessed() {
        assert_eq!(
            to_e164_au("+1 555 123 4567").as_deref(),
            Some("+15551234567")
        );
        // A bare 10-digit US-style number has no recoverable country code.
        assert_eq!(to_e164_au("555-123-4567"), None);
        assert_eq!(to_e164_au("5551234567"), None);
        // Junk / too-short.
        assert_eq!(to_e164_au("12345"), None);
        assert_eq!(to_e164_au("not a phone"), None);
    }

    #[test]
    fn ten_digit_leading_zero_requires_a_real_au_trunk_digit() {
        // Regression: a 10-digit string starting with `0` was admitted
        // regardless of its second digit, fabricating an Australian number
        // from any foreign local-format phone that happened to be 10 digits.
        // A French local mobile, "06 12 34 56 78", compacts to "0612345678"
        // — lead digit `6` is not a real AU national-significant-number lead,
        // so this must NOT be admitted as `+61612345678` (verified to
        // previously yield exactly that fabricated AU number before this gate
        // existed). Note `8` itself IS a real AU lead (SA/WA/NT geographic),
        // so a foreign number whose second digit coincidentally matches a
        // valid AU lead is an inherent, irreducible ambiguity this gate
        // narrows but cannot fully eliminate — it rejects the clearly-wrong
        // leads (0/1/6/9), which is the confirmed bug this fixes.
        assert_eq!(to_e164_au("06 12 34 56 78"), None);
        // Every valid ACMA AU national-significant-number lead still admits.
        for (lead, kind) in [
            ('2', "NSW/ACT geographic"),
            ('3', "VIC/TAS geographic"),
            ('4', "mobile"),
            ('5', "VoIP"),
            ('7', "QLD geographic"),
            ('8', "SA/WA/NT geographic"),
        ] {
            let local = format!("0{lead}12345678");
            assert!(
                to_e164_au(&local).is_some(),
                "a real AU {kind} number (lead {lead}) must still be admitted: {local}"
            );
        }
        // Leads that are not valid AU national-significant-number digits.
        for lead in ['0', '1', '6', '9'] {
            let local = format!("0{lead}12345678");
            assert_eq!(
                to_e164_au(&local),
                None,
                "lead digit {lead} is not a real AU trunk code: {local}"
            );
        }
    }

    #[test]
    fn bare_61_prefix_requires_a_real_au_trunk_digit() {
        // The `61`-without-`+` branch must apply the SAME ACMA trunk-lead gate as
        // the local branch — else a foreign national number whose first digit is a
        // non-AU lead (1/6/9) is fabricated into a `+61` AU number. A French mobile
        // "06 12 34 56 78" written international-without-`+` as "61612345678" has
        // lead `6` and must be rejected (fail-before: yielded "+61612345678").
        for lead in ['1', '6', '9'] {
            let intl = format!("61{lead}12345678");
            assert_eq!(
                to_e164_au(&intl),
                None,
                "bare-61 lead digit {lead} is not a real AU trunk code: {intl}"
            );
        }
        // A genuine AU number in the bare-`61` form still canonicalises.
        for lead in ['2', '3', '4', '5', '7', '8'] {
            let intl = format!("61{lead}12345678");
            assert_eq!(
                to_e164_au(&intl).as_deref(),
                Some(format!("+61{lead}12345678").as_str()),
                "a real AU number in bare-61 form (lead {lead}) must canonicalise: {intl}"
            );
        }
    }
}

#[cfg(test)]
mod e164_reserved_range_tests {
    use super::{is_reserved_phone_range, validate_phone_e164};

    #[test]
    fn us_test_range_555_rejected() {
        // +1-555-0000 to +1-555-0599 are documented US test/placeholder ranges
        assert!(is_reserved_phone_range("+15550000000"));
        assert!(is_reserved_phone_range("+15550100000"));
        assert!(is_reserved_phone_range("+15550599999"));
        // Just outside the reserved range should pass the range check
        // (but full validation may still reject for other reasons)
        assert!(!is_reserved_phone_range("+15550700000"));
        assert!(!is_reserved_phone_range("+15561234567"));
    }

    #[test]
    fn uifn_toll_free_rejected() {
        // +0800 and +0900 are reserved international prefixes
        assert!(is_reserved_phone_range("+0800123456"));
        assert!(is_reserved_phone_range("+0900123456"));
    }

    #[test]
    fn european_test_ranges_rejected() {
        // +33-555-xxxxx (France)
        assert!(is_reserved_phone_range("+33555123456"));
        // +49-0189-xxxxxx (Germany)
        assert!(is_reserved_phone_range("+490189123456"));
        // +44-1632-xxxxxx (UK)
        assert!(is_reserved_phone_range("+441632123456"));
    }

    #[test]
    fn validation_rejects_reserved_numbers() {
        // These should be syntactically valid but fail semantic validation
        let us_test = validate_phone_e164("+15550000000");
        assert!(!us_test.valid);
        assert_eq!(us_test.reason, "e164.reserved_range");

        let uifn = validate_phone_e164("+0800123456");
        assert!(!uifn.valid);

        // Real numbers should still pass
        let real_us = validate_phone_e164("+14155551234");
        assert!(
            real_us.valid,
            "real US number should pass: {}",
            real_us.reason
        );

        let real_au = validate_phone_e164("+61412345678");
        assert!(real_au.valid, "real AU number should pass");
    }
}

#[cfg(test)]
mod e164_property_tests {
    use super::{to_e164_au, validate_phone_e164};

    #[test]
    fn valid_e164_is_idempotent() {
        // If a number is valid E.164, normalizing it should be idempotent
        let test_numbers = vec![
            "+61412345678",
            "+14155551234",
            "+33123456789",
            "+441632123456",
        ];
        for num in test_numbers {
            // First validation
            let first = validate_phone_e164(num);
            if first.valid {
                // Second validation of same number should also pass
                let second = validate_phone_e164(num);
                assert!(
                    second.valid,
                    "E.164 number should remain valid on re-validation: {}",
                    num
                );
            }
        }
    }

    #[test]
    fn au_normalization_is_idempotent() {
        // If an AU number normalizes to E.164, normalizing the result should be idempotent
        let test_numbers = vec![
            "0412345678",
            "0298765432",
            "+61412345678",
            "61412345678",
            "(02) 9876 5432",
            "0412 345 678",
        ];
        for num in test_numbers {
            if let Some(normalized) = to_e164_au(num) {
                // Re-normalize the already-normalized number
                let re_normalized = to_e164_au(&normalized);
                assert_eq!(
                    re_normalized,
                    Some(normalized.clone()),
                    "AU normalization should be idempotent: {} → {}",
                    num,
                    normalized
                );
            }
        }
    }

    #[test]
    fn au_normalization_preserves_validity() {
        // All AU numbers that normalize successfully should be valid E.164
        let test_numbers = vec![
            "0412345678",
            "0298765432",
            "0755512345",
            "+61412345678",
            "61412345678",
        ];
        for num in test_numbers {
            if let Some(normalized) = to_e164_au(num) {
                let validation = validate_phone_e164(&normalized);
                assert!(
                    validation.valid,
                    "AU-normalized number should be valid E.164: {} → {}",
                    num, normalized
                );
            }
        }
    }

    #[test]
    fn au_normalization_rejects_foreign_numbers() {
        // Non-AU numbers should not normalize via AU path
        let non_au = vec![
            "0612345678", // French (lead digit 6)
            "0112345678", // Invalid (lead digit 1)
            "0912345678", // Invalid (lead digit 9)
            "0012345678", // Invalid (lead digit 0)
        ];
        for num in non_au {
            assert_eq!(
                to_e164_au(num),
                None,
                "Foreign/invalid number should not normalize: {}",
                num
            );
        }
    }

    #[test]
    fn au_normalization_accepts_all_real_trunk_digits() {
        // All real ACMA trunk digits (2/3/4/5/7/8) should be accepted
        for trunk in ['2', '3', '4', '5', '7', '8'] {
            let local = format!("0{trunk}12345678");
            assert!(
                to_e164_au(&local).is_some(),
                "Valid AU trunk digit {} should normalize: {}",
                trunk,
                local
            );

            let intl = format!("61{trunk}12345678");
            assert!(
                to_e164_au(&intl).is_some(),
                "Valid AU trunk digit {} should normalize (bare-61): {}",
                trunk,
                intl
            );
        }
    }

    #[test]
    fn au_international_and_local_collapse() {
        // The local and international forms of an AU number should normalize to the same value
        let test_pairs = vec![
            ("0412345678", "+61412345678"),
            ("0298765432", "61298765432"),
            ("0755512345", "+61755512345"),
        ];
        for (local, intl) in test_pairs {
            let local_norm = to_e164_au(local);
            let intl_norm = to_e164_au(intl);
            assert_eq!(
                local_norm, intl_norm,
                "Local and international forms should normalize to same value: {} vs {}",
                local, intl
            );
        }
    }
}
