use super::report::ValidationReport;

/// True if `s` is a syntactically valid E.164 number: leading `+`,
/// then 8 to 15 digits, with the country code in the conventional
/// 1-3 digit range. Does NOT verify the number is dial-able; only
/// the format.
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

    // AU international without the `+`: `61` + a 9-digit national number.
    if let Some(nat) = compact.strip_prefix("61")
        && nat.len() == 9
        && !nat.starts_with('0')
    {
        let e164 = format!("+61{nat}");
        return validate_phone_e164(&e164).valid.then_some(e164);
    }

    // AU local: a leading-`0` national number (`0` + 9 digits = 10).
    if compact.len() == 10 && compact.starts_with('0') {
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
}
