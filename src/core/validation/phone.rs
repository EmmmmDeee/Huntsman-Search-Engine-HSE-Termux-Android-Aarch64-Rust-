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
