//! Australian Business Number (ABN) and Company Number (ACN) validation +
//! company-form detection. Pure, dependency-free, no I/O.
//!
//! Both identifiers carry a deterministic check-digit, so a candidate string can
//! be rejected *algorithmically* rather than trusted on surrounding text alone —
//! which slashes false positives when harvesting 9/11-digit numbers from web
//! text, breach dumps or registry fields. Shared so every module validates ABNs
//! and ACNs identically.

/// Validate an 11-digit Australian Business Number by its ATO mod-89 checksum.
///
/// # Guarantees
/// - Returns `true` **iff** the decimal digits of `s` form a valid ABN: exactly
///   11 digits, a non-zero leading digit, and a weighted sum divisible by 89.
/// - Non-digit bytes are ignored, so spaced/grouped forms validate. A caller
///   that requires a *bare* 11-digit token must check that separately — an
///   11-digit run embedded in other text will still pass.
/// - Pure and total: no panics, no allocation beyond a small digit buffer, no
///   I/O; the result depends only on `s`.
///
/// # Failure modes (returns `false`)
/// - the digit count is not 11; the leading digit is `0`; the mod-89 checksum
///   does not hold; `s` contains no digits.
///
/// ```
/// use huntsman_search_engine::util::abn::is_valid_abn;
///
/// assert!(is_valid_abn("51824753556"));    // ATO worked example
/// assert!(is_valid_abn("51 824 753 556")); // separators ignored
/// assert!(!is_valid_abn("51824753557"));   // last digit flipped → checksum fails
/// assert!(!is_valid_abn("1824753556"));    // 10 digits
/// assert!(!is_valid_abn("01824753556"));   // ABNs never lead with 0
/// ```
pub fn is_valid_abn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 {
        return false;
    }
    // ABNs never begin with 0 (the leading pair is a checksum in 10..=99).
    if digits[0] == 0 {
        return false;
    }
    let weights = [10u32, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let mut sum = 0u32;
    for (i, &w) in weights.iter().enumerate() {
        let d = if i == 0 { digits[i] - 1 } else { digits[i] };
        sum += d * w;
    }
    sum.is_multiple_of(89)
}

/// Validate a 9-digit Australian Company Number by its ASIC check digit.
///
/// # Guarantees
/// - Returns `true` **iff** the decimal digits of `s` form a valid ACN: exactly
///   9 digits whose 9th equals the ASIC complement of the weighted sum of the
///   first 8.
/// - Non-digit bytes are ignored (grouped forms validate); the bare-token caveat
///   of [`is_valid_abn`] applies equally.
/// - Pure and total: no panics, no I/O.
///
/// # Failure modes (returns `false`)
/// - the digit count is not 9; the check digit does not match.
///
/// ```
/// use huntsman_search_engine::util::abn::is_valid_acn;
///
/// assert!(is_valid_acn("004 085 616")); // separators ignored
/// assert!(is_valid_acn("000000019"));   // ASIC worked example
/// assert!(!is_valid_acn("000000018"));  // wrong check digit
/// assert!(!is_valid_acn("00000001"));   // 8 digits
/// ```
pub fn is_valid_acn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let weights = [8u32, 7, 6, 5, 4, 3, 2, 1];
    let sum: u32 = weights.iter().zip(&digits[..8]).map(|(w, d)| w * d).sum();
    let complement = (10 - (sum % 10)) % 10;
    digits[8] == complement
}

/// Derive the nine-digit Australian Company Number (ACN) embedded in a
/// **company's** ABN.
///
/// Every body corporate registered with ASIC is issued an ABN that is its
/// nine-digit ACN prefixed by a two-digit checksum, so the ACN is simply the
/// ABN's trailing nine digits — but *only* for companies. Sole traders, trusts,
/// partnerships and super funds also hold ABNs whose trailing nine digits are
/// **not** an ACN. This function returns the ACN **iff** `s` is a checksum-valid
/// ABN whose trailing nine digits are *themselves* a checksum-valid ACN, which
/// is exactly the discriminating test for "this ABN belongs to a registered
/// company". A `Some` result therefore both (a) classifies the ABN as a company
/// and (b) surfaces the ACN as a first-class pivot for ASIC / ASX / court
/// records that key on the ACN, not the ABN.
///
/// The returned ACN is **bare** (nine digits, no separators) so it can be fed
/// straight to the ACN-consuming resolvers.
///
/// # Guarantees
/// - Returns `Some(acn)` iff [`is_valid_abn`]`(s)` holds and [`is_valid_acn`]
///   holds on the trailing nine digits; `None` otherwise (a non-company ABN, an
///   invalid ABN, or the wrong length).
/// - Non-digit bytes are ignored, matching [`is_valid_abn`] — so spaced/grouped
///   forms resolve.
/// - Pure and total: no panics, no I/O.
///
/// ```
/// use huntsman_search_engine::util::abn::derive_acn;
///
/// // A company ABN → its embedded, independently-valid ACN.
/// assert_eq!(derive_acn("53 004 085 616").as_deref(), Some("004085616"));
/// // A valid ABN that is NOT a company (its trailing 9 fail the ACN checksum).
/// assert_eq!(derive_acn("51824753556"), None);
/// // Not an ABN at all.
/// assert_eq!(derive_acn("004085616"), None);
/// ```
pub fn derive_acn(s: &str) -> Option<String> {
    if !is_valid_abn(s) {
        return None;
    }
    // `is_valid_abn` guarantees exactly 11 decimal digits, so the trailing nine
    // are well defined.
    let digits = crate::util::str_util::ascii_digits(s);
    let acn = &digits[digits.len() - 9..];
    is_valid_acn(acn).then(|| acn.to_string())
}

/// Heuristic: does `name` carry an Australian corporate legal-form suffix?
///
/// Recognises `PTY LTD`, `LIMITED`, `LTD`, `PTY`, `INC`/`INCORPORATED`, `NL`,
/// and `& CO`/`AND CO`. Used to decide whether a register owner is a company
/// worth pivoting to the ABN/ACN resolvers, versus an individual.
///
/// # Guarantees
/// - Matching is case-insensitive and punctuation-insensitive: surrounding
///   commas, periods, parentheses, etc. do not defeat a match (`"Acme Ltd."`).
/// - A form is matched only as a whitespace-bounded token, so it never fires on
///   a substring inside a word (`INC` in `INCANDESCENT`, `LTD` in `ALTDORF`).
/// - `&` is preserved (it is part of `& CO`), so a bare `" CO "` never matches.
/// - Pure and total: no panics, no I/O.
///
/// ```
/// use huntsman_search_engine::util::abn::looks_like_company;
///
/// assert!(looks_like_company("Acme Holdings Pty Ltd"));
/// assert!(looks_like_company("BHP GROUP LIMITED."));   // trailing punctuation
/// assert!(looks_like_company("Smith & Co"));
/// assert!(!looks_like_company("John Smith"));          // an individual
/// assert!(!looks_like_company("Incandescent Bay"));    // not a substring match
/// ```
pub fn looks_like_company(name: &str) -> bool {
    // Normalise so a legal-form suffix is recognised regardless of surrounding
    // punctuation: uppercase, reduce every char that is not alphanumeric or `&`
    // (the only punctuation that is itself part of a form — "& CO") to a space,
    // and collapse runs of whitespace. This folds "Pty. Ltd.", "LTD,",
    // "LIMITED.", "Inc)" onto the canonical space-delimited tokens below —
    // previously a trailing comma/period/paren on the final token defeated the
    // match and a real company was misread as an individual.
    let folded: String = name
        .to_uppercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '&' {
                c
            } else {
                ' '
            }
        })
        .collect();
    // Double-pad the collapsed token stream so each suffix matches only as a
    // whitespace-bounded token — otherwise " INC" would falsely fire inside
    // "INCANDESCENT", " LTD" inside "ALTDORF".
    let u = {
        let mut s = String::with_capacity(folded.len() + 2);
        s.push(' ');
        for (i, w) in folded.split_whitespace().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(w);
        }
        s.push(' ');
        s
    };
    const SUFFIXES: &[&str] = &[
        " PTY LTD ",
        " LIMITED ",
        " LTD ",
        " PTY ",
        " INCORPORATED ",
        " INC ",
        " NL ",
        " & CO ",
        " AND CO ",
    ];
    SUFFIXES.iter().any(|s| u.contains(s))
}

/// Split a register owner string into individually ABN-resolvable company names.
///
/// Owners are frequently joint syndicates (`"Dev Pty Ltd & Gwad Pty Ltd"`) where
/// each company has its own ABN.
///
/// # Guarantees
/// - When two or more `&`-separated parts each carry a legal form (see
///   [`looks_like_company`]), returns each part — deduplicated, input case
///   preserved, capped at 5 so a large trust cannot flood the caller.
/// - The `& Co`/`& Company` idiom stays attached to its name (it is one company,
///   not a separator), even inside a syndicate.
/// - A single company — including one that itself contains `& Co` — is returned
///   whole as a one-element vector.
/// - Returns an empty vector for individuals (no part carries a legal form).
/// - Pure and total: no panics, no I/O.
///
/// ```
/// use huntsman_search_engine::util::abn::company_names;
///
/// // Joint syndicate → one entry per company.
/// assert_eq!(
///     company_names("Alpha Pty Ltd & Beta Pty Ltd"),
///     vec!["Alpha Pty Ltd", "Beta Pty Ltd"],
/// );
/// // "& Co" stays attached, even next to a second company.
/// assert_eq!(
///     company_names("Ashton & Co Pty Ltd & Berg Pty Ltd"),
///     vec!["Ashton & Co Pty Ltd", "Berg Pty Ltd"],
/// );
/// // A single company is returned whole.
/// assert_eq!(company_names("Smith & Co"), vec!["Smith & Co"]);
/// // Individuals → empty.
/// assert!(company_names("Jane Citizen").is_empty());
/// ```
pub fn company_names(owner: &str) -> Vec<String> {
    let normalised = owner.replace(" AND ", " & ").replace(" and ", " & ");

    // Split on `&`, but first rejoin the "& Co" / "& Company" idiom: that `&`
    // is part of a single company name ("Ashton & Co Pty Ltd"), not a syndicate
    // separator. A naive split orphans the tail as a bogus standalone company
    // ("Co Pty Ltd" — which itself passes `looks_like_company`), so the ABN
    // register would be queried for the wrong name. A segment is a continuation
    // only when its first word is exactly `CO`/`CO.`/`COMPANY` (so "Coffee Pty
    // Ltd" is NOT misread as a continuation).
    let mut segments: Vec<String> = Vec::new();
    for seg in normalised.split('&') {
        let seg = seg.trim();
        let first = seg
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('.')
            .to_uppercase();
        if matches!(first.as_str(), "CO" | "COMPANY") && !segments.is_empty() {
            let prev = segments.last_mut().expect("guarded by !is_empty() above");
            prev.push_str(" & ");
            prev.push_str(seg);
        } else {
            segments.push(seg.to_string());
        }
    }

    let parts: Vec<String> = segments
        .into_iter()
        .map(|p| match p.find("- SEE") {
            Some(i) => p[..i].trim().to_string(),
            None => p.trim().to_string(),
        })
        .filter(|p| p.len() >= 4 && looks_like_company(p))
        .collect();

    if parts.len() >= 2 {
        // Joint syndicate: each company is its own ABN target.
        let mut out: Vec<String> = Vec::new();
        for c in parts {
            if !out.contains(&c) {
                out.push(c);
                if out.len() >= 5 {
                    break;
                }
            }
        }
        out
    } else if looks_like_company(owner) {
        // A single company (possibly "X & CO") — keep the whole name.
        vec![owner.trim().to_string()]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
