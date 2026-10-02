//! Australian business identifiers: ABN and ACN checksums, the ACN embedded in a
//! company ABN, and BSB to institution. Rebuilt from the monolith's `util::abn`
//! and `util::bsb`. Pure, no I/O.
//!
//! Strict by construction. The monolith ignored every non-digit byte, so
//! `"5182 hello 4753556"` validated as an ABN and a stray 11-digit run in prose
//! passed. Here the only separators are single spaces or hyphens between digits.
//! A valid checksum shows the digits are well formed, not that the number is
//! registered or belongs to anyone.

use crate::error::Error;

/// Digits of `raw`, or `None` unless it is ASCII digits optionally grouped by
/// single spaces or hyphens. No leading, trailing, or doubled separator.
fn grouped_digits(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim();
    let mut out = Vec::with_capacity(raw.len());
    let mut after_sep = true;
    for b in raw.bytes() {
        match b {
            b'0'..=b'9' => {
                out.push(b - b'0');
                after_sep = false;
            }
            b' ' | b'-' if !after_sep => after_sep = true,
            _ => return None,
        }
    }
    if after_sep { None } else { Some(out) }
}

fn digits_to_string(digits: &[u8]) -> String {
    digits.iter().map(|d| char::from(b'0' + d)).collect()
}

const ABN_WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
const ACN_WEIGHTS: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

fn abn_ok(d: &[u8]) -> bool {
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let sum: u32 = ABN_WEIGHTS
        .iter()
        .zip(d)
        .enumerate()
        .map(|(i, (w, &x))| w * (u32::from(x) - u32::from(i == 0)))
        .sum();
    #[allow(clippy::manual_is_multiple_of)] // is_multiple_of needs Rust 1.90; MSRV is 1.87
    let ok = sum % 89 == 0;
    ok
}

fn acn_ok(d: &[u8]) -> bool {
    if d.len() != 9 {
        return false;
    }
    let sum: u32 = ACN_WEIGHTS
        .iter()
        .zip(d)
        .map(|(w, &x)| w * u32::from(x))
        .sum();
    u32::from(d[8]) == (10 - sum % 10) % 10
}

/// Eleven digits, a non-zero lead, and the ATO mod-89 checksum.
#[must_use]
pub fn is_valid_abn(raw: &str) -> bool {
    grouped_digits(raw).is_some_and(|d| abn_ok(&d))
}

/// Nine digits whose last is the ASIC check digit over the first eight.
/// The check digit does not catch every single-digit error (weights 2, 4, 5, 6, 8
/// share a factor with 10), so a valid ACN is weaker evidence than a valid ABN.
#[must_use]
pub fn is_valid_acn(raw: &str) -> bool {
    grouped_digits(raw).is_some_and(|d| acn_ok(&d))
}

/// Bare 11-digit form of a valid ABN.
#[must_use]
pub fn normalise_abn(raw: &str) -> Option<String> {
    grouped_digits(raw)
        .filter(|d| abn_ok(d))
        .map(|d| digits_to_string(&d))
}

/// The ACN of a company ABN: the last nine digits, but only when they are a valid
/// ACN. Sole traders, trusts, and funds hold ABNs whose tail is not an ACN, so
/// `Some` classifies the holder as a registered company.
#[must_use]
pub fn derive_acn(raw: &str) -> Option<String> {
    let d = grouped_digits(raw).filter(|d| abn_ok(d))?;
    let tail = &d[2..];
    acn_ok(tail).then(|| digits_to_string(tail))
}

/// Bare six-digit BSB from `NNNNNN`, `NNN-NNN`, or `NNN NNN`. Any other grouping
/// is refused, so a number split across prose never normalises.
#[must_use]
pub fn normalise_bsb(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let bytes = raw.as_bytes();
    let ok_shape = match bytes.len() {
        6 => bytes.iter().all(u8::is_ascii_digit),
        7 => {
            matches!(bytes[3], b'-' | b' ')
                && bytes[..3].iter().all(u8::is_ascii_digit)
                && bytes[4..].iter().all(u8::is_ascii_digit)
        }
        _ => false,
    };
    ok_shape.then(|| raw.chars().filter(char::is_ascii_digit).collect())
}

/// Longest prefix first, so a three-digit entry beats the two-digit block it sits in.
/// Only stable, well-established allocations. An absent prefix is no attribution.
const INSTITUTIONS: &[(&str, &str)] = &[
    ("182", "Macquarie Bank"),
    ("183", "Macquarie Bank"),
    ("193", "Bank of Melbourne"),
    ("105", "BankSA"),
    ("124", "Bank of Queensland"),
    ("484", "Suncorp Bank"),
    ("923", "ING"),
    ("939", "AMP Bank"),
    ("01", "ANZ"),
    ("03", "Westpac"),
    ("06", "Commonwealth Bank"),
    ("08", "NAB"),
    ("11", "St George Bank"),
    ("30", "Bankwest"),
    ("63", "Bendigo Bank"),
];

/// Institution behind a BSB prefix. Not proof that the branch or an account exists.
#[must_use]
pub fn bsb_institution(raw: &str) -> Option<&'static str> {
    let bsb = normalise_bsb(raw)?;
    INSTITUTIONS
        .iter()
        .find(|(prefix, _)| bsb.starts_with(prefix))
        .map(|&(_, name)| name)
}

/// What an identifier string is, by checksum and shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identifier {
    Abn {
        bare: String,
        acn: Option<String>,
    },
    Acn {
        bare: String,
    },
    Bsb {
        bare: String,
        institution: Option<&'static str>,
    },
}

/// Classify one token. An ambiguous token is refused rather than guessed: nine
/// digits are an ACN, eleven an ABN, six a BSB, and nothing else is.
///
/// # Errors
/// `Error::Invalid` when no identifier shape and checksum matches.
pub fn classify(raw: &str) -> Result<Identifier, Error> {
    if let Some(bare) = normalise_abn(raw) {
        let acn = derive_acn(&bare);
        return Ok(Identifier::Abn { bare, acn });
    }
    if let Some(d) = grouped_digits(raw).filter(|d| acn_ok(d)) {
        return Ok(Identifier::Acn {
            bare: digits_to_string(&d),
        });
    }
    if let Some(bare) = normalise_bsb(raw) {
        let institution = bsb_institution(&bare);
        return Ok(Identifier::Bsb { bare, institution });
    }
    Err(Error::Invalid("not a valid ABN, ACN, or BSB".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small deterministic generator so the property tests need no crate.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    /// Build a valid ABN from nine free digits by solving for the first two.
    fn abn_from_tail(tail: &[u8; 9]) -> Option<Vec<u8>> {
        (10u8..=99).find_map(|lead| {
            let mut d = vec![lead / 10, lead % 10];
            d.extend_from_slice(tail);
            abn_ok(&d).then_some(d)
        })
    }

    #[test]
    fn published_examples() {
        assert!(is_valid_abn("51824753556"));
        assert!(is_valid_abn("51 824 753 556"));
        assert!(is_valid_abn("51-824-753-556"));
        assert!(!is_valid_abn("51824753557"));
        assert!(!is_valid_abn("1824753556"));
        assert!(!is_valid_abn("01824753556"));
        assert!(is_valid_acn("004 085 616"));
        assert!(is_valid_acn("000000019"));
        assert!(!is_valid_acn("000000018"));
        assert!(!is_valid_acn("00000001"));
        assert_eq!(derive_acn("53 004 085 616").as_deref(), Some("004085616"));
        assert_eq!(derive_acn("51824753556"), None);
        assert_eq!(derive_acn("004085616"), None);
    }

    #[test]
    fn prose_and_odd_separators_are_not_identifiers() {
        for bad in [
            "5182 hello 4753556",
            "abc51824753556xyz",
            "51  824 753 556",
            "-51824753556",
            "51824753556-",
            "51.824.753.556",
            "５１８２４７５３５５６",
            "",
            "   ",
        ] {
            assert!(!is_valid_abn(bad), "{bad:?}");
        }
        assert!(
            is_valid_abn("  51824753556  "),
            "outer whitespace is trimmed"
        );
        assert!(!is_valid_acn("004 hello 085 616"));
        assert_eq!(normalise_bsb("062-000").as_deref(), Some("062000"));
        assert_eq!(normalise_bsb("062 000").as_deref(), Some("062000"));
        for bad in [
            "0 6 2 0 0 0",
            "06-2000",
            "062--000",
            "062_000",
            "06200",
            "0620000",
            "062-00a",
        ] {
            assert_eq!(normalise_bsb(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn abn_checksum_catches_every_single_digit_error() {
        let mut rng = Lcg(0x5eed);
        let mut checked = 0;
        for _ in 0..400 {
            let mut tail = [0u8; 9];
            for t in &mut tail {
                *t = u8::try_from(rng.next() % 10).unwrap();
            }
            let Some(valid) = abn_from_tail(&tail) else {
                continue;
            };
            assert!(abn_ok(&valid));
            for pos in 0..11 {
                for replacement in 0..10u8 {
                    if replacement == valid[pos] {
                        continue;
                    }
                    let mut broken = valid.clone();
                    broken[pos] = replacement;
                    assert!(!abn_ok(&broken), "{valid:?} pos {pos} -> {replacement}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 10_000, "{checked}");
    }

    #[test]
    fn abn_checksum_catches_adjacent_transposition_unless_equal_mod_89() {
        // Weights differ by 2 between neighbours (never 0 mod 89), except the 10/1
        // lead pair, so swapping unequal neighbours past the lead always breaks it.
        let valid: Vec<u8> = "51824753556".bytes().map(|b| b - b'0').collect();
        for pos in 2..10 {
            if valid[pos] == valid[pos + 1] {
                continue;
            }
            let mut swapped = valid.clone();
            swapped.swap(pos, pos + 1);
            assert!(!abn_ok(&swapped), "swap at {pos}");
        }
    }

    #[test]
    fn acn_check_digit_has_a_documented_blind_spot() {
        // Weight 5 on digit 4: changing it by 2 moves the sum by 10, so the check
        // digit is unchanged. This is why a valid ACN is weaker evidence.
        let base: Vec<u8> = "004085616".bytes().map(|b| b - b'0').collect();
        assert!(acn_ok(&base));
        let mut shifted = base.clone();
        shifted[3] = (shifted[3] + 2) % 10;
        assert!(acn_ok(&shifted), "blind spot should exist: {shifted:?}");
    }

    #[test]
    fn derived_acn_is_always_itself_valid_and_only_for_companies() {
        let mut rng = Lcg(9);
        let (mut companies, mut others) = (0, 0);
        for _ in 0..3000 {
            let mut tail = [0u8; 9];
            for t in &mut tail {
                *t = u8::try_from(rng.next() % 10).unwrap();
            }
            let Some(abn) = abn_from_tail(&tail) else {
                continue;
            };
            let text = digits_to_string(&abn);
            if let Some(acn) = derive_acn(&text) {
                assert!(is_valid_acn(&acn));
                assert_eq!(acn, digits_to_string(&tail));
                companies += 1;
            } else {
                assert!(!acn_ok(&tail));
                others += 1;
            }
        }
        assert!(companies > 100 && others > 100, "{companies} {others}");
    }

    #[test]
    fn bsb_longest_prefix_wins_and_unknown_is_not_guessed() {
        assert_eq!(bsb_institution("062-000"), Some("Commonwealth Bank"));
        assert_eq!(bsb_institution("012-003"), Some("ANZ"));
        assert_eq!(bsb_institution("032-000"), Some("Westpac"));
        assert_eq!(bsb_institution("082-001"), Some("NAB"));
        assert_eq!(bsb_institution("182-512"), Some("Macquarie Bank"));
        assert_eq!(bsb_institution("183-334"), Some("Macquarie Bank"));
        assert_eq!(bsb_institution("112-879"), Some("St George Bank"));
        assert_eq!(bsb_institution("306-089"), Some("Bankwest"));
        assert_eq!(bsb_institution("633-000"), Some("Bendigo Bank"));
        assert_eq!(bsb_institution("999-999"), None);
        assert_eq!(bsb_institution("06200"), None);
        assert_eq!(bsb_institution("not a bsb"), None);
    }

    #[test]
    fn table_is_ordered_longest_first() {
        let lens: Vec<usize> = INSTITUTIONS.iter().map(|(p, _)| p.len()).collect();
        assert!(lens.windows(2).all(|w| w[0] >= w[1]), "{lens:?}");
        assert!(
            INSTITUTIONS
                .iter()
                .all(|(p, _)| p.bytes().all(|b| b.is_ascii_digit()))
        );
    }

    #[test]
    fn classify_picks_one_shape_or_refuses() {
        assert_eq!(
            classify("53 004 085 616").unwrap(),
            Identifier::Abn {
                bare: "53004085616".into(),
                acn: Some("004085616".into())
            }
        );
        assert_eq!(
            classify("51824753556").unwrap(),
            Identifier::Abn {
                bare: "51824753556".into(),
                acn: None
            }
        );
        assert_eq!(
            classify("004 085 616").unwrap(),
            Identifier::Acn {
                bare: "004085616".into()
            }
        );
        assert_eq!(
            classify("062-000").unwrap(),
            Identifier::Bsb {
                bare: "062000".into(),
                institution: Some("Commonwealth Bank")
            }
        );
        assert!(classify("hello").is_err());
        assert!(classify("51824753557").is_err());
    }
}
