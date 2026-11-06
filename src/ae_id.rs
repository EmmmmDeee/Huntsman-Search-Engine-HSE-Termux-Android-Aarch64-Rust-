//! United Arab Emirates identifiers: the Emirates ID card number and the UAE IBAN, each checked by
//! its published structure and check digit. Pure, no I/O.
//!
//! - An **Emirates ID** number is fifteen digits, written `784-YYYY-NNNNNNN-C`: `784` is the UAE's
//!   ISO 3166-1 numeric code, `YYYY` a year field (for most holders their year of birth), then a
//!   seven-digit serial and a Luhn check digit over the fourteen before it (the structure
//!   Microsoft Purview's "UAE identity card number" definition validates).
//! - A **UAE IBAN** is twenty-three characters, `AE`, two ISO 7064 mod 97-10 check digits, a
//!   three-digit institution identifier and a sixteen-digit account number (the Central Bank of
//!   the UAE's published IBAN structure).
//!
//! Strict by construction, as `au_id` is: the only separators are the ones each identifier is
//! printed with, so digits run together in prose never validate. A valid check digit shows the
//! number is well formed, not that it was issued, is current, or belongs to anyone; nothing here
//! names a holder, and no institution name is guessed from its identifier.

use crate::error::Error;

/// The UAE's ISO 3166-1 numeric code, the first three digits of every Emirates ID number.
const UAE_NUMERIC: &str = "784";
const EMIRATES_ID_DIGITS: usize = 15;
const UAE_IBAN_LEN: usize = 23;

/// One UAE identifier, in its bare form with the parts it is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeIdentifier {
    EmiratesId {
        /// The fifteen digits, without separators.
        bare: String,
    },
    Iban {
        /// The twenty-three characters, upper case, without spaces.
        bare: String,
    },
}

impl AeIdentifier {
    /// The identifier as it is printed: `784-1990-1234567-6`, or `AE07 0331 2345 6789 0123 456`.
    #[must_use]
    pub fn printed(&self) -> String {
        match self {
            Self::EmiratesId { bare } => format!(
                "{}-{}-{}-{}",
                &bare[..3],
                &bare[3..7],
                &bare[7..14],
                &bare[14..]
            ),
            Self::Iban { bare } => bare
                .as_bytes()
                .chunks(4)
                .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

/// The digits of a Luhn-checked number pass when the weighted sum is a multiple of ten. **Pure.**
fn luhn_ok(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            let value = u32::from(digit - b'0');
            if index % 2 == 1 {
                let doubled = value * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                value
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// The fifteen digits of an Emirates ID number written as `784199012345676`, or grouped
/// `784-1990-1234567-6` or `784 1990 1234567 6` (each separator optional, a hyphen or one space,
/// at the printed group boundaries only), when they start `784` and pass the Luhn check. **Pure.**
#[must_use]
pub fn emirates_id(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let mut digits = Vec::with_capacity(EMIRATES_ID_DIGITS);
    let mut bytes = raw.bytes().peekable();
    for (group, size) in [3, 4, 7, 1].into_iter().enumerate() {
        if group > 0 && matches!(bytes.peek(), Some(b'-' | b' ')) {
            bytes.next();
        }
        for _ in 0..size {
            match bytes.next() {
                Some(byte) if byte.is_ascii_digit() => digits.push(byte),
                _ => return None,
            }
        }
    }
    if bytes.next().is_some() || !digits.starts_with(UAE_NUMERIC.as_bytes()) || !luhn_ok(&digits) {
        return None;
    }
    String::from_utf8(digits).ok()
}

/// The remainder of an IBAN under ISO 7064 mod 97-10, read with its first four characters moved
/// to the end and each letter as its two-digit value (`A` is 10). **Pure.**
fn iban_remainder(iban: &str) -> Option<u32> {
    let (head, tail) = iban.split_at_checked(4)?;
    let mut remainder = 0_u32;
    for character in tail.chars().chain(head.chars()) {
        let value = character.to_digit(36)?;
        remainder = if value < 10 {
            (remainder * 10 + value) % 97
        } else {
            (remainder * 100 + value) % 97
        };
    }
    Some(remainder)
}

/// A UAE IBAN in its bare upper-case form, from `AE070331234567890123456` or the printed
/// `AE07 0331 2345 6789 0123 456` (single spaces between characters only), when it has the UAE's
/// twenty-three characters, digits after `AE`, and passes the mod 97-10 check. **Pure.**
#[must_use]
pub fn uae_iban(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.contains("  ") {
        return None;
    }
    let bare: String = raw
        .chars()
        .filter(|character| *character != ' ')
        .map(|character| character.to_ascii_uppercase())
        .collect();
    let digits = bare.strip_prefix("AE")?;
    (bare.len() == UAE_IBAN_LEN
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && iban_remainder(&bare) == Some(1))
    .then_some(bare)
}

/// The three-digit institution identifier of a UAE IBAN: the bank, never the account. The account
/// number is not split out: it stays inside the IBAN the operator gave, and no output repeats it
/// on its own. **Pure.**
#[must_use]
pub fn iban_institution(bare: &str) -> Option<&str> {
    (bare.len() == UAE_IBAN_LEN && bare.is_ascii()).then(|| &bare[4..7])
}

/// Classify one token as an Emirates ID number or a UAE IBAN. Anything else is refused rather than
/// guessed.
///
/// # Errors
/// `Error::Invalid` when neither structure and check digit matches.
pub fn classify(raw: &str) -> Result<AeIdentifier, Error> {
    if let Some(bare) = emirates_id(raw) {
        return Ok(AeIdentifier::EmiratesId { bare });
    }
    if let Some(bare) = uae_iban(raw) {
        return Ok(AeIdentifier::Iban { bare });
    }
    Err(Error::Invalid(
        "not a valid Emirates ID number or UAE IBAN".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_emirates_id_is_read_however_its_groups_are_separated() {
        for written in [
            "784199012345676",
            "784-1990-1234567-6",
            "784 1990 1234567 6",
            "784-19901234567-6",
            " 784-1990-1234567-6 ",
        ] {
            assert_eq!(
                emirates_id(written).as_deref(),
                Some("784199012345676"),
                "{written:?}"
            );
        }
        let id = classify("784-1990-1234567-6").unwrap();
        assert_eq!(id.printed(), "784-1990-1234567-6");
    }

    #[test]
    fn an_emirates_id_needs_its_country_code_check_digit_and_shape() {
        for refused in [
            // Wrong check digit.
            "784-1990-1234567-0",
            // The right Luhn digit under another country code.
            "123-1990-1234567-1",
            // Fourteen and sixteen digits.
            "78419901234567",
            "7841990123456760",
            // Separators off the printed boundaries, doubled, or of another kind.
            "7841-990-1234567-6",
            "784--1990-1234567-6",
            "784.1990.1234567.6",
            // Digits run into prose.
            "id784199012345676",
            "784199012345676x",
        ] {
            assert_eq!(emirates_id(refused), None, "{refused:?}");
        }
        // Only the trailing check digit differs between these two, and only one passes.
        assert!(luhn_ok(b"784198512345673"));
        assert!(!luhn_ok(b"784198512345674"));
    }

    #[test]
    fn a_uae_iban_is_read_bare_or_printed_and_checked_mod_97() {
        // The Central Bank of the UAE's published example.
        for written in [
            "AE070331234567890123456",
            "AE07 0331 2345 6789 0123 456",
            "ae07 0331 2345 6789 0123 456",
        ] {
            assert_eq!(
                uae_iban(written).as_deref(),
                Some("AE070331234567890123456"),
                "{written:?}"
            );
        }
        let iban = classify("AE07 0331 2345 6789 0123 456").unwrap();
        assert_eq!(iban.printed(), "AE07 0331 2345 6789 0123 456");
        assert_eq!(iban_institution("AE070331234567890123456"), Some("033"));
        assert_eq!(iban_institution("AE07"), None);
        for refused in [
            // A wrong check pair, and one changed account digit.
            "AE080331234567890123456",
            "AE070331234567890123457",
            // Twenty-two and twenty-four characters.
            "AE07033123456789012345",
            "AE0703312345678901234567",
            // Another country's IBAN, and a letter in the UAE account number.
            "GB29NWBK60161331926819",
            "AE07033123456789012345A",
            // Doubled spaces and other separators.
            "AE07  0331 2345 6789 0123 456",
            "AE07-0331-2345-6789-0123-456",
        ] {
            assert_eq!(uae_iban(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn anything_else_is_refused_not_guessed() {
        for raw in ["", "784", "53 004 085 616", "+971 50 123 4567", "AE"] {
            assert!(classify(raw).is_err(), "{raw:?}");
        }
    }
}
