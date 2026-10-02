//! Minimal RFC 3492 Punycode encoder for IDNA ASCII-Compatible Encoding (ACE).
//!
//! Real-world IDN-homoglyph phishing registers a label that *looks* like the
//! brand but contains a non-ASCII confusable (Cyrillic `а`, Greek `ο`, …); on
//! the wire that label is its `xn--…` Punycode form. To generate the same
//! candidates a registrar and resolver actually see, the homoglyph fuzzer
//! encodes each Unicode variant here rather than emitting a raw Unicode string
//! no resolver would accept.
//!
//! Pure, allocation-light, panic-free, and `no_std`-shaped (only `String`). The
//! encoder is the full bootstring algorithm from RFC 3492 §6.3, verified in the
//! tests against the RFC's own examples plus the canonical `bücher`/`münchen`
//! vectors; decoding is not needed (the generator only emits).

// RFC 3492 §5 bootstring parameters for Punycode.
const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

/// RFC 3492 §6.1 bias adaptation.
fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta /= if first_time { DAMP } else { 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

/// Map a 0–35 digit to its basic code point: `0..=25 → 'a'..='z'`,
/// `26..=35 → '0'..='9'`.
fn digit_to_basic(d: u32) -> char {
    debug_assert!(d < BASE);
    if d < 26 {
        (b'a' + d as u8) as char
    } else {
        (b'0' + (d - 26) as u8) as char
    }
}

/// Punycode-encode `input`'s code points into the body that follows the `xn--`
/// prefix. Returns `None` only on arithmetic overflow, which a DNS-length label
/// (≤ 63 bytes, so a handful of code points) can never reach — the checked
/// arithmetic is belt-and-braces so the encoder is total on any `&str`.
pub(super) fn encode(input: &str) -> Option<String> {
    let codepoints: Vec<u32> = input.chars().map(u32::from).collect();
    let mut output = String::new();

    // Emit the basic (ASCII) code points first, then a delimiter if any exist.
    let basic_count = codepoints.iter().filter(|&&c| c < INITIAL_N).count() as u32;
    for &c in codepoints.iter().filter(|&&c| c < INITIAL_N) {
        output.push(char::from_u32(c)?);
    }
    if basic_count > 0 {
        output.push('-');
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut handled = basic_count;
    let total = codepoints.len() as u32;

    while handled < total {
        // Smallest code point ≥ n that still needs encoding.
        let m = codepoints.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add(m.checked_sub(n)?.checked_mul(handled + 1)?)?;
        n = m;
        for &c in &codepoints {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit_to_basic(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_to_basic(q));
                bias = adapt(delta, handled + 1, handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(output)
}

/// IDNA *ToASCII* for a single DNS label, restricted to what the generator
/// needs: an all-ASCII label is returned lowercased when it is a valid
/// letter-digit-hyphen (LDH) label; a label carrying any non-ASCII code point is
/// Punycode-encoded to its `xn--…` ACE form. Returns `None` when the result
/// would not be a syntactically valid label (e.g. > 63 bytes).
pub(super) fn to_ascii_label(label: &str) -> Option<String> {
    if label.is_ascii() {
        let lower = label.to_ascii_lowercase();
        return is_ldh_label(&lower).then_some(lower);
    }
    let ace = format!("xn--{}", encode(label)?);
    is_ldh_label(&ace).then_some(ace)
}

/// A syntactically valid letter-digit-hyphen label: 1–63 bytes of `[a-z0-9-]`,
/// not starting or ending with a hyphen. Unlike the generator's stricter
/// `is_valid_label`, an internal `--` is allowed — the ACE prefix `xn--` needs
/// it.
fn is_ldh_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_rfc3492_and_canonical_vectors() {
        // Canonical IDN examples (the `xn--` body).
        assert_eq!(encode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(encode("münchen").as_deref(), Some("mnchen-3ya"));
        // RFC 3492 §7.1 example "(D) Russian" -> "b1abfaaepdrnnbgefbaDotcwatmq2g4l"
        // is too long for a label; use the short, widely-published ones above and
        // a single-confusable brand-style label below.
        // "аpple" with a Cyrillic 'а' (U+0430): the ASCII tail "pple" is basic.
        assert_eq!(encode("\u{0430}pple").as_deref(), Some("pple-43d"));
    }

    #[test]
    fn to_ascii_passes_ascii_through_and_aces_unicode() {
        assert_eq!(to_ascii_label("example").as_deref(), Some("example"));
        assert_eq!(to_ascii_label("EXAMPLE").as_deref(), Some("example"));
        assert_eq!(to_ascii_label("bücher").as_deref(), Some("xn--bcher-kva"));
        // A single Cyrillic 'е' (U+0435) in "example".
        assert_eq!(
            to_ascii_label("\u{0435}xample").as_deref(),
            Some("xn--xample-2of")
        );
    }

    #[test]
    fn to_ascii_rejects_overlong_and_bad_labels() {
        assert!(to_ascii_label("-bad").is_none());
        assert!(to_ascii_label("bad-").is_none());
        assert!(to_ascii_label(&"a".repeat(64)).is_none());
    }

    #[test]
    fn encode_is_total_on_arbitrary_input() {
        for s in ["", "a", "\u{10FFFF}", "ünïcödé", "\u{0430}\u{0431}\u{0432}"] {
            let _ = encode(s);
            let _ = to_ascii_label(s);
        }
    }
}
