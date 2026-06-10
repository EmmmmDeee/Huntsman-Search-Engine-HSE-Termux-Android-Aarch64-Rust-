pub fn mode<'a>(items: &[&'a str]) -> Option<&'a str> {
    if items.is_empty() {
        return None;
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for &item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts
        .into_iter()
        // Highest count wins; on a tie, the lexicographically SMALLEST string
        // wins — consistent with the other ranking utilities, and deterministic
        // regardless of HashMap iteration order. `max_by` keeps the "greatest"
        // element, so the tie-break compares REVERSED (`b.0.cmp(a.0)`) to make
        // the smaller string rank as greater.
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(val, _)| val)
}

pub fn mode_or<'a>(items: &[&'a str], fallback: &'a str) -> &'a str {
    mode(items).unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_breaks_ties_alphabetically_smallest_first() {
        // "apple" and "banana" tie at 2; the smallest string wins, deterministically.
        assert_eq!(mode(&["banana", "apple", "banana", "apple"]), Some("apple"));
        // Clear winner by count.
        assert_eq!(mode(&["x", "y", "y"]), Some("y"));
        // Empty input.
        assert_eq!(mode(&[]), None);
        // Fallback wrapper.
        assert_eq!(mode_or(&[], "fallback"), "fallback");
    }
}
