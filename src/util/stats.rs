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
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(val, _)| val)
}

pub fn mode_or<'a>(items: &[&'a str], fallback: &'a str) -> &'a str {
    mode(items).unwrap_or(fallback)
}
