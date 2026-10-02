use std::collections::BTreeMap;

/// Rank `items` by frequency and render the top `n` as a compact distribution
/// summary string: `"key×count, key×count, …"` (the separator is U+00D7
/// MULTIPLICATION SIGN). Counts occurrences, orders by count **descending** with
/// ties broken by key **ascending** (so the summary is deterministic regardless of
/// input order), then truncates to `n`. An empty iterator yields `""`.
///
/// Used across the module layer to fold a column of repeated values — HTTP status
/// codes (`wayback`), breach/event types (`dehashed`, `leakix`), Wi-Fi encryption
/// types (`wigle`) — into one human-readable line.
#[must_use]
pub fn top_n<'a>(items: impl Iterator<Item = &'a str>, n: usize) -> String {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    let mut ranked: Vec<(&str, u32)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ranked.truncate(n);
    ranked
        .iter()
        .map(|(k, v)| format!("{k}\u{00d7}{v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
