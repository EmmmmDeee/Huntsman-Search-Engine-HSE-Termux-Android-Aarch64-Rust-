use std::collections::BTreeMap;

pub fn top_n<'a>(items: impl Iterator<Item = &'a str>, n: usize) -> String {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for item in items {
        *counts.entry(item).or_insert(0) += 1;
    }
    let mut ranked: Vec<(&str, u32)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ranked.truncate(n);
    // Fold directly into one String rather than allocating a `format!` String
    // per entry plus an intermediate Vec for `join`.
    use std::fmt::Write as _;
    let mut out = String::new();
    for (i, (k, v)) in ranked.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        // Writing to a String is infallible; the `let _` documents that.
        let _ = write!(out, "{k}\u{00d7}{v}");
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
