use std::collections::BTreeMap;

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
