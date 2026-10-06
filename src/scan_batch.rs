//! Pure batch-seed parsing for the `scan --input-file` front end.

use std::collections::BTreeSet;

use crate::error::Error;

/// Bound one batch even when the input file itself is within the 1 MiB CLI cap.
pub const MAX_BATCH_SEEDS: usize = 1_000;

/// Parse one-target-per-line input using the legacy Huntsman semantics:
/// trim whitespace, ignore blank/comment lines, preserve first-seen order, and
/// de-duplicate exact seed spellings.
///
/// # Errors
/// Empty input after filtering or more than [`MAX_BATCH_SEEDS`] unique seeds.
pub fn parse_seed_list(body: &str) -> Result<Vec<String>, Error> {
    let mut seen = BTreeSet::new();
    let mut seeds = Vec::new();

    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || !seen.insert(line.to_owned()) {
            continue;
        }
        if seeds.len() >= MAX_BATCH_SEEDS {
            return Err(Error::Invalid(format!(
                "scan input contains more than {} unique seeds",
                MAX_BATCH_SEEDS
            )));
        }
        seeds.push(line.to_owned());
    }

    if seeds.is_empty() {
        return Err(Error::Invalid(
            "scan input contains no seeds (one target per line; blank and # lines are ignored)"
                .into(),
        ));
    }
    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_skips_comments_deduplicates_and_preserves_order() {
        let got = parse_seed_list(
            "
              # comment
              0412 345 678

              +44 20 7183 8750
              0412 345 678
              @alice
            ",
        )
        .unwrap();
        assert_eq!(
            got,
            ["0412 345 678", "+44 20 7183 8750", "@alice"]
        );
    }

    #[test]
    fn empty_filtered_input_is_rejected() {
        let error = parse_seed_list("  \n# only a comment\n\t").unwrap_err();
        assert!(error.to_string().contains("no seeds"));
    }

    #[test]
    fn unique_seed_limit_is_explicit() {
        let body = (0..=MAX_BATCH_SEEDS)
            .map(|index| format!("seed-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let error = parse_seed_list(&body).unwrap_err();
        assert!(error.to_string().contains("more than"));
    }
}
