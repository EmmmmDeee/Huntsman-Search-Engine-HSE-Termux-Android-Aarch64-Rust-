//! Option grammar shared by the lookup front-ends.
//!
//! Every lookup command reads its positional values and at most one `--save FILE` the same way
//! before applying its own rules. Writing the ledger is [`crate::lookup_save`]'s job.

use std::path::PathBuf;

use crate::error::Error;

/// The tokens every lookup command reads before applying its own rules: positional values in
/// order, and at most one `--save FILE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupTokens {
    pub positional: Vec<String>,
    pub save: Option<PathBuf>,
}

impl LookupTokens {
    /// Splits `args` into positional values and the optional save path. Options are read in
    /// order, so the first bad token decides the error.
    ///
    /// # Errors
    /// [`Error::Invalid`] when `--save` is repeated, has no value, or has an empty or
    /// option-shaped path, or when an unknown `--` option is present.
    pub fn split(args: &[String]) -> Result<Self, Error> {
        let mut positional = Vec::new();
        let mut save = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--save" => {
                    if save.is_some() {
                        return Err(Error::Invalid("only one --save".into()));
                    }
                    let Some(path) = it.next() else {
                        return Err(Error::Invalid("--save needs a value".into()));
                    };
                    if path.is_empty() || path.starts_with("--") {
                        return Err(Error::Invalid("--save needs a file path".into()));
                    }
                    save = Some(PathBuf::from(path));
                }
                flag if flag.starts_with("--") => {
                    return Err(Error::Invalid(format!("unknown option {flag}")));
                }
                value => positional.push(value.to_owned()),
            }
        }
        Ok(Self { positional, save })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn owned(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn split_keeps_positionals_in_order_and_reads_one_save_path() {
        let tokens = LookupTokens::split(&owned(&["a", "--save", "out.json", "b", "-x"])).unwrap();
        assert_eq!(tokens.positional, ["a", "b", "-x"]);
        assert_eq!(tokens.save.as_deref(), Some(Path::new("out.json")));
    }

    #[test]
    fn split_refuses_a_second_save_before_reading_its_value() {
        assert_eq!(
            LookupTokens::split(&owned(&["--save", "a.json", "--save"])),
            Err(Error::Invalid("only one --save".into()))
        );
    }

    #[test]
    fn split_refuses_a_save_without_a_usable_path() {
        assert_eq!(
            LookupTokens::split(&owned(&["--save"])),
            Err(Error::Invalid("--save needs a value".into()))
        );
        assert_eq!(
            LookupTokens::split(&owned(&["--save", ""])),
            Err(Error::Invalid("--save needs a file path".into()))
        );
        assert_eq!(
            LookupTokens::split(&owned(&["--save", "--json"])),
            Err(Error::Invalid("--save needs a file path".into()))
        );
    }

    #[test]
    fn split_refuses_the_first_unknown_double_dash_option() {
        assert_eq!(
            LookupTokens::split(&owned(&["--json", "--save", "a.json", "--save"])),
            Err(Error::Invalid("unknown option --json".into()))
        );
    }
}
