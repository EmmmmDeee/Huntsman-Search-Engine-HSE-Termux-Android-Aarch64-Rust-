//! Argument parsing for `huntsman-recon fetch`. Kept in the library so the grammar
//! is unit-tested without spawning the binary.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::Error;
use crate::fetch::{AuthStyle, DEFAULT_MAX_REDIRECTS};
use crate::keys::valid_slot;

pub const FETCH_USAGE: &str = "usage: huntsman-recon fetch URL [--body] [--allow-private] [--keys FILE] \
[--bearer SLOT | --header NAME=SLOT] [--max-redirects N] [--timeout SECS]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchArgs {
    pub url: String,
    pub print_body: bool,
    pub allow_private: bool,
    pub keys_file: Option<PathBuf>,
    /// Credential slot and how to send it. `None` means anonymous.
    pub auth: Option<(String, AuthStyle)>,
    pub max_redirects: u32,
    pub timeout: Duration,
}

impl FetchArgs {
    /// # Errors
    /// `Error::Invalid` with the reason; the caller prints [`FETCH_USAGE`].
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut url = None;
        let mut out = Self {
            url: String::new(),
            print_body: false,
            allow_private: false,
            keys_file: None,
            auth: None,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            timeout: crate::http::DEFAULT_TIMEOUT,
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| {
                it.next()
                    .cloned()
                    .ok_or_else(|| Error::Invalid(format!("{name} needs a value")))
            };
            match arg.as_str() {
                "--body" => out.print_body = true,
                "--allow-private" => out.allow_private = true,
                "--keys" => out.keys_file = Some(PathBuf::from(value("--keys")?)),
                "--bearer" => {
                    let slot = checked_slot(&value("--bearer")?)?;
                    set_auth(&mut out, slot, AuthStyle::Bearer)?;
                }
                "--header" => {
                    let spec = value("--header")?;
                    let (name, slot) = spec
                        .split_once('=')
                        .ok_or_else(|| Error::Invalid("--header wants NAME=SLOT".into()))?;
                    set_auth(
                        &mut out,
                        checked_slot(slot)?,
                        AuthStyle::Header(name.to_owned()),
                    )?;
                }
                "--max-redirects" => {
                    out.max_redirects = value("--max-redirects")?
                        .parse()
                        .ok()
                        .filter(|n| *n <= 20)
                        .ok_or_else(|| Error::Invalid("--max-redirects is 0..=20".into()))?;
                }
                "--timeout" => {
                    let secs: u64 = value("--timeout")?
                        .parse()
                        .ok()
                        .filter(|s| (1..=600).contains(s))
                        .ok_or_else(|| Error::Invalid("--timeout is 1..=600 seconds".into()))?;
                    out.timeout = Duration::from_secs(secs);
                }
                flag if flag.starts_with("--") => {
                    return Err(Error::Invalid(format!("unknown option {flag}")));
                }
                positional => {
                    if url.replace(positional.to_owned()).is_some() {
                        return Err(Error::Invalid("only one URL".into()));
                    }
                }
            }
        }
        out.url = url.ok_or_else(|| Error::Invalid("missing URL".into()))?;
        Ok(out)
    }
}

fn checked_slot(slot: &str) -> Result<String, Error> {
    if valid_slot(slot) {
        Ok(slot.to_owned())
    } else {
        Err(Error::Invalid(
            "credential slot must be an UPPER_SNAKE name".into(),
        ))
    }
}

fn set_auth(out: &mut FetchArgs, slot: String, style: AuthStyle) -> Result<(), Error> {
    if out.auth.replace((slot, style)).is_some() {
        return Err(Error::Invalid("one credential per fetch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<FetchArgs, Error> {
        FetchArgs::parse(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
    }

    #[test]
    fn defaults_are_anonymous_public_only_and_quiet() {
        let a = parse("https://a.example/").expect("parse");
        assert_eq!(a.url, "https://a.example/");
        assert!(!a.print_body && !a.allow_private && a.auth.is_none() && a.keys_file.is_none());
        assert_eq!(a.max_redirects, DEFAULT_MAX_REDIRECTS);
    }

    #[test]
    fn options_in_any_order() {
        let a = parse("--body --bearer SHODAN_KEY https://a.example/ --allow-private --timeout 9 --max-redirects 0 --keys k.env")
            .expect("parse");
        assert!(a.print_body && a.allow_private);
        assert_eq!(a.auth, Some(("SHODAN_KEY".into(), AuthStyle::Bearer)));
        assert_eq!((a.max_redirects, a.timeout), (0, Duration::from_secs(9)));
        assert_eq!(a.keys_file, Some(PathBuf::from("k.env")));
        let h = parse("https://a.example/ --header X-Api-Key=PROVIDER_KEY").expect("parse");
        assert_eq!(
            h.auth,
            Some(("PROVIDER_KEY".into(), AuthStyle::Header("X-Api-Key".into())))
        );
    }

    #[test]
    fn bad_input_is_refused_with_a_reason() {
        for bad in [
            "",
            "--body",
            "https://a.example/ https://b.example/",
            "https://a.example/ --nope",
            "https://a.example/ --bearer",
            "https://a.example/ --bearer lowercase",
            "https://a.example/ --header NOEQUALS",
            "https://a.example/ --bearer A_KEY --header X=B_KEY",
            "https://a.example/ --timeout 0",
            "https://a.example/ --timeout 601",
            "https://a.example/ --timeout x",
            "https://a.example/ --max-redirects 21",
            "https://a.example/ --max-redirects -1",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
