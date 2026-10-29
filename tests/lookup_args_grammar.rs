//! The `--save FILE` grammar that the lookup front-ends share, pinned through their public parsers.
//! Each parser must keep the same error text and the same error order, whichever module owns the
//! grammar.

use std::path::Path;

use huntsman_recon::email_cli::EmailArgs;
use huntsman_recon::error::Error;
use huntsman_recon::people_cli::PeopleArgs;
use huntsman_recon::phone_cli::PhoneArgs;
use huntsman_recon::username_cli::UsernameArgs;

fn tokens(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

/// Every front-end must refuse `args` with the same grammar error, so the grammar error has to be
/// reported before any positional value is checked.
fn assert_refused_by_every_front_end(args: &[&str], message: &str) {
    let args = tokens(args);
    let expected = Error::Invalid(message.to_owned());
    assert_eq!(
        UsernameArgs::parse(&args).unwrap_err(),
        expected,
        "username: {args:?}"
    );
    assert_eq!(
        EmailArgs::parse(&args).unwrap_err(),
        expected,
        "email: {args:?}"
    );
    assert_eq!(
        PhoneArgs::parse(&args).unwrap_err(),
        expected,
        "phone: {args:?}"
    );
    assert_eq!(
        PeopleArgs::parse(&args).unwrap_err(),
        expected,
        "people: {args:?}"
    );
}

#[test]
fn a_repeated_save_is_refused_before_its_value_is_read() {
    assert_refused_by_every_front_end(&["jane", "--save", "a.json", "--save"], "only one --save");
    assert_refused_by_every_front_end(
        &["jane", "--save", "a.json", "--save", "b.json"],
        "only one --save",
    );
}

#[test]
fn a_save_without_a_usable_path_is_refused() {
    assert_refused_by_every_front_end(&["jane", "--save"], "--save needs a value");
    assert_refused_by_every_front_end(&["--save"], "--save needs a value");
    assert_refused_by_every_front_end(&["jane", "--save", ""], "--save needs a file path");
    assert_refused_by_every_front_end(&["jane", "--save", "--json"], "--save needs a file path");
}

#[test]
fn the_first_bad_option_decides_the_error() {
    assert_refused_by_every_front_end(&["jane", "--json"], "unknown option --json");
    assert_refused_by_every_front_end(
        &["--json", "--save", "a.json", "--save"],
        "unknown option --json",
    );
}

#[test]
fn each_front_end_keeps_its_own_positional_rule() {
    assert_eq!(
        UsernameArgs::parse(&tokens(&["--save", "a.json"])).unwrap_err(),
        Error::Invalid("username needs exactly one HANDLE".into())
    );
    assert_eq!(
        UsernameArgs::parse(&tokens(&["jane", "doe"])).unwrap_err(),
        Error::Invalid("username needs exactly one HANDLE".into())
    );
    assert_eq!(
        EmailArgs::parse(&tokens(&["--save", "a.json"])).unwrap_err(),
        Error::Invalid("email needs exactly one ADDR".into())
    );
    assert_eq!(
        PhoneArgs::parse(&tokens(&["--save", "a.json"])).unwrap_err(),
        Error::Invalid("phone needs exactly one NUMBER".into())
    );
    assert_eq!(
        PeopleArgs::parse(&tokens(&["--save", "a.json"])).unwrap_err(),
        Error::Invalid("missing NAME".into())
    );
}

#[test]
fn valid_arguments_keep_their_save_path_and_positionals() {
    let username = UsernameArgs::parse(&tokens(&["@Jane.Doe", "--save", "out.json"])).unwrap();
    // Original case is preserved (only `@` and surrounding space are stripped): the case-sensitive
    // Hacker News leg needs it, and every other username source case-folds again downstream.
    assert_eq!(username.username, "Jane.Doe");
    assert_eq!(username.save.as_deref(), Some(Path::new("out.json")));

    let email = EmailArgs::parse(&tokens(&["jane@example.org", "--save", "mail.json"])).unwrap();
    assert_eq!(email.save.as_deref(), Some(Path::new("mail.json")));

    let phone = PhoneArgs::parse(&tokens(&["--save", "phone.json", "0412 345 678"])).unwrap();
    assert_eq!(phone.save.as_deref(), Some(Path::new("phone.json")));

    let people = PeopleArgs::parse(&tokens(&["Ada", "--save", "p.json", "Lovelace"])).unwrap();
    assert_eq!(people.name, "Ada Lovelace");
    assert_eq!(people.save.as_deref(), Some(Path::new("p.json")));
}
