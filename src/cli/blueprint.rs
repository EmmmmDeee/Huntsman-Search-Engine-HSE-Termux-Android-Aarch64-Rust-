//! `blueprint`: the OSINT app blueprint ([`huntsman_recon::osint_blueprint`]) as text, JSON or
//! a Word document.

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::exit::{EX_IOERR, EX_USAGE};
use huntsman_recon::osint_blueprint::{self, ENTRIES};

use super::{fail, terminal_json_pretty};

pub(super) const BLUEPRINT_HELP: &str = "blueprint [--json] [--docx FILE|-]\nThe OSINT app blueprint: each Android app an investigator uses for OSINT (cell and radio survey, Wi-Fi, app analysis, network, location, media metadata), its package, source, licence and features, the Huntsman modules and commands that reproduce it in Rust on a rootless Termux phone, its Termux requirements, priority, status (implemented, partial, planned, or not feasible without root) with the gap or limit, and its acceptance criterion. Without options, one line per app: priority, status, app, category, commands. --json prints every field; --docx writes it as a Word document to FILE (or standard output for -), the document committed as docs/OSINT_APK_BLUEPRINT.docx. Offline.";

/// The largest blueprint document written; it is tens of kilobytes.
const MAX_DOCX_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn blueprint_cmd(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => {
            print!("{}", osint_blueprint::render());
            ExitCode::SUCCESS
        }
        ["--json"] => match terminal_json_pretty(
            &serde_json::json!({ "count": ENTRIES.len(), "entries": ENTRIES }),
        ) {
            Ok(body) => {
                println!("{body}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(EX_IOERR, &format!("blueprint: {error}")),
        },
        ["--docx", "-"] => {
            let mut out = std::io::stdout().lock();
            match out
                .write_all(&osint_blueprint::docx())
                .and_then(|()| out.flush())
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(EX_IOERR, &format!("blueprint: {error}")),
            }
        }
        ["--docx", path] => {
            match huntsman_recon::fsio::write_atomic(
                Path::new(path),
                &osint_blueprint::docx(),
                MAX_DOCX_BYTES,
            ) {
                Ok(()) => {
                    eprintln!("blueprint: wrote {path}");
                    ExitCode::SUCCESS
                }
                Err(error) => fail(EX_IOERR, &format!("blueprint: {error}")),
            }
        }
        _ => fail(
            EX_USAGE,
            "usage: huntsman-recon blueprint [--json] [--docx FILE|-]",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::help::command_help;
    use huntsman_recon::osint_blueprint::ENTRIES;

    /// The words of a help's synopsis, its first line: each alternative of `a|b` and each
    /// bracketed option is a word of its own.
    fn synopsis(help: &str) -> Vec<&str> {
        help.lines()
            .next()
            .unwrap_or_default()
            .split(|c: char| c.is_whitespace() || matches!(c, '|' | '[' | ']'))
            .filter(|word| !word.is_empty())
            .collect()
    }

    /// A blueprint entry may only name commands the dispatcher has: the first word is a command
    /// with help, and every further word (a subcommand or the argument form) is a whole word of
    /// that help's synopsis, so a subcommand the command lacks cannot pass by appearing in prose.
    #[test]
    fn every_command_the_blueprint_names_is_one_huntsman_dispatches() {
        for entry in ENTRIES {
            for command in entry.commands {
                let mut words = command.split_whitespace();
                let name = words.next().expect("a command");
                let help = command_help(name)
                    .unwrap_or_else(|| panic!("{}: {name} is not a command", entry.app));
                let known = synopsis(help);
                for word in words {
                    assert!(
                        known.contains(&word),
                        "{}: `{command}`: {word} is not in {name}'s synopsis {known:?}",
                        entry.app
                    );
                }
            }
        }
        assert!(command_help("blueprint").is_some());
        // Prose does not count: `sweep` is in radar's help text, not its synopsis.
        assert!(command_help("radar").is_some_and(|help| help.contains("sweep")));
        assert!(!synopsis(command_help("radar").unwrap_or_default()).contains(&"sweep"));
    }
}
