//! Thin CLI adapter for the application update service.

use crate::{
    app::update::{self, AutoUpdateOutcome},
    core::error::Result,
};

use super::Command;

pub(super) async fn cmd_update(check: bool, ref_: Option<String>) -> Result<()> {
    println!("hse {} — update", crate::VERSION);

    if check {
        match update::find_install_dir() {
            Some(dir) => {
                print!("Source: {}  ", dir.display());
                match update::commits_behind(&dir) {
                    Some(0) => println!("Already up to date."),
                    Some(n) => {
                        println!("{n} commit(s) available — run `hse update` to install.");
                        for line in update::changelog_lines(&dir).iter().take(20) {
                            println!("  {line}");
                        }
                    }
                    None => println!("(could not reach remote — offline?)"),
                }
            }
            None => {
                println!("Source directory not found.");
                println!("Re-run the installer to get updates:");
                println!("  {}", update::INSTALL_CMD);
            }
        }
        return Ok(());
    }

    update::apply_update(ref_).await
}

pub(super) async fn maybe_auto_update(command: &Command) {
    if matches!(command, Command::Serve { .. } | Command::Update { .. }) {
        return;
    }

    match update::maybe_auto_update().await {
        AutoUpdateOutcome::None => {}
        AutoUpdateOutcome::Applying { commits, log } => eprintln!(
            "hse: {commits} commit(s) behind GitHub main — applying the update in the \
             background (log: {}). This run uses the current build; the next run \
             picks up the rebuilt one. Disable with `hse config feature.auto_update off`.",
            log.display()
        ),
        AutoUpdateOutcome::Available { commits } => eprintln!(
            "hse: {commits} commit(s) available on GitHub main — run `hse update` to install \
             (auto-update is off; silence with `hse config feature.update_notify off`)."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_owners_skip_opportunistic_check() {
        assert!(matches!(
            Command::Serve {
                bind: "127.0.0.1:8080".into(),
                no_key_write: false,
            },
            Command::Serve { .. } | Command::Update { .. }
        ));
        assert!(matches!(
            Command::Update {
                check: false,
                r#ref: None,
            },
            Command::Serve { .. } | Command::Update { .. }
        ));
        assert!(!matches!(
            Command::Doctor { live: false },
            Command::Serve { .. } | Command::Update { .. }
        ));
    }
}
