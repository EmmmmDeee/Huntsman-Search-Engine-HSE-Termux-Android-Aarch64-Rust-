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

/// Commands that OWN the update decision and must never have this opportunistic
/// check run underneath them.
///
/// `Serve` and `Update` were always here. `Repair` joins them because it carries
/// its own update stage and its own `--no-update` opt-out: without this, a
/// `hse repair --no-update` still performed a network check and could apply an
/// update in the background, which makes the flag a lie. Observed rather than
/// reasoned — a `--dry-run --no-update` against a pristine HOME left an
/// `hse-autoupdate` stamp behind, which is how the check announced itself.
fn owns_its_update_decision(command: &Command) -> bool {
    matches!(
        command,
        Command::Serve { .. } | Command::Update { .. } | Command::Repair { .. }
    )
}

pub(super) async fn maybe_auto_update(command: &Command) {
    if owns_its_update_decision(command) {
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
        assert!(owns_its_update_decision(&Command::Serve {
            bind: "127.0.0.1:8080".into(),
            no_key_write: false,
        }));
        assert!(owns_its_update_decision(&Command::Update {
            check: false,
            r#ref: None,
        }));
        assert!(!owns_its_update_decision(&Command::Doctor { live: false }));
    }

    /// `hse repair` runs its own update stage and offers `--no-update`, so the
    /// opportunistic checker must not also fire underneath it — otherwise
    /// `--no-update` still reaches the network and can apply an update in the
    /// background, which is the opposite of what the flag says.
    ///
    /// Asserted for EVERY flag combination, because the exemption is a property
    /// of the command, not of how it was invoked: an operator who passes
    /// `--no-update` and one who does not must both get exactly one update
    /// decision, made by the repair stage.
    #[test]
    fn repair_owns_its_own_update_decision() {
        for (dry_run, deep, no_update, json) in [
            (false, false, false, false),
            (true, true, true, true),
            (false, false, true, false),
            (true, false, false, true),
        ] {
            assert!(
                owns_its_update_decision(&Command::Repair {
                    dry_run,
                    deep,
                    no_update,
                    json,
                }),
                "repair must own its update decision (dry_run={dry_run}, deep={deep}, \
                 no_update={no_update}, json={json})"
            );
        }
    }
}
