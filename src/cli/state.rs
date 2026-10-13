//! The operator's private state directory, `$HOME/.huntsman`, shared by commands that persist.

use std::path::PathBuf;

/// `$HOME/.huntsman`, or `$HOME/.huntsman/SUB` when `sub` is given, each created mode 700 when
/// absent. An unset or relative `HOME` is an error naming the flag or file that avoids it.
pub(in crate::cli) fn state_dir(sub: Option<&str>) -> Result<PathBuf, String> {
    let home = huntsman_recon::environment::home()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("HOME is not an absolute path")?;
    let mut dir = home.join(".huntsman");
    create_private(&dir)?;
    if let Some(sub) = sub {
        dir.push(sub);
        create_private(&dir)?;
    }
    Ok(dir)
}

fn create_private(dir: &std::path::Path) -> Result<(), String> {
    if dir.is_dir() {
        return Ok(());
    }
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))
}
