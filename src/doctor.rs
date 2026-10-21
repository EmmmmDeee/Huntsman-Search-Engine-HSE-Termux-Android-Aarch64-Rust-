//! `doctor`: one report over everything that decides whether this install works, and the
//! reversible repairs `doctor --fix` makes.
//!
//! [`examine`] turns a [`Context`] (what the process boundary read from the environment) and a
//! [`Host`] (the few side effects that run other programs) into a [`Report`] of [`Check`]s. A
//! check that fails or warns names the exact command that fixes it. Where that fix is safe to
//! make without asking, the check carries a [`Repair`] and [`repair`] makes it.
//!
//! Repairs are reversible. They create missing directories and files, tighten permissions,
//! rewrite the install record after the installer's own acceptance passes again (keeping a
//! backup of the old record), and remove a Rust build cache only when Cargo tagged it as a cache
//! and it is stale or the disk is full. A repair never deletes a ledger or scan data, never
//! writes a credential, and never prints one: credentials appear only as counts and provider
//! names.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::diagnostics::{TermuxState, normalized_build_sha};
use crate::fsio::write_atomic_private;
use crate::keys::{DEFAULT_KEYS_FILE, DefaultFileRefusal, Keys, read_private_file};
use crate::ledger::load_chain;
use crate::provider_credentials::{self, ProbeState, ProviderProbeStatus};
use crate::serve_probe::{ServeProbe, ServeState};

/// The repository `install.sh` builds from.
pub const REPOSITORY: &str =
    "https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git";
/// The one-line installer, as README and `docs/INSTALL.md` give it. It rebuilds and reinstalls
/// this binary from `main` and re-runs the install acceptance.
pub const REINSTALL: &str = "curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o \"$TMPDIR/huntsman-install.sh\" && bash \"$TMPDIR/huntsman-install.sh\"";
/// The command that runs every repair `doctor` can make.
pub const FIX: &str = "huntsman-recon fix";
/// The install record `install.sh` writes once its acceptance passes.
pub const PROVENANCE_FILE: &str = "installed-revision";
/// The state directory under `$HOME` when `HUNTSMAN_HOME` is not set.
pub const STATE_DIR: &str = ".huntsman";
/// Where `install.sh` keeps Cargo's build cache when `CARGO_TARGET_DIR` is not set.
pub const BUILD_CACHE: &str = ".cache/huntsman-recon-target";
/// The first line of the `CACHEDIR.TAG` Cargo writes into a target directory. A directory
/// without it is not removed, whatever the install record says.
const CACHEDIR_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";
/// Below this much free space a build or a saved scan can fail part way.
pub const DISK_FAIL_BYTES: u64 = 256 * 1024 * 1024;
/// Below this much free space a source rebuild under Termux may not fit.
pub const DISK_WARN_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROVENANCE_BYTES: u64 = 4096;
const MAX_KEYS_BYTES: u64 = 64 * 1024;
/// Files the ledger scan reads at most, so a huge state directory cannot stall `doctor`.
const MAX_SCANNED_FILES: usize = 2000;
const MAX_SCAN_DEPTH: usize = 4;
/// Entries the build-cache size walk visits at most; past this the size is a lower bound.
const MAX_CACHE_ENTRIES: usize = 500_000;

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// A repair `doctor --fix` makes without asking, because it can be undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repair {
    /// Create the directory (and its parents) with this mode.
    CreateDir { path: PathBuf, mode: u32 },
    /// Set the permission bits of an existing file or directory.
    SetMode { path: PathBuf, mode: u32 },
    /// Create an empty mode-600 file that does not exist yet.
    CreatePrivateFile { path: PathBuf },
    /// Re-run the install acceptance, then record this binary's commit as installed, keeping a
    /// backup of the old record.
    RecordInstall,
    /// Remove a Cargo build cache. Only a directory Cargo tagged with `CACHEDIR.TAG` qualifies.
    ClearBuildCache { path: PathBuf },
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub message: String,
    /// The exact command that fixes a warning or a failure.
    pub fix: Option<String>,
    /// Whether `huntsman-recon fix` makes the repair itself.
    pub auto_fix: bool,
    #[serde(skip)]
    pub repair: Option<Repair>,
}

impl Check {
    fn ok(id: &'static str, message: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Ok,
            message: message.into(),
            fix: None,
            auto_fix: false,
            repair: None,
        }
    }

    fn warn(id: &'static str, message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Warn,
            fix: Some(fix.into()),
            ..Self::ok(id, message)
        }
    }

    fn fail(id: &'static str, message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            fix: Some(fix.into()),
            ..Self::ok(id, message)
        }
    }

    /// Attach a repair `fix` makes itself; the fix command becomes `huntsman-recon fix`.
    fn repaired_by(mut self, repair: Repair) -> Self {
        self.repair = Some(repair);
        self.auto_fix = true;
        self.fix = Some(FIX.to_owned());
        self
    }
}

/// Every check, in the order they print.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// The worst status of any check.
    #[must_use]
    pub fn status(&self) -> Status {
        self.checks
            .iter()
            .map(|check| check.status)
            .max()
            .unwrap_or(Status::Ok)
    }

    /// How many checks came out with `status`.
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|check| check.id == id)
    }
}

/// The key slots as `doctor` sees them: which providers are configured, never a value.
pub enum KeyState<'a> {
    Resolved(&'a Keys),
    /// The keys could not be resolved; the text names the problem without a value.
    Error(String),
}

/// What the process boundary read for `doctor`. Library code does not read the environment.
pub struct Context<'a> {
    /// `$HOME` when it is absolute.
    pub home: Option<PathBuf>,
    /// `$HUNTSMAN_HOME` when it is set and absolute.
    pub state_dir_override: Option<PathBuf>,
    /// `$HUNTSMAN_ENV_FILE` when it is set. `install.sh` creates that file, but `huntsman-recon`
    /// reads only `~/.huntsman.env`.
    pub env_file_override: Option<PathBuf>,
    pub termux: TermuxState,
    /// `$PREFIX`, when it is set.
    pub prefix: Option<PathBuf>,
    /// `$PATH`, split.
    pub path_dirs: Vec<PathBuf>,
    /// `$TMPDIR`, when it is set.
    pub tmpdir: Option<PathBuf>,
    /// The running binary.
    pub current_exe: Option<PathBuf>,
    /// The working directory; its `var/` holds the ledger `check` writes.
    pub cwd: Option<PathBuf>,
    /// This binary's embedded commit, or `unknown`.
    pub build_sha: &'a str,
    pub version: &'a str,
    pub keys: KeyState<'a>,
    /// Live key probes, when `--probe` asked for them.
    pub probes: Option<&'a [ProviderProbeStatus]>,
    pub serve: &'a ServeProbe,
}

impl Context<'_> {
    /// `$HUNTSMAN_HOME`, else `~/.huntsman`.
    #[must_use]
    pub fn state_dir(&self) -> Option<PathBuf> {
        self.state_dir_override
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(STATE_DIR)))
    }

    fn env_file(&self) -> Option<PathBuf> {
        self.home.as_ref().map(|home| home.join(DEFAULT_KEYS_FILE))
    }

    fn provenance_path(&self) -> Option<PathBuf> {
        self.state_dir().map(|dir| dir.join(PROVENANCE_FILE))
    }

    /// `path`, with `$HOME` written as `~` so a report reads the same on every phone.
    fn show(&self, path: &Path) -> String {
        match self
            .home
            .as_ref()
            .and_then(|home| path.strip_prefix(home).ok())
        {
            Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
            Some(rest) => format!("~/{}", rest.display()),
            None => path.display().to_string(),
        }
    }
}

/// The side effects `doctor` needs that run other programs or read the clock.
pub trait Host {
    /// Free bytes on the filesystem holding `path`, when they can be read.
    fn free_bytes(&self, path: &Path) -> Option<u64>;
    /// `rustc --version`, when a Rust compiler is installed.
    fn rustc_version(&self) -> Option<String>;
    /// What `exe build-sha` prints, when it runs.
    fn build_sha_of(&self, exe: &Path) -> Option<String>;
    /// The installer's acceptance: `check` and `verify var/ledger.json` in a fresh directory.
    ///
    /// # Errors
    /// Which step failed, without its output.
    fn acceptance(&self) -> Result<(), String>;
    /// Seconds since the Unix epoch, for backup names.
    fn now_unix(&self) -> u64;
}

/// Run every check.
#[must_use]
pub fn examine(ctx: &Context<'_>, host: &dyn Host) -> Report {
    let provenance = read_provenance(ctx);
    let checks = vec![
        binary(ctx, host),
        build_sha(ctx),
        provenance_check(ctx, &provenance),
        state_dir(ctx),
        env_file(ctx),
        keys(ctx),
        ledgers(ctx),
        selfcheck(host),
        serve(ctx),
        disk(ctx, host, &provenance),
        build_cache(ctx, host, &provenance),
        termux(ctx),
    ];
    Report { checks }
}

fn sha7(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

fn known_sha(sha: &str) -> Option<&str> {
    let sha = normalized_build_sha(sha);
    (sha != "unknown").then_some(sha)
}

fn binary(ctx: &Context<'_>, host: &dyn Host) -> Check {
    const ID: &str = "binary";
    let Some(found) = ctx
        .path_dirs
        .iter()
        .map(|dir| dir.join("huntsman-recon"))
        .find(|candidate| is_executable(candidate))
    else {
        return Check::fail(ID, "huntsman-recon is not on PATH", REINSTALL);
    };
    let same = ctx
        .current_exe
        .as_ref()
        .is_some_and(|exe| same_file(exe, &found));
    if same {
        return Check::ok(ID, ctx.show(&found));
    }
    let theirs = host.build_sha_of(&found);
    match (
        theirs.as_deref().and_then(known_sha),
        known_sha(ctx.build_sha),
    ) {
        (Some(theirs), Some(ours)) if theirs == ours => {
            Check::ok(ID, format!("{} (same build)", ctx.show(&found)))
        }
        (theirs, _) => Check::warn(
            ID,
            format!(
                "PATH runs {} (build {}), not this binary (build {})",
                ctx.show(&found),
                theirs.map_or("unknown", sha7),
                known_sha(ctx.build_sha).map_or("unknown", sha7),
            ),
            REINSTALL,
        ),
    }
}

fn build_sha(ctx: &Context<'_>) -> Check {
    const ID: &str = "build_sha";
    match known_sha(ctx.build_sha) {
        Some(sha) => Check::ok(ID, format!("{} (version {})", sha7(sha), ctx.version)),
        None => Check::warn(
            ID,
            "this binary has no embedded commit, so its install cannot be confirmed",
            REINSTALL,
        ),
    }
}

/// The install record, as `install.sh` writes it: `key=value` lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Provenance {
    revision: Option<String>,
    repository: Option<String>,
    rustc: Option<String>,
    cargo_target_dir: Option<String>,
}

enum ProvenanceRead {
    NoStateDir,
    Missing,
    Unreadable(String),
    Read { record: Provenance, mode: u32 },
}

fn read_provenance(ctx: &Context<'_>) -> ProvenanceRead {
    let Some(path) = ctx.provenance_path() else {
        return ProvenanceRead::NoStateDir;
    };
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProvenanceRead::Missing;
        }
        Err(error) => return ProvenanceRead::Unreadable(error.kind().to_string()),
    };
    if !meta.is_file() {
        return ProvenanceRead::Unreadable("not a regular file".to_owned());
    }
    match crate::fsio::read_bounded(&path, MAX_PROVENANCE_BYTES) {
        Ok(bytes) => ProvenanceRead::Read {
            record: parse_provenance(&String::from_utf8_lossy(&bytes)),
            mode: mode_of(&meta),
        },
        Err(error) => ProvenanceRead::Unreadable(error.to_string()),
    }
}

fn parse_provenance(text: &str) -> Provenance {
    let mut record = Provenance::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = Some(value.trim().to_owned());
        match key.trim() {
            "revision" => record.revision = value,
            "repository" => record.repository = value,
            "rustc" => record.rustc = value,
            "cargo_target_dir" => record.cargo_target_dir = value,
            _ => {}
        }
    }
    record
}

fn render_provenance(record: &Provenance) -> String {
    let mut out = String::new();
    for (key, value) in [
        ("revision", &record.revision),
        ("repository", &record.repository),
        ("rustc", &record.rustc),
        ("cargo_target_dir", &record.cargo_target_dir),
    ] {
        if let Some(value) = value {
            let _ = writeln!(out, "{key}={value}");
        }
    }
    out.push_str("recorded_by=doctor\n");
    out
}

fn provenance_check(ctx: &Context<'_>, read: &ProvenanceRead) -> Check {
    const ID: &str = "provenance";
    let ours = known_sha(ctx.build_sha);
    let record = |check: Check| match ours {
        Some(_) => check.repaired_by(Repair::RecordInstall),
        None => check,
    };
    match read {
        ProvenanceRead::NoStateDir => Check::fail(
            ID,
            "HOME is not set to an absolute path, so there is no install record",
            "export HOME=/data/data/com.termux/files/home",
        ),
        ProvenanceRead::Missing => record(Check::warn(
            ID,
            "no install record (~/.huntsman/installed-revision): not installed by install.sh",
            REINSTALL,
        )),
        ProvenanceRead::Unreadable(why) => Check::fail(
            ID,
            format!("the install record cannot be read: {why}"),
            REINSTALL,
        ),
        ProvenanceRead::Read {
            record: found,
            mode,
        } => {
            let revision = found
                .revision
                .as_deref()
                .map(str::to_ascii_lowercase)
                .filter(|revision| known_sha(revision).is_some());
            let path = ctx.provenance_path().unwrap_or_default();
            match (revision, ours) {
                (None, _) => record(Check::fail(
                    ID,
                    "the install record has no valid revision line",
                    REINSTALL,
                )),
                (Some(revision), Some(ours)) if revision != ours => record(Check::fail(
                    ID,
                    format!(
                        "stale: the install record says {}, but this binary is {}",
                        sha7(&revision),
                        sha7(ours)
                    ),
                    REINSTALL,
                )),
                (Some(revision), None) => Check::warn(
                    ID,
                    format!(
                        "the install record says {}, but this binary has no embedded commit to compare",
                        sha7(&revision)
                    ),
                    REINSTALL,
                ),
                (Some(revision), Some(_)) if mode & 0o077 != 0 => Check::warn(
                    ID,
                    format!("{} is readable by others (mode {mode:o})", ctx.show(&path)),
                    format!("chmod 600 {}", ctx.show(&path)),
                )
                .repaired_by(Repair::SetMode { path, mode: 0o600 })
                .with_note(&format!("matches {}", sha7(&revision))),
                (Some(revision), Some(_)) => Check::ok(
                    ID,
                    format!("installed revision {} matches", sha7(&revision)),
                ),
            }
        }
    }
}

impl Check {
    fn with_note(mut self, note: &str) -> Self {
        let _ = write!(self.message, "; {note}");
        self
    }
}

fn state_dir(ctx: &Context<'_>) -> Check {
    const ID: &str = "state_dir";
    let Some(dir) = ctx.state_dir() else {
        return Check::fail(
            ID,
            "HOME is not set to an absolute path",
            "export HOME=/data/data/com.termux/files/home",
        );
    };
    let shown = ctx.show(&dir);
    match fs::metadata(&dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Check::warn(
            ID,
            format!("{shown} does not exist"),
            format!("mkdir -m 700 {shown}"),
        )
        .repaired_by(Repair::CreateDir {
            path: dir,
            mode: 0o700,
        }),
        Err(error) => Check::fail(
            ID,
            format!("{shown} cannot be read: {}", error.kind()),
            format!("ls -ld {shown}"),
        ),
        Ok(meta) if !meta.is_dir() => Check::fail(
            ID,
            format!("{shown} is not a directory"),
            format!("mv {shown} {shown}.bak && {FIX}"),
        ),
        Ok(meta) => {
            let mode = mode_of(&meta);
            if mode & 0o700 != 0o700 || mode & 0o077 != 0 {
                Check::warn(
                    ID,
                    format!("{shown} has mode {mode:o}, not 700"),
                    format!("chmod 700 {shown}"),
                )
                .repaired_by(Repair::SetMode {
                    path: dir,
                    mode: 0o700,
                })
            } else {
                Check::ok(ID, format!("{shown} (mode 700)"))
            }
        }
    }
}

fn env_file(ctx: &Context<'_>) -> Check {
    const ID: &str = "env_file";
    let Some(path) = ctx.env_file() else {
        return Check::fail(
            ID,
            "HOME is not set to an absolute path, so ~/.huntsman.env is not read",
            "export HOME=/data/data/com.termux/files/home",
        );
    };
    let shown = ctx.show(&path);
    let check = match read_private_file(&path, MAX_KEYS_BYTES) {
        Ok(None) => Check::warn(
            ID,
            format!("{shown} does not exist; keys can only come from the environment"),
            format!("(umask 077; touch {shown})"),
        )
        .repaired_by(Repair::CreatePrivateFile { path: path.clone() }),
        Ok(Some(Err(refusal))) => refusal_check(ID, &path, &shown, refusal),
        Ok(Some(Ok(bytes))) => match String::from_utf8(bytes) {
            Err(_) => Check::fail(
                ID,
                format!("{shown} is not UTF-8, so no key in it is used"),
                format!("huntsman-recon keys {shown}"),
            ),
            Ok(text) => match Keys::parse(&text) {
                Ok(keys) => {
                    let unrecognised = provider_credentials::unrecognised_slots(&keys);
                    if unrecognised.is_empty() {
                        Check::ok(
                            ID,
                            format!("{shown} (mode 600, {} slots set)", keys.slots().len()),
                        )
                    } else {
                        Check::warn(
                            ID,
                            format!(
                                "{shown} (mode 600, {} slots set); {} read by no provider: {}",
                                keys.slots().len(),
                                unrecognised.len(),
                                unrecognised.join(", ")
                            ),
                            "huntsman-recon credential-status",
                        )
                    }
                }
                Err(error) => Check::fail(
                    ID,
                    format!("{shown}: {error}, so no key in it is used"),
                    format!("huntsman-recon keys {shown}"),
                ),
            },
        },
        Err(error) => Check::fail(
            ID,
            format!("{shown} cannot be read: {error}"),
            format!("ls -l {shown}"),
        ),
    };
    match ctx
        .env_file_override
        .as_ref()
        .filter(|other| **other != path)
    {
        Some(other) if check.status == Status::Ok => Check::warn(
            ID,
            format!(
                "HUNTSMAN_ENV_FILE names {}, but huntsman-recon reads only {shown}",
                ctx.show(other)
            ),
            format!("unset HUNTSMAN_ENV_FILE, and keep keys in {shown}"),
        ),
        _ => check,
    }
}

fn refusal_check(id: &'static str, path: &Path, shown: &str, refusal: DefaultFileRefusal) -> Check {
    match refusal {
        DefaultFileRefusal::LoosePermissions { mode } => Check::fail(
            id,
            format!(
                "{shown} has mode {mode:o}; huntsman-recon refuses a keys file others can read, so no key in it is used"
            ),
            format!("chmod 600 {shown}"),
        )
        .repaired_by(Repair::SetMode {
            path: path.to_path_buf(),
            mode: 0o600,
        }),
        DefaultFileRefusal::Symlink => Check::fail(
            id,
            format!("{shown} is a symlink, which huntsman-recon does not follow"),
            format!("cp --remove-destination \"$(readlink -f {shown})\" {shown} && chmod 600 {shown}"),
        ),
        DefaultFileRefusal::NotRegularFile => Check::fail(
            id,
            format!("{shown} is not a regular file"),
            format!("ls -ld {shown}"),
        ),
        DefaultFileRefusal::ForeignOwner { file_uid, current_uid } => Check::fail(
            id,
            format!("{shown} belongs to uid {file_uid}, not you (uid {current_uid})"),
            format!("cp {shown} {shown}.mine && mv -f {shown}.mine {shown} && chmod 600 {shown}"),
        ),
        DefaultFileRefusal::UnknownCurrentUser => Check::fail(
            id,
            "the current uid cannot be read from /proc/self/status, so the keys file is not read",
            "pass --keys FILE to each command",
        ),
        DefaultFileRefusal::ChangedWhileOpening => Check::warn(
            id,
            format!("{shown} changed while doctor read it"),
            "huntsman-recon doctor",
        ),
    }
}

fn keys(ctx: &Context<'_>) -> Check {
    const ID: &str = "keys";
    let keys = match &ctx.keys {
        KeyState::Resolved(keys) => keys,
        KeyState::Error(error) => {
            return Check::fail(
                ID,
                format!("keys could not be loaded: {error}"),
                "huntsman-recon credential-status",
            );
        }
    };
    let status = provider_credentials::status(keys);
    let total = status.len();
    let configured: Vec<&str> = status
        .iter()
        .filter(|provider| provider.configured)
        .map(|provider| provider.name)
        .collect();
    if configured.is_empty() {
        return Check::warn(
            ID,
            format!("0 of {total} providers have a key; lookups run keyless sources only"),
            "huntsman-recon credential-status",
        );
    }
    let mut message = format!(
        "{} of {total} providers have a key: {}",
        configured.len(),
        configured.join(", ")
    );
    let Some(probes) = ctx.probes else {
        return Check::ok(ID, message);
    };
    let named = |state: ProbeState| -> Vec<&str> {
        probes
            .iter()
            .filter(|probe| probe.probe == state)
            .map(|probe| probe.provider.name)
            .collect()
    };
    let rejected = named(ProbeState::Rejected);
    let limited = named(ProbeState::RateLimited);
    let unavailable = named(ProbeState::Unavailable);
    let valid = named(ProbeState::Valid);
    let _ = write!(message, "; {} answered valid", valid.len());
    if !rejected.is_empty() {
        return Check::fail(
            ID,
            format!("{message}; rejected: {}", rejected.join(", ")),
            "replace the rejected keys in ~/.huntsman.env, then run huntsman-recon doctor --probe",
        );
    }
    if !limited.is_empty() || !unavailable.is_empty() {
        let mut notes = Vec::new();
        if !limited.is_empty() {
            notes.push(format!("rate limited: {}", limited.join(", ")));
        }
        if !unavailable.is_empty() {
            notes.push(format!("no answer: {}", unavailable.join(", ")));
        }
        return Check::warn(
            ID,
            format!("{message}; {}", notes.join("; ")),
            "huntsman-recon doctor --probe",
        );
    }
    Check::ok(ID, message)
}

/// Ledgers in the state directory, in the working directory and in its `var/`. A file is a
/// ledger when its name says so or its JSON is a hash chain.
fn ledgers(ctx: &Context<'_>) -> Check {
    const ID: &str = "ledgers";
    let mut files = Vec::new();
    if let Some(dir) = ctx.state_dir() {
        json_files(&dir, MAX_SCAN_DEPTH, &mut files);
    }
    if let Some(cwd) = &ctx.cwd {
        json_files(cwd, 0, &mut files);
        json_files(&cwd.join("var"), 0, &mut files);
    }
    files.sort();
    files.dedup();
    let mut checked = 0;
    let mut broken = Vec::new();
    for path in files {
        let named = path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.contains("ledger"));
        if !named && !looks_like_ledger(&path) {
            continue;
        }
        checked += 1;
        if let Err(error) = load_chain(&path) {
            broken.push(format!("{} ({error})", ctx.show(&path)));
        }
    }
    match broken.as_slice() {
        [] => Check::ok(ID, format!("{checked} ledgers verified")),
        [only] => Check::fail(
            ID,
            format!("broken ledger: {only}"),
            format!(
                "huntsman-recon verify {}  (doctor never deletes a ledger: restore it from a copy, or move it aside)",
                only.split(" (").next().unwrap_or(only)
            ),
        ),
        many => Check::fail(
            ID,
            format!("{} broken ledgers: {}", many.len(), many.join("; ")),
            "huntsman-recon verify FILE for each  (doctor never deletes a ledger: restore it from a copy, or move it aside)",
        ),
    }
}

fn json_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_SCANNED_FILES {
            return;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() && depth > 0 {
            json_files(&path, depth - 1, out);
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
}

/// Whether the file is a JSON array whose first element has `prev` and `hash`, as a ledger's is.
/// Only the first kilobyte is read.
fn looks_like_ledger(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0_u8; 1024];
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let Ok(read) = file.read(&mut head) else {
        return false;
    };
    let head = String::from_utf8_lossy(&head[..read]);
    let head = head.trim_start();
    head.starts_with('[') && head.contains("\"prev\"") && head.contains("\"hash\"")
}

fn selfcheck(host: &dyn Host) -> Check {
    const ID: &str = "selfcheck";
    match host.acceptance() {
        Ok(()) => Check::ok(ID, "offline self-acceptance and ledger verification pass"),
        Err(why) => Check::fail(
            ID,
            format!("offline self-acceptance failed: {why}"),
            REINSTALL,
        ),
    }
}

fn serve(ctx: &Context<'_>) -> Check {
    const ID: &str = "serve";
    let probe = ctx.serve;
    let addr = &probe.addr;
    let rebind = "huntsman-recon serve --bind 127.0.0.1:8081";
    match probe.state {
        ServeState::NotRunning => Check::ok(
            ID,
            format!("not running on {addr} (start it with huntsman-recon serve)"),
        ),
        ServeState::Healthy => match probe.version.as_deref() {
            Some(version) if version != ctx.version => Check::warn(
                ID,
                format!(
                    "{addr} runs version {version}, but this binary is {}: restart serve to use it",
                    ctx.version
                ),
                "stop the running serve (Ctrl-C where it runs), then huntsman-recon serve",
            ),
            _ => Check::ok(
                ID,
                format!(
                    "running on {addr}: page, policy and analysis work ({} ms)",
                    probe.elapsed_ms
                ),
            ),
        },
        // A loopback serve needs no token, so only a public bind, or a build from before that,
        // still asks for one.
        ServeState::Unauthorized => Check::warn(
            ID,
            format!("running on {addr}, and it asks for a token this shell does not send"),
            "on the phone: huntsman restart (a current build needs no token on loopback); on a public bind: export HSE_AUTH_TOKEN=<the token serve was started with>",
        ),
        ServeState::Foreign => Check::fail(
            ID,
            format!("another program holds {addr}, so huntsman-recon serve cannot start there"),
            rebind,
        ),
        ServeState::Degraded => Check::fail(
            ID,
            format!(
                "running on {addr} but broken: {}",
                probe.problems.join("; ")
            ),
            "stop the running serve (Ctrl-C where it runs), then huntsman-recon serve",
        ),
    }
}

fn mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

fn cache_dir(ctx: &Context<'_>, provenance: &ProvenanceRead) -> Option<PathBuf> {
    let recorded = match provenance {
        ProvenanceRead::Read { record, .. } => record
            .cargo_target_dir
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.is_absolute()),
        _ => None,
    };
    recorded.or_else(|| ctx.home.as_ref().map(|home| home.join(BUILD_CACHE)))
}

/// A directory Cargo tagged as its build cache.
fn tagged_cache(dir: &Path) -> bool {
    fs::read_to_string(dir.join("CACHEDIR.TAG"))
        .is_ok_and(|tag| tag.starts_with(CACHEDIR_SIGNATURE))
}

fn disk(ctx: &Context<'_>, host: &dyn Host, provenance: &ProvenanceRead) -> Check {
    const ID: &str = "disk";
    let mut places: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(home) = &ctx.home {
        places.push(("home", home.clone()));
    }
    if let Some(tmp) = &ctx.tmpdir {
        places.push(("tmp", tmp.clone()));
    }
    let measured: Vec<(&str, u64)> = places
        .iter()
        .filter_map(|(name, path)| host.free_bytes(path).map(|free| (*name, free)))
        .collect();
    let Some(&(tightest, free)) = measured.iter().min_by_key(|(_, free)| *free) else {
        return Check::ok(ID, "free space could not be measured");
    };
    let summary = measured
        .iter()
        .map(|(name, free)| format!("{name} {} MiB free", mib(*free)))
        .collect::<Vec<_>>()
        .join(", ");
    if free >= DISK_WARN_BYTES {
        return Check::ok(ID, summary);
    }
    let cache = cache_dir(ctx, provenance).filter(|dir| tagged_cache(dir));
    if free < DISK_FAIL_BYTES {
        let check = Check::fail(
            ID,
            format!("{summary}: {tightest} is nearly full"),
            "delete large files you no longer need, then huntsman-recon doctor",
        );
        return match cache {
            Some(path) => {
                let shown = ctx.show(&path);
                check
                    .repaired_by(Repair::ClearBuildCache { path })
                    .with_note(&format!(
                        "fix removes the build cache {shown}; the next install rebuilds it"
                    ))
            }
            None => check,
        };
    }
    Check::warn(
        ID,
        format!("{summary}: a source rebuild needs about 1 GiB"),
        match cache {
            Some(path) => format!(
                "rm -rf {}  (the build cache; the next install rebuilds it)",
                ctx.show(&path)
            ),
            None => "delete large files you no longer need".to_owned(),
        },
    )
}

fn build_cache(ctx: &Context<'_>, host: &dyn Host, provenance: &ProvenanceRead) -> Check {
    const ID: &str = "build_cache";
    let Some(dir) = cache_dir(ctx, provenance) else {
        return Check::ok(ID, "no build cache");
    };
    let shown = ctx.show(&dir);
    if !dir.is_dir() {
        return Check::ok(ID, format!("no build cache at {shown}"));
    }
    let size = format!("{} MiB", mib(dir_size(&dir)));
    let built_with = match provenance {
        ProvenanceRead::Read { record, .. } => record.rustc.clone(),
        _ => None,
    };
    let now = host.rustc_version();
    match (built_with, now) {
        (Some(then), Some(now)) if then.trim() != now.trim() => {
            let check = Check::warn(
                ID,
                format!(
                    "{shown} ({size}) was built by {then}, but rustc is now {now}: Cargo cannot reuse any of it"
                ),
                format!("rm -rf {shown}"),
            );
            if tagged_cache(&dir) {
                check.repaired_by(Repair::ClearBuildCache { path: dir })
            } else {
                check
            }
        }
        _ => Check::ok(ID, format!("{shown} ({size}), reused by the next install")),
    }
}

fn termux(ctx: &Context<'_>) -> Check {
    const ID: &str = "termux";
    if ctx.termux == TermuxState::NotDetected {
        return Check::ok(
            ID,
            format!(
                "not Termux ({} {})",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        );
    }
    let Some(prefix) = &ctx.prefix else {
        return Check::fail(
            ID,
            "PREFIX is not set; open a new Termux session",
            "exit, then open Termux again",
        );
    };
    if !prefix.starts_with("/data/data/com.termux") {
        return Check::fail(
            ID,
            format!(
                "PREFIX is {}, not under /data/data/com.termux",
                prefix.display()
            ),
            "export PREFIX=/data/data/com.termux/files/usr",
        );
    }
    let bin = prefix.join("bin");
    if !ctx.path_dirs.contains(&bin) {
        return Check::warn(
            ID,
            "$PREFIX/bin is not on PATH, so installed commands are not found",
            "export PATH=\"$PREFIX/bin:$PATH\"",
        );
    }
    match &ctx.tmpdir {
        Some(tmp) if tmp.is_dir() => Check::ok(ID, format!("PREFIX {}", prefix.display())),
        Some(tmp) => Check::warn(
            ID,
            format!(
                "TMPDIR {} does not exist; the installer needs it",
                tmp.display()
            ),
            "mkdir -p \"$TMPDIR\"",
        ),
        None => Check::warn(
            ID,
            "TMPDIR is not set; the installer needs it",
            "export TMPDIR=\"$PREFIX/tmp\"",
        ),
    }
}

/// What one repair did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Repaired {
    pub check: &'static str,
    pub action: String,
    pub ok: bool,
    /// Why it failed, when it did.
    pub error: Option<String>,
}

/// Make every repair the report carries, state directory first. Each runs once even when two
/// checks ask for it. Run [`examine`] again afterwards to see what is left.
#[must_use]
pub fn repair(ctx: &Context<'_>, report: &Report, host: &dyn Host) -> Vec<Repaired> {
    let mut planned: Vec<(&'static str, &Repair)> = report
        .checks
        .iter()
        .filter_map(|check| check.repair.as_ref().map(|repair| (check.id, repair)))
        .collect();
    planned.sort_by_key(|(_, repair)| match repair {
        Repair::CreateDir { .. } => 0,
        Repair::SetMode { .. } => 1,
        Repair::CreatePrivateFile { .. } => 2,
        Repair::RecordInstall => 3,
        Repair::ClearBuildCache { .. } => 4,
    });
    let mut done: Vec<&Repair> = Vec::new();
    let mut out = Vec::new();
    for (check, repair) in planned {
        if done.contains(&repair) {
            continue;
        }
        done.push(repair);
        let (action, result) = apply(ctx, repair, host);
        out.push(Repaired {
            check,
            action,
            ok: result.is_ok(),
            error: result.err(),
        });
    }
    out
}

fn apply(ctx: &Context<'_>, repair: &Repair, host: &dyn Host) -> (String, Result<(), String>) {
    match repair {
        Repair::CreateDir { path, mode } => (
            format!("created {} (mode {mode:o})", ctx.show(path)),
            fs::create_dir_all(path)
                .and_then(|()| set_mode(path, *mode))
                .map_err(|error| error.to_string()),
        ),
        Repair::SetMode { path, mode } => (
            format!("set {} to mode {mode:o}", ctx.show(path)),
            set_mode(path, *mode).map_err(|error| error.to_string()),
        ),
        Repair::CreatePrivateFile { path } => (
            format!("created an empty {} (mode 600)", ctx.show(path)),
            create_private_file(path).map_err(|error| error.to_string()),
        ),
        Repair::RecordInstall => record_install(ctx, host),
        Repair::ClearBuildCache { path } => (
            format!("removed the build cache {}", ctx.show(path)),
            clear_build_cache(path),
        ),
    }
}

fn create_private_file(path: &Path) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map(drop)
}

fn record_install(ctx: &Context<'_>, host: &dyn Host) -> (String, Result<(), String>) {
    let Some(sha) = known_sha(ctx.build_sha) else {
        return (
            "kept the install record".to_owned(),
            Err("this binary has no embedded commit".to_owned()),
        );
    };
    let Some(path) = ctx.provenance_path() else {
        return (
            "kept the install record".to_owned(),
            Err("HOME is not an absolute path".to_owned()),
        );
    };
    let action = format!("recorded {} as installed in {}", sha7(sha), ctx.show(&path));
    let result = (|| {
        host.acceptance()
            .map_err(|why| format!("acceptance failed, record kept: {why}"))?;
        let old = match read_provenance(ctx) {
            ProvenanceRead::Read { record, .. } => record,
            _ => Provenance::default(),
        };
        if path.exists() {
            let backup = path.with_file_name(format!("{PROVENANCE_FILE}.bak-{}", host.now_unix()));
            fs::copy(&path, &backup).map_err(|error| format!("backup: {error}"))?;
            set_mode(&backup, 0o600).map_err(|error| format!("backup: {error}"))?;
        }
        let record = Provenance {
            revision: Some(sha.to_owned()),
            repository: old.repository.or_else(|| Some(REPOSITORY.to_owned())),
            rustc: host.rustc_version().or(old.rustc),
            cargo_target_dir: old.cargo_target_dir.or_else(|| {
                ctx.home
                    .as_ref()
                    .map(|home| home.join(BUILD_CACHE).display().to_string())
            }),
        };
        write_atomic_private(
            &path,
            render_provenance(&record).as_bytes(),
            MAX_PROVENANCE_BYTES,
        )
        .map_err(|error| error.to_string())
    })();
    (action, result)
}

fn clear_build_cache(path: &Path) -> Result<(), String> {
    if !tagged_cache(path) {
        return Err("no Cargo CACHEDIR.TAG there, so it is kept".to_owned());
    }
    fs::remove_dir_all(path).map_err(|error| error.to_string())
}

/// Total size of the files under `dir`, without following symlinks.
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0_u64;
    let mut visited = 0_usize;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_CACHE_ENTRIES {
                return total;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// The report as text: one line per check, its fix under it, then one summary line. A fix
/// already printed for an earlier check is not repeated.
#[must_use]
pub fn render(report: &Report) -> String {
    let mut out = String::new();
    let mut shown: Vec<&str> = Vec::new();
    for check in &report.checks {
        let _ = writeln!(
            out,
            "{:<4} {:<11} {}",
            check.status.as_str(),
            check.id,
            check.message
        );
        match check.fix.as_deref() {
            Some(fix) if shown.contains(&fix) => {
                out.push_str("     fix: the same command as above\n");
            }
            Some(fix) => {
                shown.push(fix);
                let _ = writeln!(out, "     fix: {fix}");
            }
            None => {}
        }
    }
    let _ = writeln!(
        out,
        "doctor={} ok={} warn={} fail={}",
        report.status().as_str(),
        report.count(Status::Ok),
        report.count(Status::Warn),
        report.count(Status::Fail)
    );
    out
}

/// The repairs as text, one line each.
#[must_use]
pub fn render_repairs(repairs: &[Repaired]) -> String {
    let mut out = String::new();
    if repairs.is_empty() {
        out.push_str("repaired: nothing needed an automatic repair\n");
    }
    for repaired in repairs {
        match &repaired.error {
            None => {
                let _ = writeln!(out, "repaired {}: {}", repaired.check, repaired.action);
            }
            Some(error) => {
                let _ = writeln!(
                    out,
                    "not repaired {}: {} failed: {error}",
                    repaired.check, repaired.action
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
