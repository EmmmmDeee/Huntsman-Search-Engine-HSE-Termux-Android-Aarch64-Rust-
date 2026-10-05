//! Which process runs a scan, so that another process can tell a scan still
//! being run from one whose process died (REQ-SCANSTATUS-038).
//!
//! `hse serve`, `hse scan`, `hse radar` and `hse live` each run the engine in
//! their own process against one database. A server's in-flight registry
//! knows only its own scans, so a scan another `hse` process is running
//! looked, to the server, exactly like one whose process was killed. The row
//! therefore records its runner: the process id; the process's start time,
//! so that a recycled pid does not pass for the same process; and the boot
//! id, so that a pid from before a reboot does not either.
//!
//! Reading them needs `/proc` (Linux, Android). Where it is missing, a runner
//! cannot be confirmed alive, and a reader falls back to its own registry.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// The process running a scan. Persisted with the scan's row, never
/// serialised anywhere else: see `Scan::runner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRunner {
    /// The process id.
    pub pid: u32,
    /// The process's start time, in clock ticks after boot (field 22 of
    /// `/proc/<pid>/stat`). Zero when it could not be read.
    pub start_ticks: u64,
    /// `/proc/sys/kernel/random/boot_id`. Empty when it could not be read.
    pub boot_id: String,
}

impl ScanRunner {
    /// This process. Read once, then cached.
    #[must_use]
    pub fn current() -> Self {
        static CURRENT: OnceLock<ScanRunner> = OnceLock::new();
        CURRENT
            .get_or_init(|| {
                let pid = std::process::id();
                Self {
                    pid,
                    start_ticks: proc_stat(pid).map_or(0, |s| s.start_ticks),
                    boot_id: boot_id(),
                }
            })
            .clone()
    }

    /// Whether this names the calling process.
    #[must_use]
    pub fn is_this_process(&self) -> bool {
        *self == Self::current()
    }

    /// Whether the process this names is still running: same boot, its pid
    /// exists and started when this says it did, and it is not a zombie. A
    /// runner whose start time was not recorded cannot be confirmed, so it
    /// reads as not running.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.start_ticks != 0
            && self.boot_id == Self::current().boot_id
            && proc_stat(self.pid)
                .is_some_and(|s| s.start_ticks == self.start_ticks && s.is_running())
    }
}

/// The two fields of `/proc/<pid>/stat` a liveness check reads.
#[derive(Debug, PartialEq, Eq)]
struct ProcStat {
    state: char,
    start_ticks: u64,
}

impl ProcStat {
    /// Not a zombie (`Z`) and not dead (`X`, `x`).
    fn is_running(&self) -> bool {
        !matches!(self.state, 'Z' | 'X' | 'x')
    }
}

fn proc_stat(pid: u32) -> Option<ProcStat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Parse `/proc/<pid>/stat`: `pid (comm) state ppid … starttime …`. The
/// command name may hold spaces and parentheses, so fields are counted after
/// the last `)`. The state is field 3 and the start time field 22.
fn parse_stat(stat: &str) -> Option<ProcStat> {
    let mut fields = stat.get(stat.rfind(')')? + 1..)?.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let start_ticks = fields.nth(18)?.parse().ok()?;
    Some(ProcStat { state, start_ticks })
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_are_counted_after_the_last_parenthesis() {
        // A command name with a space and a `)` of its own.
        let stat = "4242 (hse (serve) x) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 3 0 987654 1 2 3";
        assert_eq!(
            parse_stat(stat),
            Some(ProcStat {
                state: 'S',
                start_ticks: 987_654
            })
        );
        assert_eq!(parse_stat("no parenthesis at all"), None);
        assert_eq!(parse_stat("1 (short) S 1 2"), None);
    }

    #[test]
    fn zombies_and_dead_processes_are_not_running() {
        for (state, running) in [
            ('R', true),
            ('S', true),
            ('D', true),
            ('Z', false),
            ('X', false),
        ] {
            assert_eq!(
                ProcStat {
                    state,
                    start_ticks: 1
                }
                .is_running(),
                running,
                "{state}"
            );
        }
    }

    /// The live checks below read `/proc`, so they run where it exists.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_is_alive_and_a_recycled_pid_is_not() {
        let me = ScanRunner::current();
        assert_eq!(me.pid, std::process::id());
        assert!(me.start_ticks > 0, "{me:?}");
        assert!(me.is_this_process());
        assert!(me.is_alive());
        // The same pid with another start time is another process.
        let recycled = ScanRunner {
            start_ticks: me.start_ticks + 1,
            ..me.clone()
        };
        assert!(!recycled.is_alive());
        assert!(!recycled.is_this_process());
        // So is a pid from another boot.
        let other_boot = ScanRunner {
            boot_id: format!("{}-other", me.boot_id),
            ..me.clone()
        };
        assert!(!other_boot.is_alive());
        // And a runner whose start time was never read cannot be confirmed.
        assert!(
            !ScanRunner {
                start_ticks: 0,
                ..me
            }
            .is_alive()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_is_alive_until_it_exits() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let runner = ScanRunner {
            pid: child.id(),
            start_ticks: proc_stat(child.id()).expect("child stat").start_ticks,
            boot_id: ScanRunner::current().boot_id,
        };
        assert!(runner.is_alive(), "a running child is alive");
        assert!(!runner.is_this_process());
        child.kill().expect("kill");
        child.wait().expect("reap");
        assert!(!runner.is_alive(), "an exited child is not");
    }
}
