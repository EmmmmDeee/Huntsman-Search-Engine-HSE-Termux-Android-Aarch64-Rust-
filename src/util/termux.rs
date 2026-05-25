use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
    let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
    let output = timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()? // outer timeout
        .ok()?; // spawn/io error (incl. NotFound when termux-api missing)
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}
