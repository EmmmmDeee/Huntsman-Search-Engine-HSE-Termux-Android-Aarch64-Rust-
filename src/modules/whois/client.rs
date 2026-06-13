//! Async WHOIS TCP client with referral-following.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::QUERY_TIMEOUT_MS;
use super::parse::starts_with_ascii_ci;

/// Open a TCP connection to `server` (host:port), send `q\r\n`, and read up
/// to 64 KiB of the response. Both connect and read are capped at
/// [`QUERY_TIMEOUT_MS`].
pub(super) async fn query(server: &str, q: &str) -> std::io::Result<String> {
    let mut stream = timeout(
        Duration::from_millis(QUERY_TIMEOUT_MS),
        TcpStream::connect(server),
    )
    .await??;
    let mut query_line = String::with_capacity(q.len() + 2);
    query_line.push_str(q);
    query_line.push_str("\r\n");
    stream.write_all(query_line.as_bytes()).await?;
    let mut buf = String::with_capacity(4096);
    // Cap the read at 64 KiB so a malicious or misconfigured whois server
    // can't OOM the engine by streaming forever. Real WHOIS responses are
    // ≪ 64 KiB (typically 2–8 KiB).
    timeout(
        Duration::from_millis(QUERY_TIMEOUT_MS),
        (&mut stream).take(65_536).read_to_string(&mut buf),
    )
    .await??;
    Ok(buf)
}

/// Scan `text` for a `whois:` or `refer:` line and return the value if found.
/// Used to follow IANA referrals to the authoritative whois server.
pub(super) fn find_referral(text: &str) -> Option<String> {
    for line in text.lines() {
        // Use the zero-alloc helper for consistency with field() /
        // all_fields() below. The previous per-line `to_lowercase()`
        // allocation here contradicted the v0.5 "zero allocation" promise.
        if (starts_with_ascii_ci(line, "whois:") || starts_with_ascii_ci(line, "refer:"))
            && let Some((_, rest)) = line.split_once(':')
        {
            let v = rest.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}
