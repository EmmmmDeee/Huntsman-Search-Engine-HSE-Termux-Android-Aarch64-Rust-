//! Async WHOIS TCP client with referral-following.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

use super::QUERY_TIMEOUT_MS;
use super::parse::starts_with_ascii_ci;

/// Open a TCP connection to `server`, send `q\r\n`, and read up to 64 KiB of the
/// response. Both connect and read are capped at [`QUERY_TIMEOUT_MS`]. Generic
/// over the address so the referral path can pass a pre-vetted, **pinned**
/// [`SocketAddr`] (see [`resolve_public_whois`]) while the IANA bootstrap passes
/// the trusted constant host string.
pub(super) async fn query<A: tokio::net::ToSocketAddrs>(
    server: A,
    q: &str,
) -> std::io::Result<String> {
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

/// SSRF gate for the referral path (PROBLEM_TREE §7 S2): the referral server is
/// taken **verbatim** from the (attacker-influenceable) WHOIS response, and this
/// raw TCP/43 path bypasses the HTTP `SsrfResolver`. Resolve `server` to a vetted,
/// **public** `:43` [`SocketAddr`] — or `None` if the port isn't 43, the host is a
/// local domain, or every resolved address is private/loopback/link-local — so a
/// malicious `refer: 127.0.0.1:6379` / `169.254.169.254:80` can never be dialled.
/// Returning a concrete address also **pins** the connection (no resolve-then-
/// connect rebind window).
pub(super) async fn resolve_public_whois(server: &str) -> Option<SocketAddr> {
    // Normalise to (host, port); default 43. Handle `[v6]:port`, `host:port`, a
    // bare v6 literal (multiple colons, no brackets), and a bare host.
    let (host, port): (&str, u16) = if let Some(rest) = server.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let p = match tail.strip_prefix(':') {
            Some(s) => s.parse().ok()?,
            None => 43,
        };
        (h, p)
    } else if server.matches(':').count() == 1 {
        let (h, p) = server.split_once(':')?;
        (h, p.parse().ok()?)
    } else {
        (server, 43)
    };
    // Refuse any port but whois/43 — the referral must not widen the reach.
    if port != 43 {
        return None;
    }
    if crate::util::preflight::is_local_domain(host) {
        return None;
    }
    // Resolve and keep only a public address (also pins the dial target).
    lookup_host((host, port))
        .await
        .ok()?
        .find(|a| !crate::util::preflight::is_private_addr(a.ip()))
}

#[cfg(test)]
mod tests {
    use super::resolve_public_whois;

    #[tokio::test]
    async fn blocks_ssrf_and_non_whois_referrals() {
        // §7 S2: a referral host taken from the WHOIS response must never dial a
        // private/internal address or a non-43 port. (Hermetic: IP literals +
        // `localhost` resolve without a network DNS query.)
        for bad in [
            "127.0.0.1:43",         // loopback
            "169.254.169.254:43",   // link-local cloud-metadata
            "10.0.0.5:43",          // RFC1918
            "192.168.1.1:43",       // RFC1918
            "[::1]:43",             // v6 loopback
            "8.8.8.8:6379",         // public host but non-43 port
            "whois.example.com:80", // non-43 port
            "localhost:43",         // local domain
        ] {
            assert!(
                resolve_public_whois(bad).await.is_none(),
                "must refuse SSRF/non-43 referral: {bad}"
            );
        }
        // A public IP literal on :43 is allowed and pinned to that exact address.
        assert_eq!(
            resolve_public_whois("8.8.8.8:43").await,
            Some("8.8.8.8:43".parse().unwrap()),
            "a public :43 referral must be allowed"
        );
        // A bare public literal defaults to :43 and is allowed.
        assert_eq!(
            resolve_public_whois("1.1.1.1").await,
            Some("1.1.1.1:43".parse().unwrap()),
            "bare public host defaults to whois/43"
        );
    }
}
