//! SMTP email verification — check deliverability via MX lookup + SMTP
//! RCPT TO handshake. No email is sent; only the envelope is tested.
//!
//! Flow: target email → extract domain → resolve MX → connect to MX
//! on port 25 → EHLO → MAIL FROM → RCPT TO → check 250 vs 550.
//!
//! Many servers reject VRFY but accept RCPT TO probing. Some servers
//! accept all recipients (catch-all). The module tags entities
//! accordingly: `smtp-valid`, `smtp-invalid`, `smtp-catchall`,
//! `smtp-unreachable`.
//!
//! Uses raw TCP via tokio — no SMTP library dependency.

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "smtp_vrfy";

pub struct SmtpVrfy;

#[async_trait]
impl Module for SmtpVrfy {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Verify email deliverability via SMTP RCPT TO handshake (no email sent)"
    }

    fn priority(&self) -> u8 {
        85
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let email = target.value.clone();
        let Some((_, domain)) = email.split_once('@') else {
            return Ok(result);
        };

        // The whole outcome space — no-MX, the four SMTP verdicts — flows
        // through `verdict` so the entity mapping is a single pure step.
        let (mx_host, verdict) = match resolve_mx(domain).await {
            None => (None, SmtpVerdict::NoMx),
            Some(host) => {
                let v = smtp_rcpt_check(&host, &email).await;
                (Some(host), v)
            }
        };

        result.push(build_entity(
            &email,
            domain,
            mx_host.as_deref(),
            &verdict,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

/// The full outcome of a verification attempt: either no MX exists, or the SMTP
/// RCPT TO probe reached one of four verdicts.
enum SmtpVerdict {
    /// The domain publishes no MX record — nothing to probe.
    NoMx,
    /// RCPT TO accepted (250) and a random-address probe was *not* accepted.
    Valid,
    /// RCPT TO rejected; carries the 3-digit SMTP reply code.
    Invalid(String),
    /// The server accepts every recipient (a random probe also got 250).
    CatchAll,
    /// Could not complete the handshake; carries a human reason.
    Unreachable(String),
}

/// Map a verification outcome onto the email entity. **Pure** (no network/IO):
/// each verdict fixes the confidence and `smtp-*` tag, and attaches a `mx_host`
/// evidence attribute whenever an MX was found (every case except `NoMx`).
/// `domain` is used only for the no-MX message. Mirrors the deliverability
/// ladder: valid 0.92 ≫ catch-all 0.50 > invalid 0.35 > unreachable/no-MX 0.30.
fn build_entity(
    email: &str,
    domain: &str,
    mx_host: Option<&str>,
    verdict: &SmtpVerdict,
    scan_id: &str,
) -> Entity {
    let (conf, tag, summary, code) = match verdict {
        SmtpVerdict::NoMx => (
            0.30,
            "smtp-unreachable",
            format!("No MX record for {domain}"),
            None,
        ),
        SmtpVerdict::Valid => (
            0.92,
            "smtp-valid",
            format!("SMTP RCPT TO accepted by {}", mx_host.unwrap_or("?")),
            None,
        ),
        SmtpVerdict::Invalid(c) => (
            0.35,
            "smtp-invalid",
            format!("SMTP RCPT TO rejected ({c}) by {}", mx_host.unwrap_or("?")),
            Some(c.as_str()),
        ),
        SmtpVerdict::CatchAll => (
            0.50,
            "smtp-catchall",
            format!(
                "{} appears to accept all recipients",
                mx_host.unwrap_or("?")
            ),
            None,
        ),
        SmtpVerdict::Unreachable(reason) => (
            0.30,
            "smtp-unreachable",
            format!("SMTP connection failed: {reason}"),
            None,
        ),
    };

    let mut e = Entity::new(EntityKind::Email, email, conf, scan_id);
    e.tag(tag);
    let mut ev = Evidence::new(SRC, summary);
    if let Some(host) = mx_host {
        ev = ev.with_attr("mx_host", host);
    }
    if let Some(c) = code {
        ev = ev.with_attr("smtp_code", c);
    }
    e.add_evidence(ev);
    e
}

async fn resolve_mx(domain: &str) -> Option<String> {
    use hickory_resolver::proto::rr::RData;
    let resolver = crate::util::dns::shared_resolver();
    match resolver.mx_lookup(domain).await {
        Ok(response) => {
            let mut best: Option<(u16, String)> = None;
            for record in response.answers() {
                if let RData::MX(mx) = &record.data {
                    let host = mx.exchange.to_ascii();
                    let host = host.trim_end_matches('.').to_string();
                    let pref = mx.preference;
                    if best.as_ref().is_none_or(|(p, _)| pref < *p) {
                        best = Some((pref, host));
                    }
                }
            }
            best.map(|(_, h)| h)
        }
        Err(_) => None,
    }
}

async fn smtp_rcpt_check(mx_host: &str, email: &str) -> SmtpVerdict {
    let addr = format!("{mx_host}:25");
    let stream =
        match tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
            .await
        {
            Ok(Ok(s)) => s,
            _ => return SmtpVerdict::Unreachable(format!("connect to {addr} failed")),
        };

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read banner
    if read_line_timeout(&mut reader, &mut line).await.is_err() {
        return SmtpVerdict::Unreachable("no banner".into());
    }
    if !line.starts_with("220") {
        return SmtpVerdict::Unreachable(format!("bad banner: {}", line.trim()));
    }

    // EHLO
    if send_cmd(&mut writer, "EHLO huntsman.local\r\n")
        .await
        .is_err()
    {
        return SmtpVerdict::Unreachable("EHLO send failed".into());
    }
    if read_multiline(&mut reader, &mut line).await.is_err() {
        return SmtpVerdict::Unreachable("EHLO response failed".into());
    }

    // MAIL FROM
    if send_cmd(&mut writer, "MAIL FROM:<probe@huntsman.local>\r\n")
        .await
        .is_err()
    {
        return SmtpVerdict::Unreachable("MAIL FROM send failed".into());
    }
    line.clear();
    if read_line_timeout(&mut reader, &mut line).await.is_err() {
        return SmtpVerdict::Unreachable("MAIL FROM response failed".into());
    }

    // RCPT TO — the actual target
    let rcpt = format!("RCPT TO:<{email}>\r\n");
    if send_cmd(&mut writer, &rcpt).await.is_err() {
        return SmtpVerdict::Unreachable("RCPT TO send failed".into());
    }
    line.clear();
    if read_line_timeout(&mut reader, &mut line).await.is_err() {
        return SmtpVerdict::Unreachable("RCPT TO response failed".into());
    }

    let code = line.chars().take(3).collect::<String>();
    let target_accepted = code == "250";

    if !target_accepted {
        let _ = send_cmd(&mut writer, "QUIT\r\n").await;
        return SmtpVerdict::Invalid(code);
    }

    // Catch-all detection: probe a random address
    let random_addr = format!(
        "RCPT TO:<hseprobex{}@{}>\r\n",
        crate::core::entity::unix_now() % 99999,
        email.split_once('@').map_or("", |(_, d)| d)
    );
    if send_cmd(&mut writer, &random_addr).await.is_ok() {
        line.clear();
        if read_line_timeout(&mut reader, &mut line).await.is_ok() && line.starts_with("250") {
            let _ = send_cmd(&mut writer, "QUIT\r\n").await;
            return SmtpVerdict::CatchAll;
        }
    }

    let _ = send_cmd(&mut writer, "QUIT\r\n").await;
    SmtpVerdict::Valid
}

async fn send_cmd(writer: &mut tokio::net::tcp::OwnedWriteHalf, cmd: &str) -> std::io::Result<()> {
    writer.write_all(cmd.as_bytes()).await?;
    writer.flush().await
}

async fn read_line_timeout(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut String,
) -> std::io::Result<()> {
    buf.clear();
    tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_line(buf))
        .await
        .map_err(|_| std::io::Error::other("timeout"))?
        .map(|_| ())
}

async fn read_multiline(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut String,
) -> std::io::Result<()> {
    loop {
        buf.clear();
        read_line_timeout(reader, buf).await?;
        if buf.len() >= 4 && buf.as_bytes()[3] == b' ' {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn module_metadata() {
        let m = SmtpVrfy;
        assert_eq!(m.name(), "smtp_vrfy");
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert_eq!(m.max_timeout_ms(), 15_000);
    }

    #[tokio::test]
    async fn no_mx_produces_unreachable() {
        let m = SmtpVrfy;
        let target = Target::new(
            TargetKind::Email,
            "test@thisdomain-does-not-exist-xyzzy.com",
        );
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
            proxy_pool: Default::default(),
        };
        let r = m.process(&target, &ctx).await.unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.entities[0].has_tag("smtp-unreachable"));
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn valid_verdict_is_high_confidence_with_mx_attr() {
        let e = build_entity(
            "a@b.com",
            "b.com",
            Some("mx.b.com"),
            &SmtpVerdict::Valid,
            "s",
        );
        assert_eq!(e.kind, EntityKind::Email);
        assert!(e.has_tag("smtp-valid"));
        assert!((e.confidence - 0.92).abs() < 1e-9);
        assert_eq!(attr(&e, "mx_host"), Some("mx.b.com"));
        assert_eq!(attr(&e, "smtp_code"), None);
    }

    #[test]
    fn invalid_verdict_records_smtp_code() {
        let e = build_entity(
            "a@b.com",
            "b.com",
            Some("mx.b.com"),
            &SmtpVerdict::Invalid("550".into()),
            "s",
        );
        assert!(e.has_tag("smtp-invalid"));
        assert!((e.confidence - 0.35).abs() < 1e-9);
        assert_eq!(attr(&e, "smtp_code"), Some("550"));
        assert!(e.evidence[0].summary.contains("550"));
    }

    #[test]
    fn catchall_verdict_is_mid_confidence() {
        let e = build_entity(
            "a@b.com",
            "b.com",
            Some("mx.b.com"),
            &SmtpVerdict::CatchAll,
            "s",
        );
        assert!(e.has_tag("smtp-catchall"));
        assert!((e.confidence - 0.50).abs() < 1e-9);
        assert_eq!(attr(&e, "mx_host"), Some("mx.b.com"));
    }

    #[test]
    fn unreachable_carries_reason_and_mx_attr() {
        let e = build_entity(
            "a@b.com",
            "b.com",
            Some("mx.b.com"),
            &SmtpVerdict::Unreachable("no banner".into()),
            "s",
        );
        assert!(e.has_tag("smtp-unreachable"));
        assert!((e.confidence - 0.30).abs() < 1e-9);
        assert!(e.evidence[0].summary.contains("no banner"));
        assert_eq!(attr(&e, "mx_host"), Some("mx.b.com"));
    }

    #[test]
    fn no_mx_omits_mx_attr_and_names_domain() {
        let e = build_entity("a@b.com", "b.com", None, &SmtpVerdict::NoMx, "s");
        assert!(e.has_tag("smtp-unreachable"));
        assert!((e.confidence - 0.30).abs() < 1e-9);
        // No MX was found → no mx_host attribute, and the domain is named.
        assert_eq!(attr(&e, "mx_host"), None);
        assert_eq!(e.evidence[0].summary, "No MX record for b.com");
    }

    #[test]
    fn deliverability_ladder_is_ordered() {
        let mk = |v| build_entity("a@b.com", "b.com", Some("mx"), &v, "s").confidence;
        let valid = mk(SmtpVerdict::Valid);
        let catchall = mk(SmtpVerdict::CatchAll);
        let invalid = mk(SmtpVerdict::Invalid("550".into()));
        let unreachable = mk(SmtpVerdict::Unreachable("x".into()));
        assert!(valid > catchall && catchall > invalid && invalid > unreachable);
    }
}
