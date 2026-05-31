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
    module::{Module, ModuleContext, ModuleResult},
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

        let mx_host = match resolve_mx(domain).await {
            Some(h) => h,
            None => {
                let mut e = Entity::new(EntityKind::Email, &email, 0.30, &ctx.scan_id);
                e.tag("smtp-unreachable");
                e.add_evidence(Evidence::new(SRC, format!("No MX record for {domain}")));
                result.push(e);
                return Ok(result);
            }
        };

        match smtp_rcpt_check(&mx_host, &email).await {
            SmtpResult::Valid => {
                let mut e = Entity::new(EntityKind::Email, &email, 0.92, &ctx.scan_id);
                e.tag("smtp-valid");
                e.add_evidence(
                    Evidence::new(SRC, format!("SMTP RCPT TO accepted by {mx_host}"))
                        .with_attr("mx_host", &mx_host),
                );
                result.push(e);
            }
            SmtpResult::Invalid(code) => {
                let mut e = Entity::new(EntityKind::Email, &email, 0.35, &ctx.scan_id);
                e.tag("smtp-invalid");
                e.add_evidence(
                    Evidence::new(SRC, format!("SMTP RCPT TO rejected ({code}) by {mx_host}"))
                        .with_attr("mx_host", &mx_host)
                        .with_attr("smtp_code", &code),
                );
                result.push(e);
            }
            SmtpResult::CatchAll => {
                let mut e = Entity::new(EntityKind::Email, &email, 0.50, &ctx.scan_id);
                e.tag("smtp-catchall");
                e.add_evidence(
                    Evidence::new(SRC, format!("{mx_host} appears to accept all recipients"))
                        .with_attr("mx_host", &mx_host),
                );
                result.push(e);
            }
            SmtpResult::Unreachable(reason) => {
                let mut e = Entity::new(EntityKind::Email, &email, 0.30, &ctx.scan_id);
                e.tag("smtp-unreachable");
                e.add_evidence(
                    Evidence::new(SRC, format!("SMTP connection failed: {reason}"))
                        .with_attr("mx_host", &mx_host),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

enum SmtpResult {
    Valid,
    Invalid(String),
    CatchAll,
    Unreachable(String),
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

async fn smtp_rcpt_check(mx_host: &str, email: &str) -> SmtpResult {
    let addr = format!("{mx_host}:25");
    let stream =
        match tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(&addr))
            .await
        {
            Ok(Ok(s)) => s,
            _ => return SmtpResult::Unreachable(format!("connect to {addr} failed")),
        };

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read banner
    if read_line_timeout(&mut reader, &mut line).await.is_err() {
        return SmtpResult::Unreachable("no banner".into());
    }
    if !line.starts_with("220") {
        return SmtpResult::Unreachable(format!("bad banner: {}", line.trim()));
    }

    // EHLO
    if send_cmd(&mut writer, "EHLO huntsman.local\r\n")
        .await
        .is_err()
    {
        return SmtpResult::Unreachable("EHLO send failed".into());
    }
    if read_multiline(&mut reader, &mut line).await.is_err() {
        return SmtpResult::Unreachable("EHLO response failed".into());
    }

    // MAIL FROM
    if send_cmd(&mut writer, "MAIL FROM:<probe@huntsman.local>\r\n")
        .await
        .is_err()
    {
        return SmtpResult::Unreachable("MAIL FROM send failed".into());
    }
    line.clear();
    if read_line_timeout(&mut reader, &mut line).await.is_err() {
        return SmtpResult::Unreachable("MAIL FROM response failed".into());
    }

    // RCPT TO — the actual target
    let rcpt = format!("RCPT TO:<{email}>\r\n");
    if send_cmd(&mut writer, &rcpt).await.is_err() {
        return SmtpResult::Unreachable("RCPT TO send failed".into());
    }
    line.clear();
    if read_line_timeout(&mut reader, &mut line).await.is_err() {
        return SmtpResult::Unreachable("RCPT TO response failed".into());
    }

    let code = line.chars().take(3).collect::<String>();
    let target_accepted = code == "250";

    if !target_accepted {
        let _ = send_cmd(&mut writer, "QUIT\r\n").await;
        return SmtpResult::Invalid(code);
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
            return SmtpResult::CatchAll;
        }
    }

    let _ = send_cmd(&mut writer, "QUIT\r\n").await;
    SmtpResult::Valid
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
}
