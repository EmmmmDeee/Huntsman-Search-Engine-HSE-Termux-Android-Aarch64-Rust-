use super::{SmtpVerdict, SmtpVrfy, build_entity};
use crate::core::entity::{Entity, EntityKind};
use crate::core::module::{Module, ModuleContext};
use crate::core::scan::{Target, TargetKind};

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

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
    };
    let r = m.process(&target, &ctx).await.expect("should succeed");
    assert_eq!(r.len(), 1);
    assert!(r.entities[0].has_tag("smtp-unreachable"));
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
    assert!((e.confidence - 0.30).abs() < 1e-9);
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
    assert!(valid > invalid && invalid > catchall);
    // catchall and unreachable are both 0.30; verify equality holds
    assert!((catchall - mk(SmtpVerdict::Unreachable("x".into()))).abs() < f64::EPSILON);
}

/// Read one SMTP command line off the mock-server side of a
/// `tokio::io::duplex()` pipe, looping until a full `\r\n`-terminated line
/// has arrived (an in-memory duplex can split a write across multiple
/// `read` calls, so a single `read` is not guaranteed to return a whole
/// line).
async fn read_cmd(server: &mut tokio::io::DuplexStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = server.read(&mut chunk).await.expect("should succeed");
        assert!(n > 0, "connection closed while reading a command");
        buf.extend_from_slice(&chunk[..n]);
        if buf.ends_with(b"\r\n") {
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
}

#[tokio::test]
async fn run_probe_reports_unreachable_when_mail_from_is_rejected() {
    // Regression: a MAIL FROM rejection must surface as `Unreachable`, not
    // fall through to RCPT TO — which would then typically be misreported
    // as `Invalid` for the TARGET address even though nothing about the
    // target was ever actually tested. Also confirms the sender is the
    // RFC 5321 §4.1.1.2 null reverse-path, not a fabricated `.local`
    // address that a real MTA could plausibly reject for its own domain.
    use tokio::io::AsyncWriteExt;
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        server
            .write_all(b"220 mx.example.com ESMTP\r\n")
            .await
            .expect("should succeed");
        let ehlo = read_cmd(&mut server).await;
        assert!(ehlo.starts_with("EHLO"), "got: {ehlo}");
        server
            .write_all(b"250 mx.example.com\r\n")
            .await
            .expect("should succeed");
        let mail_from = read_cmd(&mut server).await;
        assert_eq!(
            mail_from, "MAIL FROM:<>\r\n",
            "must probe with the null reverse-path sender, not a fabricated domain"
        );
        server
            .write_all(b"550 sender domain not found\r\n")
            .await
            .expect("should succeed");
        // No RCPT TO is ever sent by a correct implementation once MAIL
        // FROM is rejected; leaving the mock server here means a bug that
        // does send RCPT TO will simply time out waiting for a response
        // that never comes, which is caught by the test's own timeout.
    });

    let verdict = super::run_probe(client, "target@example.com").await;
    match verdict {
        SmtpVerdict::Unreachable(reason) => {
            assert!(
                reason.contains("MAIL FROM rejected"),
                "expected a MAIL FROM rejection reason, got: {reason}"
            );
        }
        _ => panic!("a rejected MAIL FROM must yield Unreachable, not a target-address verdict"),
    }
}

#[tokio::test]
async fn run_probe_reaches_the_target_when_mail_from_is_accepted() {
    // Companion to the rejection test above: a normal MAIL FROM 250
    // acceptance must still flow through to a RCPT TO probe of the actual
    // target and reach the usual Valid/Invalid/CatchAll verdicts.
    use tokio::io::AsyncWriteExt;
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        server
            .write_all(b"220 mx.example.com ESMTP\r\n")
            .await
            .expect("should succeed");
        read_cmd(&mut server).await; // EHLO
        server
            .write_all(b"250 mx.example.com\r\n")
            .await
            .expect("should succeed");
        let mail_from = read_cmd(&mut server).await;
        assert_eq!(mail_from, "MAIL FROM:<>\r\n");
        server
            .write_all(b"250 OK\r\n")
            .await
            .expect("should succeed");
        let rcpt = read_cmd(&mut server).await;
        assert_eq!(rcpt, "RCPT TO:<target@example.com>\r\n");
        server
            .write_all(b"250 OK\r\n")
            .await
            .expect("should succeed");
        read_cmd(&mut server).await; // catch-all probe RCPT TO
        server
            .write_all(b"550 no such user\r\n")
            .await
            .expect("should succeed");
        read_cmd(&mut server).await; // QUIT
        server
            .write_all(b"221 bye\r\n")
            .await
            .expect("should succeed");
    });

    let verdict = super::run_probe(client, "target@example.com").await;
    assert!(
        matches!(verdict, SmtpVerdict::Valid),
        "target accepted + catch-all probe rejected must yield Valid"
    );
}

#[tokio::test]
async fn read_line_timeout_caps_a_giant_newline_less_line() {
    // T2.8: a single newline-less line from a hostile MX must not grow `buf`
    // unbounded (OOM on the device) — the 5 s timeout bounds time, not bytes.
    // Send 100 KiB with no newline; the capped reader must stop at the 8 KiB
    // ceiling rather than buffer the whole blob.
    use tokio::io::{AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should succeed");
    let addr = listener.local_addr().expect("should succeed");
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let blob = vec![b'A'; 100 * 1024]; // no newline anywhere
            let _ = sock.write_all(&blob).await;
            let _ = sock.flush().await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("should succeed");
    let (rd, _wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut buf = String::new();
    super::read_line_timeout(&mut reader, &mut buf)
        .await
        .expect("should succeed");
    assert!(
        buf.len() <= 8 * 1024,
        "capped line read must not exceed the 8 KiB ceiling, got {}",
        buf.len()
    );
    assert!(!buf.is_empty(), "should have read the capped prefix");
}
