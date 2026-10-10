//! `huntsman-recon hibp …` against a fake transport, plus offline binary runs.
//!
//! Test names carry the ATT&CK technique they exercise: T1589.001 (gather
//! victim identity information: credentials) and T1589.002 (email addresses).
//! No test opens a socket.

use std::collections::VecDeque;
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use huntsman_recon::hibp::cli::HibpCommand;
use huntsman_recon::hibp::key::{EmbeddedSource, KeyLoader};
use huntsman_recon::hibp::passwords::{PasswordHashMode, hash_password};
use huntsman_recon::hibp::rate_limit::RateLimiter;
use huntsman_recon::hibp::{HibpClient, HibpConfig};
use huntsman_recon::http::{Method, Request, Response, Transport, TransportFailure};

const KEY: &str = "fake-hibp-key-5f0c1d2e3a4b";
const PASSWORD: &str = "correct horse battery staple";

#[derive(Default)]
struct Fake {
    responses: Mutex<VecDeque<Response>>,
    requests: Mutex<Vec<Request>>,
}

impl Fake {
    fn push(&self, status: u16, body: &str, headers: &[(&str, &str)]) {
        self.responses.lock().unwrap().push_back(Response {
            status,
            body: body.as_bytes().to_vec(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            truncated: false,
        });
    }

    /// Every request seen so far. Every endpoint the command uses is a GET, so a
    /// request with any other method fails the calling test here.
    fn requests(&self) -> Vec<Request> {
        let requests = self.requests.lock().unwrap().clone();
        for request in &requests {
            assert_eq!(request.method, Method::Get, "{}", request.url);
        }
        requests
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}

fn command(key: Option<&str>) -> (HibpCommand, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let transport = fake.clone();
    let config = HibpConfig {
        max_429_retries: 0,
        ..HibpConfig::default()
    };
    let keys = KeyLoader::from_parts(key.map(str::to_owned), None, None, "");
    let cmd = HibpCommand::new(keys, move |auth| {
        HibpClient::with_config(
            transport.clone(),
            auth,
            config.clone(),
            Arc::new(RateLimiter::per_minute(0)),
        )
    });
    (cmd, fake)
}

struct Run {
    code: u8,
    stdout: String,
    stderr: String,
}

fn run(cmd: &HibpCommand, args: &[&str], stdin: &str) -> Run {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd.run(&args, &mut stdin.as_bytes(), &mut out, &mut err);
    Run {
        code,
        stdout: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(err).unwrap(),
    }
}

fn assert_never_shown(run: &Run, secret: &str) {
    assert!(
        !run.stdout.contains(secret),
        "stdout leaked: {}",
        run.stdout
    );
    assert!(
        !run.stderr.contains(secret),
        "stderr leaked: {}",
        run.stderr
    );
}

const ADOBE: &str = r#"{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","AddedDate":"2013-12-04T00:00Z","ModifiedDate":"2022-05-15T23:52Z","PwnCount":152445165,"Description":"In October 2013, <em>153 million</em>\naccounts.","LogoPath":"Adobe.png","DataClasses":["Email addresses","Password hints","Passwords","Usernames"],"IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":false,"IsMalware":false,"IsStealerLog":false,"IsSubscriptionFree":false,"Attribution":"provided by a researcher"}"#;

/// Every field of the Adobe fixture, as the CLI prints it.
const ADOBE_LINES: [&str; 23] = [
    "breach=Adobe",
    "title=Adobe",
    "domain=adobe.com",
    "breach_date=2013-10-04",
    "added_date=2013-12-04T00:00Z",
    "modified_date=2022-05-15T23:52Z",
    "pwn_count=152445165",
    "data_classes=4",
    "data_class=Email addresses",
    "data_class=Password hints",
    "data_class=Passwords",
    "data_class=Usernames",
    "is_verified=true",
    "is_fabricated=false",
    "is_sensitive=false",
    "is_retired=false",
    "is_spam_list=false",
    "is_malware=false",
    "is_stealer_log=false",
    "is_subscription_free=false",
    "attribution=provided by a researcher",
    "logo_path=Adobe.png",
    "description=In October 2013, <em>153 million</em>\\naccounts.",
];

fn assert_attributed(stdout: &str, results: usize) {
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines[0], "source=HIBP", "{stdout}");
    assert!(lines[2].starts_with("source_attribution="), "{stdout}");
    assert!(lines[2].contains("haveibeenpwned.com"), "{stdout}");
    assert_eq!(lines[3], format!("results={results}"), "{stdout}");
}

#[test]
fn catalogue_breach_by_name_prints_every_field_with_attribution_and_no_key() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(200, ADOBE, &[]);
    let out = run(&cmd, &["breach", "Adobe"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 1);
    for want in ADOBE_LINES {
        assert!(
            out.stdout.lines().any(|l| l == want),
            "missing {want:?} in {}",
            out.stdout
        );
    }
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url,
        "https://haveibeenpwned.com/api/v3/breach/Adobe"
    );
    assert!(requests[0].header_value("hibp-api-key").is_none());
    assert!(requests[0].header_value("User-Agent").is_some());
}

#[test]
fn catalogue_breach_not_found_404_is_no_results() {
    let (cmd, fake) = command(None);
    fake.push(404, "", &[]);
    let out = run(&cmd, &["breach", "NoSuchBreach"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 0);
    assert!(!out.stdout.contains("breach="), "{}", out.stdout);
}

#[test]
fn catalogue_breaches_are_complete_and_domain_filter_is_sent() {
    let (cmd, fake) = command(None);
    let many: Vec<String> = (0..250)
        .map(|i| format!(r#"{{"Name":"Breach{i}","DataClasses":["Passwords"]}}"#))
        .collect();
    fake.push(200, &format!("[{}]", many.join(",")), &[]);
    let out = run(&cmd, &["breaches"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 250);
    for i in 0..250 {
        assert!(out.stdout.contains(&format!("\nbreach=Breach{i}\n")));
    }
    assert_eq!(out.stdout.matches("data_class=Passwords").count(), 250);
    assert_eq!(out.stdout.matches("title=<none>").count(), 250);

    fake.push(200, &format!("[{ADOBE}]"), &[]);
    let out = run(&cmd, &["breaches", "--domain", "adobe.com"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 1);
    assert!(out.stdout.contains("\nbreach=Adobe\n"));
    let requests = fake.requests();
    assert_eq!(
        requests[0].url,
        "https://haveibeenpwned.com/api/v3/breaches"
    );
    assert_eq!(
        requests[1].url,
        "https://haveibeenpwned.com/api/v3/breaches?Domain=adobe.com"
    );
}

#[test]
fn t1589_002_breached_account_asks_for_the_full_model_with_the_key() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(200, &format!("[{ADOBE}]"), &[]);
    let out = run(&cmd, &["account", " a+b@example.com "], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 1);
    assert_eq!(out.stdout.lines().nth(4), Some("query=a+b@example.com"));
    for want in ADOBE_LINES {
        assert!(out.stdout.lines().any(|l| l == want), "missing {want:?}");
    }
    assert_never_shown(&out, KEY);
    let request = &fake.requests()[0];
    assert_eq!(
        request.url,
        "https://haveibeenpwned.com/api/v3/breachedaccount/a%2Bb%40example.com?truncateResponse=false"
    );
    assert_eq!(request.header_value("hibp-api-key"), Some(KEY));
}

#[test]
fn t1589_002_breached_account_404_is_no_results() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(404, "", &[]);
    let out = run(&cmd, &["account", "nobody@example.com"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 0);
    assert!(
        out.stdout
            .ends_with("results=0\nquery=nobody@example.com\n"),
        "{}",
        out.stdout
    );
    assert_never_shown(&out, KEY);
}

#[test]
fn t1589_002_pastes_print_every_paste_field_and_404_is_no_results() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(
        200,
        r#"[{"Source":"Pastebin","Id":"8Q0BvKD8","Title":"syslog","Date":"2014-03-04T19:14:54Z","EmailCount":139},{"Source":"Pastie","Id":"7152479","Date":null,"EmailCount":30}]"#,
        &[],
    );
    let out = run(&cmd, &["pastes", "a@example.com"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 2);
    assert_eq!(out.stdout.lines().nth(4), Some("query=a@example.com"));
    for want in [
        "paste_source=Pastebin",
        "paste_id=8Q0BvKD8",
        "title=syslog",
        "date=2014-03-04T19:14:54Z",
        "email_count=139",
        "paste_source=Pastie",
        "paste_id=7152479",
        "title=<none>",
        "date=<none>",
        "email_count=30",
    ] {
        assert!(out.stdout.lines().any(|l| l == want), "missing {want:?}");
    }
    fake.push(404, "", &[]);
    let out = run(&cmd, &["pastes", "a@example.com"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 0);
    assert!(
        out.stdout.ends_with("results=0\nquery=a@example.com\n"),
        "{}",
        out.stdout
    );
    let requests = fake.requests();
    assert_eq!(
        requests[0].url,
        "https://haveibeenpwned.com/api/v3/pasteaccount/a%40example.com"
    );
    assert_eq!(requests[0].header_value("hibp-api-key"), Some(KEY));
}

#[test]
fn t1589_001_password_range_lists_every_suffix_without_a_key() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(
        200,
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n",
        &[],
    );
    let out = run(&cmd, &["password-range", "21bd1"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "source=HIBP",
            "service=pwned-passwords",
            "source_attribution=Pwned Passwords by Have I Been Pwned (https://haveibeenpwned.com/Passwords)",
            "results=2",
            "mode=sha1",
            "prefix=21BD1",
            "0018A45C4D1DEF81644B54AB7F969B88D65:1",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
        ]
    );
    let request = &fake.requests()[0];
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.url, "https://api.pwnedpasswords.com/range/21BD1");
    assert_eq!(request.header_value("Add-Padding"), Some("true"));
    assert!(request.header_value("hibp-api-key").is_none());
}

#[test]
fn t1589_001_password_sends_only_the_5_char_prefix_and_matches_locally() {
    let hash = hash_password(PASSWORD, PasswordHashMode::Sha1);
    let (prefix, suffix) = hash.split_at(5);
    let (cmd, fake) = command(Some(KEY));
    fake.push(
        200,
        &format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:42\r\n"),
        &[],
    );
    let out = run(&cmd, &["password"], &format!("{PASSWORD}\n"));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.ends_with("mode=sha1\ncount=42\n"),
        "{}",
        out.stdout
    );
    for secret in [PASSWORD, hash.as_str(), suffix, prefix] {
        assert_never_shown(&out, secret);
    }
    let requests = fake.requests();
    assert_eq!(requests.len(), 1, "exactly one request");
    let request = &requests[0];
    assert_eq!(request.method, Method::Get);
    assert_eq!(
        request.url,
        format!("https://api.pwnedpasswords.com/range/{prefix}")
    );
    let path = request
        .url
        .strip_prefix("https://api.pwnedpasswords.com")
        .unwrap();
    assert_eq!(path.len(), "/range/".len() + 5);
    assert_eq!(request.header_value("Add-Padding"), Some("true"));
    assert!(request.header_value("hibp-api-key").is_none());
    assert_eq!(request.body.len(), 0);
    let mut sent = request.url.clone();
    for (name, value) in &request.headers {
        sent.push_str(name);
        sent.push_str(value);
    }
    let sent = sent.to_ascii_uppercase();
    for secret in [suffix, hash.as_str()] {
        assert!(!sent.contains(secret), "request carries hash material");
    }
    assert!(!sent.contains(&PASSWORD.to_ascii_uppercase()));

    fake.push(200, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n", &[]);
    let out = run(&cmd, &["password"], &format!("{PASSWORD}\r\nsecond line\n"));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.ends_with("count=0\n"), "{}", out.stdout);
    assert_never_shown(&out, PASSWORD);
    assert!(!out.stdout.contains("second line"));
}

#[test]
fn t1589_001_password_is_never_echoed_on_error_paths() {
    let hash = hash_password(PASSWORD, PasswordHashMode::Sha1);
    let (cmd, fake) = command(None);
    for (status, headers, code) in [
        (500, vec![], 69),
        (429, vec![("retry-after", "7")], 69),
        (200, vec![], 69),
    ] {
        let body = if status == 200 {
            "not a range"
        } else {
            PASSWORD
        };
        fake.push(status, body, &headers);
        let out = run(&cmd, &["password"], PASSWORD);
        assert_eq!(out.code, code, "{status}: {}", out.stderr);
        assert_eq!(out.stdout, "");
        assert_never_shown(&out, PASSWORD);
        assert_never_shown(&out, &hash[5..]);
    }
    for (stdin, accepted) in [
        (format!("{}\r\n", "a".repeat(4096)), true),
        (format!("{}\n", "a".repeat(4096)), true),
        ("a".repeat(4096), true),
        (format!("{}\r\n", "a".repeat(4097)), false),
        ("a".repeat(4097), false),
    ] {
        if accepted {
            fake.push(200, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n", &[]);
        }
        let out = run(&cmd, &["password"], &stdin);
        let want = if accepted { 0 } else { 65 };
        assert_eq!(out.code, want, "{} bytes: {}", stdin.len(), out.stderr);
        assert_never_shown(&out, &"a".repeat(64));
    }
    let before = fake.requests().len();
    for stdin in ["", "\n", "\r\n"] {
        let out = run(&cmd, &["password"], stdin);
        assert_eq!(out.code, 65, "{}", out.stderr);
        assert!(out.stderr.contains("no password on stdin"));
    }
    let long = "x".repeat(5000);
    let out = run(&cmd, &["password"], &long);
    assert_eq!(out.code, 65);
    assert_never_shown(&out, &long[..64]);
    let invalid = run(&cmd, &["password", "extra-argument"], "");
    assert_eq!(invalid.code, 64);
    assert_eq!(
        fake.requests().len(),
        before,
        "invalid input sent a request"
    );
}

#[test]
fn subscription_prints_every_status_field_and_the_key_source_not_the_key() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(
        200,
        r#"{"SubscriptionName":"Pro 1","Description":"Up to 10 emails per minute","SubscribedUntil":"2027-01-01T00:00:00","Rpm":10,"DomainSearchMaxBreachedAccounts":100,"MaxBreachedDomains":null,"IncludesStealerLogs":true,"IncludesBulkDomainAdd":false,"IncludesAutoSubdomainVerification":false,"IncludesCustomerDomains":false,"IncludesKAnon":true}"#,
        &[],
    );
    let out = run(&cmd, &["subscription"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_attributed(&out.stdout, 1);
    for want in [
        "key_source=env:HIBP_API_KEY",
        "subscription_name=Pro 1",
        "description=Up to 10 emails per minute",
        "subscribed_until=2027-01-01T00:00:00",
        "rpm=10",
        "domain_search_max_breached_accounts=100",
        "max_breached_domains=<none>",
        "includes_stealer_logs=true",
        "includes_bulk_domain_add=false",
        "includes_auto_subdomain_verification=false",
        "includes_customer_domains=false",
        "includes_k_anon=true",
    ] {
        assert!(out.stdout.lines().any(|l| l == want), "missing {want:?}");
    }
    assert_never_shown(&out, KEY);
    let request = &fake.requests()[0];
    assert_eq!(
        request.url,
        "https://haveibeenpwned.com/api/v3/subscription/status"
    );
    assert_eq!(request.header_value("hibp-api-key"), Some(KEY));
}

#[test]
fn t1589_002_keyed_subcommands_without_a_key_fail_cleanly_and_send_nothing() {
    let (cmd, fake) = command(None);
    for args in [
        &["account", "a@example.com"][..],
        &["pastes", "a@example.com"],
        &["subscription"],
    ] {
        let out = run(&cmd, args, "");
        assert_eq!(out.code, 66, "{args:?}: {}", out.stderr);
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr.contains("no API key configured") && out.stderr.contains("HIBP_API_KEY"),
            "{}",
            out.stderr
        );
    }
    assert_eq!(fake.requests().len(), 0, "a request was sent");
}

#[test]
fn t1589_002_account_429_surfaces_retry_after() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(429, KEY, &[("retry-after", "3600")]);
    let out = run(&cmd, &["account", "a@example.com"], "");
    assert_eq!(out.code, 69);
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains("HTTP 429"), "{}", out.stderr);
    assert!(out.stderr.contains("retry_after=3600s"), "{}", out.stderr);
    assert_never_shown(&out, KEY);
    assert_eq!(fake.requests().len(), 1, "no retry with a zero budget");
}

#[test]
fn t1589_001_password_range_429_surfaces_retry_after() {
    let (cmd, fake) = command(None);
    fake.push(429, "", &[("Retry-After", "7")]);
    let out = run(&cmd, &["password-range", "21BD1"], "");
    assert_eq!(out.code, 69);
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains("HTTP 429"), "{}", out.stderr);
    assert!(out.stderr.contains("retry_after=7s"), "{}", out.stderr);
    assert_eq!(
        fake.requests().len(),
        1,
        "Pwned Passwords 429 is not retried"
    );
}

#[test]
fn catalogue_breach_429_without_retry_after_reports_unknown() {
    let (cmd, fake) = command(None);
    fake.push(429, "", &[]);
    let out = run(&cmd, &["breach", "Adobe"], "");
    assert_eq!(out.code, 69);
    assert!(out.stderr.contains("retry_after=unknown"), "{}", out.stderr);
    assert_eq!(fake.requests().len(), 1, "no retry with a zero budget");
}

#[test]
fn t1589_002_absent_empty_and_literal_none_paste_fields_are_distinct() {
    let (cmd, fake) = command(Some(KEY));
    fake.push(
        200,
        r#"[{"Source":"Pastebin","Id":"","Title":"<none>","Date":null}]"#,
        &[],
    );
    let out = run(&cmd, &["pastes", "a@example.com"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    let lines: Vec<&str> = out.stdout.lines().skip(6).collect();
    assert_eq!(
        lines,
        [
            "paste_source=Pastebin",
            "paste_id=",
            "title=\\<none>",
            "date=<none>",
            "email_count=<none>",
        ]
    );
}

#[test]
fn rejected_key_and_server_errors_do_not_echo_key_or_body() {
    let (cmd, fake) = command(Some(KEY));
    for (status, code) in [(401, 77), (403, 77), (503, 69), (400, 65)] {
        fake.push(status, &format!("echo {KEY}"), &[]);
        let out = run(&cmd, &["subscription"], "");
        assert_eq!(out.code, code, "{status}: {}", out.stderr);
        assert!(
            out.stderr.contains(&format!("HTTP {status}")),
            "{}",
            out.stderr
        );
        assert_never_shown(&out, KEY);
    }
}

#[test]
fn usage_help_and_invalid_input_make_no_requests() {
    let (cmd, fake) = command(Some(KEY));
    let help = run(&cmd, &["help"], "");
    assert_eq!(help.code, 0);
    assert!(help.stdout.starts_with("usage: huntsman-recon hibp ["));
    for args in [
        &[][..],
        &["nope"],
        &["breach"],
        &["breach", "a", "b"],
        &["breaches", "--domain"],
        &["account"],
        &["domain-search", "example.com"],
        &["subscribed-domains"],
    ] {
        let out = run(&cmd, args, "");
        assert_eq!(out.code, 64, "{args:?}");
        assert!(out.stderr.contains("usage: huntsman-recon hibp"));
        let unknown = matches!(
            args.first(),
            Some(&("nope" | "domain-search" | "subscribed-domains"))
        );
        assert_eq!(
            out.stderr.contains("unknown subcommand"),
            unknown,
            "{}",
            out.stderr
        );
    }
    for args in [
        &["breaches", "--domain", " "][..],
        &["password-range", "21BD"],
        &["password-range", "21BDZ"],
        &["breach", " "],
        &["account", " "],
    ] {
        let out = run(&cmd, args, "");
        assert_eq!(out.code, 65, "{args:?}: {}", out.stderr);
        assert!(out.stderr.contains("invalid input"), "{}", out.stderr);
    }
    assert_eq!(fake.requests().len(), 0, "a request was sent");
}

// ── The real binary, offline paths only ─────────────────────────────────

fn scratch_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huntsman-hibp-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin(home: &PathBuf) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    cmd.env("HOME", home)
        .env_remove("HIBP_API_KEY")
        .env_remove("HUNTSMAN_HIBP_KEY");
    cmd
}

#[test]
fn binary_registers_hibp_and_keyed_lookups_need_a_key() {
    let home = scratch_home("bin");
    let usage = bin(&home).arg("no-such-command").output().unwrap();
    assert!(String::from_utf8_lossy(&usage.stderr).contains("| hibp SUBCOMMAND"));
    let help = bin(&home).args(["hibp", "help"]).output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).starts_with("usage: huntsman-recon hibp ["));
    let bare = bin(&home).arg("hibp").output().unwrap();
    assert_eq!(bare.status.code(), Some(64));
    let bad = bin(&home)
        .args(["hibp", "password-range", "xyz"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(65));
    if EmbeddedSource::is_present() {
        eprintln!("skipping the binary missing-key run: this build embeds a key");
    } else {
        for args in [
            &["hibp", "account", "a@example.com"][..],
            &["hibp", "pastes", "a@example.com"],
            &["hibp", "subscription"],
        ] {
            let out = bin(&home).args(args).output().unwrap();
            // The exposure-order gate refuses a keyed leg before any key lookup.
            assert_eq!(out.status.code(), Some(77), "{args:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("keyed leg is not in the free order")
            );
        }
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn t1589_001_binary_password_from_stdin_is_not_echoed_on_bad_input() {
    let home = scratch_home("stdin");
    let long = format!("{}\n", "s3cret-".repeat(700));
    let mut child = bin(&home)
        .args(["hibp", "password"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(long.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains("s3cret-"), "{text}");
    let _ = fs::remove_dir_all(&home);
}
