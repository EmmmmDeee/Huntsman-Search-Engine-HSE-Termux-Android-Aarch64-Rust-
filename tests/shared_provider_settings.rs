//! The shipped server's credential availability must match lookup execution. Settings drives
//! technique selection, so an accepted provider-key alias must not hide a runnable source.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use huntsman_recon::environment::{
    ABUSECH_KEY_ENV, HIBP_API_KEY_ENV, HUNTSMAN_HIBP_KEY_ENV, THREATFOX_KEY_ENV, WIGLE_TOKEN_ENV,
    WIGLE_USER_ENV,
};
use serde_json::Value;

/// Own the child and its isolated home even when an assertion fails.
struct Serve {
    child: Child,
    home: PathBuf,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn settings_with(tag: &str, slots: &[&str]) -> Value {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "shared-provider-settings-{tag}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let keys = home.join(".huntsman.env");
    let mut text = String::new();
    for slot in slots {
        text.push_str(slot);
        text.push_str("=TEST_ONLY_SHARED_PROVIDER_KEY\n");
    }
    fs::write(&keys, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut serve = Serve {
        child: Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
            .args(["serve", "--bind", "127.0.0.1:0"])
            .env_clear()
            .env("HOME", &home)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        home,
    };
    let stdout = serve.child.stdout.take().unwrap();
    let (sent, received) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut first = String::new();
        let result = BufReader::new(stdout).read_line(&mut first).map(|_| first);
        let _ = sent.send(result);
    });
    let first = received
        .recv_timeout(Duration::from_secs(10))
        .expect("server announces its bound address")
        .expect("read startup line");
    reader.join().unwrap();
    let addr: SocketAddr = first
        .trim()
        .strip_prefix("serving=http://")
        .and_then(|rest| rest.strip_suffix('/'))
        .unwrap_or_else(|| panic!("no serving= line: {first:?}"))
        .parse()
        .unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET /api/settings HTTP/1.1\r\nHost: {addr}\r\nSec-Fetch-Site: same-origin\r\nX-Huntsman-Lookup: 1\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn configured(settings: &Value, name: &str) -> bool {
    settings["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["name"] == name)
        .unwrap_or_else(|| panic!("no module {name}"))["configured"]
        .as_bool()
        .unwrap()
}

#[test]
fn settings_accept_either_abuse_ch_key_and_require_one() {
    let cases: &[(&str, &[&str], bool)] = &[
        ("none", &[], false),
        ("urlhaus", &[ABUSECH_KEY_ENV], true),
        ("threatfox", &[THREATFOX_KEY_ENV], true),
        ("both", &[ABUSECH_KEY_ENV, THREATFOX_KEY_ENV], true),
    ];
    for &(tag, slots, expected) in cases {
        let settings = settings_with(tag, slots);
        for source in ["threatfox", "urlhaus"] {
            assert_eq!(configured(&settings, source), expected, "{tag}: {source}");
        }
    }
}

#[test]
fn settings_preserve_hibp_aliases_and_require_both_wigle_keys() {
    let cases: &[(&str, &[&str], bool, bool)] = &[
        ("hibp-alias", &[HIBP_API_KEY_ENV], true, false),
        ("hibp-primary", &[HUNTSMAN_HIBP_KEY_ENV], true, false),
        ("wigle-user", &[WIGLE_USER_ENV], false, false),
        ("wigle-token", &[WIGLE_TOKEN_ENV], false, false),
        (
            "wigle-both",
            &[WIGLE_USER_ENV, WIGLE_TOKEN_ENV],
            false,
            true,
        ),
    ];
    for &(tag, slots, hibp, wigle) in cases {
        let settings = settings_with(tag, slots);
        for name in ["hibp", "hibp_account"] {
            assert_eq!(configured(&settings, name), hibp, "{tag}: {name}");
        }
        for name in ["wigle", "wigle_bluetooth"] {
            assert_eq!(configured(&settings, name), wigle, "{tag}: {name}");
        }
    }
}
