//! How each Network Survey CSV importer refuses a bad export, recorded before the four share one
//! envelope reader: the size bound, UTF-8, the `# CSV Version=` comments, the CSV itself and the
//! header. They now share that reader (`rf::survey_csv::read_export`), and each words a refusal
//! under its own label. Each importer's own tests pin what it reads from a good export.

use huntsman_recon::cell_radar::network_survey::{self as lte, nr};
use huntsman_recon::rf::network_survey as bluetooth;
use huntsman_recon::wifi_radar::network_survey as wifi;

type Import = fn(&[u8]) -> Result<(), String>;

/// Each importer: its name, the CSV version it reads, and how to run it.
fn importers() -> [(&'static str, &'static str, Import); 4] {
    [
        ("bluetooth", bluetooth::CSV_VERSION, |bytes| {
            bluetooth::parse_bluetooth(bytes)
                .map(drop)
                .map_err(|error| error.to_string())
        }),
        ("wifi", wifi::CSV_VERSION, |bytes| {
            wifi::parse_wifi(bytes)
                .map(drop)
                .map_err(|error| error.to_string())
        }),
        ("lte", lte::CSV_VERSION, |bytes| {
            lte::parse_lte(bytes)
                .map(drop)
                .map_err(|error| error.to_string())
        }),
        ("nr", nr::NR_CSV_VERSION, |bytes| {
            nr::parse_nr(bytes)
                .map(drop)
                .map_err(|error| error.to_string())
        }),
    ]
}

/// Exports wrong in one way each, for an importer that reads `version`.
fn bad_exports(version: &str) -> Vec<(&'static str, Vec<u8>)> {
    let line = format!("# CSV Version={version}");
    vec![
        ("oversize", vec![b'#'; 262_145]),
        ("not_utf8", b"\xff\xfe".to_vec()),
        ("no_version", b"a,b\n1,2\n".to_vec()),
        (
            "duplicate_version",
            format!("{line}\n{line}\na\n").into_bytes(),
        ),
        ("other_version", b"# CSV Version=9.9.9\na\n".to_vec()),
        (
            "byte_order_mark",
            format!("\u{feff}{line}\na\n").into_bytes(),
        ),
        ("malformed_csv", format!("{line}\n\"a\"b\n").into_bytes()),
        ("no_header", format!("{line}\n").into_bytes()),
        ("wrong_header", format!("{line}\nx,y\n").into_bytes()),
        (
            "crlf_wrong_header",
            format!("{line}\r\nx,y\r\n").into_bytes(),
        ),
    ]
}

const EXPECTED: &str = "\
bluetooth\toversize\tinvalid input: Network Survey Bluetooth CSV: input exceeds 256 KiB
bluetooth\tnot_utf8\tinvalid input: Network Survey Bluetooth CSV: not UTF-8
bluetooth\tno_version\tinvalid input: Network Survey Bluetooth CSV: missing or unsupported CSV version
bluetooth\tduplicate_version\tinvalid input: Network Survey Bluetooth CSV: duplicate CSV version
bluetooth\tother_version\tinvalid input: Network Survey Bluetooth CSV: missing or unsupported CSV version
bluetooth\tbyte_order_mark\tinvalid input: Network Survey Bluetooth CSV: missing or unsupported CSV version
bluetooth\tmalformed_csv\tinvalid input: Network Survey Bluetooth CSV: text after quoted field
bluetooth\tno_header\tinvalid input: Network Survey Bluetooth CSV: missing header
bluetooth\twrong_header\tinvalid input: Network Survey Bluetooth CSV: Bluetooth 0.3.0 requires the exact documented 23-column header
bluetooth\tcrlf_wrong_header\tinvalid input: Network Survey Bluetooth CSV: Bluetooth 0.3.0 requires the exact documented 23-column header
wifi\toversize\tinvalid input: Network Survey Wi-Fi CSV: input exceeds 256 KiB
wifi\tnot_utf8\tinvalid input: Network Survey Wi-Fi CSV: not UTF-8
wifi\tno_version\tinvalid input: Network Survey Wi-Fi CSV: missing or unsupported CSV version
wifi\tduplicate_version\tinvalid input: Network Survey Wi-Fi CSV: duplicate CSV version
wifi\tother_version\tinvalid input: Network Survey Wi-Fi CSV: missing or unsupported CSV version
wifi\tbyte_order_mark\tinvalid input: Network Survey Wi-Fi CSV: missing or unsupported CSV version
wifi\tmalformed_csv\tinvalid input: Network Survey Wi-Fi CSV: text after quoted field
wifi\tno_header\tinvalid input: Network Survey Wi-Fi CSV: missing header
wifi\twrong_header\tinvalid input: Network Survey Wi-Fi CSV: Wi-Fi 0.4.0 requires the exact documented 30-column header
wifi\tcrlf_wrong_header\tinvalid input: Network Survey Wi-Fi CSV: Wi-Fi 0.4.0 requires the exact documented 30-column header
lte\toversize\tinvalid input: Network Survey LTE CSV: input exceeds 256 KiB
lte\tnot_utf8\tinvalid input: Network Survey LTE CSV: not UTF-8
lte\tno_version\tinvalid input: Network Survey LTE CSV: missing or unsupported CSV version
lte\tduplicate_version\tinvalid input: Network Survey LTE CSV: duplicate CSV version
lte\tother_version\tinvalid input: Network Survey LTE CSV: missing or unsupported CSV version
lte\tbyte_order_mark\tinvalid input: Network Survey LTE CSV: missing or unsupported CSV version
lte\tmalformed_csv\tinvalid input: Network Survey LTE CSV: text after quoted field
lte\tno_header\tinvalid input: Network Survey LTE CSV: missing header
lte\twrong_header\tinvalid input: Network Survey LTE CSV: missing required LTE column
lte\tcrlf_wrong_header\tinvalid input: Network Survey LTE CSV: missing required LTE column
nr\toversize\tinvalid input: Network Survey NR CSV: input exceeds 256 KiB
nr\tnot_utf8\tinvalid input: Network Survey NR CSV: not UTF-8
nr\tno_version\tinvalid input: Network Survey NR CSV: missing or unsupported CSV version
nr\tduplicate_version\tinvalid input: Network Survey NR CSV: duplicate CSV version
nr\tother_version\tinvalid input: Network Survey NR CSV: missing or unsupported CSV version
nr\tbyte_order_mark\tinvalid input: Network Survey NR CSV: missing or unsupported CSV version
nr\tmalformed_csv\tinvalid input: Network Survey NR CSV: text after quoted field
nr\tno_header\tinvalid input: Network Survey NR CSV: missing header
nr\twrong_header\tinvalid input: Network Survey NR CSV: NR 0.4.0 requires the exact documented 28-column header
nr\tcrlf_wrong_header\tinvalid input: Network Survey NR CSV: NR 0.4.0 requires the exact documented 28-column header
";

fn rows() -> Vec<String> {
    let mut rows = Vec::new();
    for (name, version, import) in importers() {
        for (case, bytes) in bad_exports(version) {
            let outcome = match import(&bytes) {
                Ok(()) => "accepted".to_owned(),
                Err(error) => error,
            };
            rows.push(format!("{name}\t{case}\t{outcome}"));
        }
    }
    rows
}

#[test]
fn each_importer_refuses_a_bad_export_as_it_did() {
    let found = rows();
    let expected: Vec<&str> = EXPECTED.lines().collect();
    assert!(
        found
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()),
        "the envelope rows changed. As this run found them:\n{}",
        found.join("\n")
    );
}
