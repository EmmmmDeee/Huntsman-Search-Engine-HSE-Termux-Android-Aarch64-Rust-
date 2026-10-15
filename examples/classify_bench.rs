//! Times the fetch classifier on served pages: a large content page that embeds a CAPTCHA
//! widget, the same page cut to interstitial size, and a real interstitial; then the
//! status-blind classifier that crt.sh and DNS over HTTPS use on a large JSON answer that
//! quotes a vendor path. Prints the median of seven runs and the verdict for each body, so a
//! change to the classifier can be compared before and after on the same machine:
//!
//! ```text
//! cargo run --release --locked --example classify_bench
//! ```

use std::hint::black_box;
use std::time::Instant;

use huntsman_recon::classify::is_challenge;
use huntsman_recon::source_outcome::classify_fetch;

const RUNS: usize = 7;

fn median_micros(body: &str) -> u128 {
    median_of(|| {
        black_box(classify_fetch(200, black_box(body)));
    })
}

fn median_of(mut run: impl FnMut()) -> u128 {
    let mut times: Vec<u128> = (0..RUNS)
        .map(|_| {
            let started = Instant::now();
            run();
            started.elapsed().as_micros()
        })
        .collect();
    times.sort_unstable();
    times[RUNS / 2]
}

fn main() {
    let widget_page = format!(
        "<!doctype html><html><head><script src=\"https://www.google.com/recaptcha/api.js\"></script></head><body>{}<div class=\"g-recaptcha\" data-sitekey=\"x\"></div></body></html>",
        "<p>Jane Doe, Sydney, joined 2019</p>\n".repeat(100_000)
    );
    let short_widget_page = format!(
        "<!doctype html><html><head><script src=\"https://www.google.com/recaptcha/api.js\"></script></head><body>{}<div class=\"g-recaptcha\" data-sitekey=\"x\"></div></body></html>",
        "<p>Jane Doe, Sydney, joined 2019</p>\n".repeat(400)
    );
    let interstitial = "<!doctype html><html><head><title>Just a moment...</title></head><body><p>Checking your browser before accessing the site.</p><p>Cloudflare</p></body></html>";
    for (label, body) in [
        ("widget_page", widget_page.as_str()),
        ("short_widget_page", short_widget_page.as_str()),
        ("interstitial", interstitial),
    ] {
        println!(
            "{label}\tbytes={}\tmedian_us={}\tkind={:?}",
            body.len(),
            median_micros(body),
            classify_fetch(200, body)
        );
    }
    // A crt.sh answer for a popular apex: several MiB of JSON whose records quote a vendor
    // path, which is never a wall. Classified status-blind, as crt.sh and DoH do.
    let json_answer = format!(
        "[{}{{\"issuer_name\":\"C=US, O=Let's Encrypt, CN=R11\",\"common_name\":\"captcha.example.com\",\"name_value\":\"captcha.example.com\\ncdn-cgi.example.com\"}}]",
        "{\"issuer_name\":\"C=US, O=Let's Encrypt, CN=R11\",\"common_name\":\"www.example.com\",\"name_value\":\"www.example.com\\nexample.com\"},".repeat(30_000)
    );
    println!(
        "json_answer\tbytes={}\tmedian_us={}\tchallenge={}",
        json_answer.len(),
        median_of(|| {
            black_box(is_challenge(black_box(json_answer.as_str())));
        }),
        is_challenge(&json_answer)
    );
}
