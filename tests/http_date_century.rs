//! The documented fifty-year RFC850 window is relative to the complete supplied instant.
//! These fixtures exercise the shared decoder and the actual rate-limit error path offline.
use huntsman_recon::api_leg::{self, LegError};
use huntsman_recon::http::{self, Request, Response, Transport, TransportFailure};
use huntsman_recon::keys::Keys;
use huntsman_recon::ripestat;
use huntsman_recon::timefmt::{days_from_civil, parse_http_date};

fn at(year: i32, month: u32, day: u32, seconds: i64) -> i64 {
    days_from_civil(year, month, day) * 86_400 + seconds
}

#[test]
fn obsolete_year_window_uses_the_complete_instant() {
    let now = u64::try_from(at(2026, 11, 7, 43_200)).expect("positive fixture clock");
    for (text, year, month, day, seconds) in [
        ("Sunday, 07-Nov-76 12:00:00 GMT", 2076, 11, 7, 43_200),
        ("Sunday, 07-Nov-76 12:00:01 GMT", 1976, 11, 7, 43_201),
        ("Sunday, 08-Nov-76 00:00:00 GMT", 1976, 11, 8, 0),
        ("Sunday, 06-Nov-76 23:59:59 GMT", 2076, 11, 6, 86_399),
        ("Sunday, 01-Dec-76 00:00:00 GMT", 1976, 12, 1, 0),
        ("Sunday, 01-Oct-76 00:00:00 GMT", 2076, 10, 1, 0),
    ] {
        assert_eq!(
            parse_http_date(text, now),
            Some(at(year, month, day, seconds)),
            "the fifty-year cutoff must include month, day and clock"
        );
    }
}

struct ObsoleteRetryAfter;
impl Transport for ObsoleteRetryAfter {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        Ok(Response {
            status: 429,
            headers: vec![(
                "Retry-After".into(),
                "Sunday, 08-Nov-76 00:00:00 GMT".into(),
            )],
            body: Vec::new(),
            truncated: false,
        })
    }
}

#[test]
fn an_obsolete_past_retry_after_does_not_become_a_future_pause() {
    let now = u64::try_from(at(2026, 11, 7, 43_200)).expect("positive fixture clock");
    let Err(LegError::RateLimited { retry_after, .. }) = api_leg::get(
        &ObsoleteRetryAfter,
        &ripestat::API,
        &Keys::default(),
        &ripestat::url("1.1.1.1"),
        now,
    ) else {
        panic!("the offline fixture must reach the real rate-limit error path");
    };
    assert_eq!(
        retry_after,
        Some(0),
        "a past obsolete date must not impose a future rate-limit pause"
    );
    assert_eq!(
        http::retry_after_secs("Sunday, 08-Nov-76 00:00:00 GMT", now),
        Some(0)
    );
}

#[test]
fn obsolete_year_arithmetic_does_not_panic_at_supported_extreme_clocks() {
    let now = u64::try_from(at(i32::MAX, 1, 1, 0)).expect("positive fixture clock");
    assert_eq!(
        parse_http_date("Sunday, 01-Jan-00 00:00:00 GMT", now),
        Some(at(2_147_483_600, 1, 1, 0))
    );
    assert_eq!(
        parse_http_date("Sunday, 01-Jan-99 00:00:00 GMT", now),
        Some(at(2_147_483_599, 1, 1, 0))
    );
}

#[test]
fn ordinary_http_dates_and_delta_seconds_are_preserved() {
    let now = u64::try_from(at(2026, 11, 7, 43_200)).expect("positive fixture clock");
    for text in [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
    ] {
        assert_eq!(parse_http_date(text, now), Some(784_111_777));
    }
    assert_eq!(http::retry_after_secs("42", now), Some(42));
    assert_eq!(http::retry_after_secs("-1", now), None);
    assert_eq!(
        http::retry_after_secs("18446744073709551616", now),
        Some(u64::MAX)
    );
    assert_eq!(
        parse_http_date("Sunday, 01-Jan-00 00:00:00 GMT", u64::MAX),
        None
    );
    let before_century = u64::try_from(at(2049, 1, 1, 0)).expect("positive fixture clock");
    assert_eq!(
        parse_http_date("Sunday, 29-Feb-00 00:00:00 GMT", before_century),
        Some(at(2000, 2, 29, 0)),
        "infer the century before checking its leap day"
    );
    assert_eq!(parse_http_date("Sun, 31 Feb 1994 08:49:37 GMT", now), None);
    assert_eq!(
        parse_http_date("Sun, 06 Nov 1994 08:49:60 GMT", now),
        Some(784_111_800)
    );
}
