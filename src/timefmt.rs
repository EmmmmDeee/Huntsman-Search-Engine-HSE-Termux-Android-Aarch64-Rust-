//! Timestamp parsing and formatting over the proleptic Gregorian calendar.
//!
//! The calendar arithmetic is Howard Hinnant's integer algorithm. The tests check it against an
//! independent month-length reference for every day from 1900-01-01 through 2100-12-31. The parsers
//! accept only the shapes documented on [`parse_timestamp_and_iso`]. A malformed or impossible
//! timestamp is `None`, never a corrected or defaulted value.

/// Days from 1970-01-01 to `year`-`month`-`day`, negative before that date.
///
/// The date must be valid: `month` is in 1..=12 and `day` lies within that month. For any other
/// date the result is the day number of a different date.
#[must_use]
pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian `(year, month, day)` that is `days` after 1970-01-01.
///
/// Total over every `i64`. The year is an `i64`, so no day number falls outside the result.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // month 1..=12, day 1..=31
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

/// The UTC instant `ts` seconds after 1970-01-01T00:00:00Z, as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn format_unix(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let rem = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Days in `month` of `year`, with leap years under the Gregorian rule. `month` must be 1..=12.
pub(crate) fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Whether `field` is one or more ASCII digits and nothing else.
fn is_digits(field: &str) -> bool {
    !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit())
}

/// `field` as a number, but only when it is plain digits. A sign, a space, or an overflow is `None`.
fn digits<T: std::str::FromStr>(field: &str) -> Option<T> {
    if is_digits(field) {
        field.parse().ok()
    } else {
        None
    }
}

/// The clock text and the numeric offset after it, if there is one (`+HH:MM`, `-HHMM`). The search
/// starts after the first character, so a leading sign is never taken for an offset.
fn split_offset(time: &str) -> (&str, Option<(char, &str)>) {
    match time
        .char_indices()
        .skip(1)
        .find(|&(_, c)| matches!(c, '+' | '-'))
    {
        Some((index, sign)) => (&time[..index], Some((sign, &time[index + 1..]))),
        None => (time, None),
    }
}

/// Seconds in a numeric UTC offset written `HH:MM` or `HHMM`. Any other shape, any non-digit,
/// hours above 23 and minutes above 59 are `None`. The match is on bytes, so no UTF-8 is sliced.
pub(crate) fn offset_seconds(tail: &str) -> Option<i64> {
    let (hours, minutes) = match tail.as_bytes() {
        [h1, h2, b':', m1, m2] | [h1, h2, m1, m2] => (two_digits(*h1, *h2)?, two_digits(*m1, *m2)?),
        _ => return None,
    };
    (hours <= 23 && minutes <= 59).then_some(hours * 3_600 + minutes * 60)
}

/// The number written by two ASCII digits, or `None` when either byte is not a digit.
fn two_digits(tens: u8, units: u8) -> Option<i64> {
    if tens.is_ascii_digit() && units.is_ascii_digit() {
        Some(i64::from(tens - b'0') * 10 + i64::from(units - b'0'))
    } else {
        None
    }
}

/// Parses a timestamp to Unix seconds and its canonical UTC text.
///
/// Accepted shapes: a Unix time in seconds (up to 12 digits) or in milliseconds (13 or more
/// digits); a bare four-digit number, read as a year and January 1st of it; `YYYY-MM-DD` or
/// `YYYY/MM/DD`; and either date followed by `T` or a space and a time `HH[:MM[:SS[.fraction]]]`
/// with an optional `Z` or a numeric offset `±HH:MM` or `±HHMM`. The date must exist, so February
/// 30th is refused, and nothing may follow the last field. Any other input is `None`.
#[must_use]
pub fn parse_timestamp_and_iso(raw: &str) -> Option<(i64, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_digits(trimmed) {
        let n: i64 = trimmed.parse().ok()?;
        if trimmed.len() >= 13 {
            return Some((n / 1_000, format_unix(n / 1_000)));
        }
        if trimmed.len() == 4 {
            let year: i32 = trimmed.parse().ok()?;
            let ts = days_from_civil(year, 1, 1) * 86_400;
            return Some((ts, format!("{year:04}-01-01")));
        }
        return Some((n, format_unix(n)));
    }
    let normalised = trimmed.replace('/', "-");
    let (date_part, time_part) = normalised
        .split_once('T')
        .or_else(|| normalised.split_once(' '))
        .map_or((normalised.as_str(), None), |(date, time)| {
            (date, Some(time))
        });
    let mut date_bits = date_part.split('-');
    let year: i32 = digits(date_bits.next()?)?;
    let month: u32 = digits(date_bits.next()?)?;
    let day: u32 = digits(date_bits.next()?)?;
    if date_bits.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
    {
        return None;
    }
    let mut hour = 0_i64;
    let mut min = 0_i64;
    let mut sec = 0_i64;
    let mut offset = 0_i64;
    if let Some(time) = time_part {
        if time.is_empty() {
            return None;
        }
        let (clock, offset_spec) = match time.strip_suffix('Z') {
            Some(clock) => (clock, None),
            None => split_offset(time),
        };
        let mut bits = clock.split(':');
        hour = digits(bits.next()?)?;
        min = digits(bits.next().unwrap_or("0"))?;
        // Fractional seconds (`.sss`, as in JS `toISOString()` and atproto timestamps) are
        // accepted and truncated to whole seconds. A dot must be followed by digits.
        let sec_field = bits.next().unwrap_or("0");
        let (whole, fraction) = sec_field
            .split_once('.')
            .map_or((sec_field, None), |(whole, fraction)| {
                (whole, Some(fraction))
            });
        if fraction.is_some_and(|value| !is_digits(value)) {
            return None;
        }
        sec = digits(whole)?;
        if bits.next().is_some()
            || !(0..=23).contains(&hour)
            || !(0..=59).contains(&min)
            || !(0..=59).contains(&sec)
        {
            return None;
        }
        if let Some((sign, tail)) = offset_spec {
            let seconds = offset_seconds(tail)?;
            offset = if sign == '+' { -seconds } else { seconds };
        }
    }
    let ts = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec + offset;
    let iso = if time_part.is_some() {
        format_unix(ts)
    } else {
        format!("{year:04}-{month:02}-{day:02}")
    };
    Some((ts, iso))
}

#[must_use]
pub fn parse_timestamp(raw: &str) -> Option<i64> {
    parse_timestamp_and_iso(raw).map(|(ts, _)| ts)
}

/// An HTTP-date (RFC 9110 §5.6.7) as Unix seconds: the IMF-fixdate `Sun, 06 Nov 1994 08:49:37 GMT`,
/// or either obsolete form a recipient must also accept, RFC 850 `Sunday, 06-Nov-94 08:49:37 GMT`
/// and asctime `Sun Nov  6 08:49:37 1994`. The weekday is not checked against the date. A two-digit
/// RFC 850 year more than 50 years ahead of `now_unix` is read as the previous century.
#[must_use]
pub fn parse_http_date(raw: &str, now_unix: u64) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let raw = raw.trim();
    let (weekday, rest) = raw.split_once([',', ' '])?;
    if weekday.len() < 3 || !weekday.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let parts: Vec<&str> = rest.split_ascii_whitespace().collect();
    let (year, month, day, clock) = match parts.as_slice() {
        [day, month, year, clock, "GMT"] if raw.as_bytes()[3] == b',' && year.len() == 4 => {
            (year.parse::<i32>().ok()?, *month, *day, *clock)
        }
        [date, clock, "GMT"] if raw.as_bytes().get(weekday.len()) == Some(&b',') => {
            let mut fields = date.split('-');
            let (day, month, yy) = (fields.next()?, fields.next()?, fields.next()?);
            if fields.next().is_some() || yy.len() != 2 {
                return None;
            }
            let yy: i32 = yy.parse().ok()?;
            let now_year =
                i32::try_from(civil_from_days(i64::try_from(now_unix / 86_400).ok()?).0).ok()?;
            let mut year = now_year - now_year.rem_euclid(100) + yy;
            if year > now_year + 50 {
                year -= 100;
            }
            (year, month, day, *clock)
        }
        [month, day, clock, year] if raw.as_bytes()[3] == b' ' && year.len() == 4 => {
            (year.parse::<i32>().ok()?, *month, *day, *clock)
        }
        _ => return None,
    };
    let month = u32::try_from(MONTHS.iter().position(|m| *m == month)? + 1).ok()?;
    if day.is_empty() || day.len() > 2 || !day.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let day: u32 = day.parse().ok()?;
    let mut hms = clock.split(':');
    let mut field = |max: i64| -> Option<i64> {
        let text = hms.next()?;
        if text.len() != 2 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let value: i64 = text.parse().ok()?;
        (value <= max).then_some(value)
    };
    let (hour, minute, second) = (field(23)?, field(59)?, field(60)?);
    if hms.next().is_some() {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if civil_from_days(days) != (i64::from(year), month, day) {
        return None;
    }
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates_in_all_three_forms_read_as_the_same_instant() {
        let now = 1_792_108_800; // 2026-10-15
        for raw in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(parse_http_date(raw, now), Some(784_111_777), "{raw}");
        }
        for raw in [
            "",
            "120",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 31 Feb 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Sun, 6 Nov 1994 8:49:37 GMT",
        ] {
            assert_eq!(parse_http_date(raw, now), None, "{raw}");
        }
    }

    #[test]
    fn round_trip_epoch_and_leap_day() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn parses_supported_formats() {
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06").unwrap(),
            (days_from_civil(2024, 5, 6) * 86_400, "2024-05-06".into())
        );
        assert_eq!(
            parse_timestamp_and_iso("2024/05/06 12:34:56").unwrap().1,
            "2024-05-06T12:34:56Z"
        );
        assert_eq!(parse_timestamp("1714998896"), Some(1_714_998_896));
        assert_eq!(parse_timestamp("1714998896000"), Some(1_714_998_896));
    }

    #[test]
    fn parses_rfc3339_offsets_and_fractional_seconds() {
        // +10:00 is ten hours ahead of UTC, so 12:34:56+10:00 is 02:34:56Z.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56+10:00")
                .unwrap()
                .1,
            "2024-05-06T02:34:56Z"
        );
        // UTC written with a numeric offset rather than 'Z'.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56+00:00")
                .unwrap()
                .1,
            "2024-05-06T12:34:56Z"
        );
        // A behind-UTC offset moves the clock forward.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56-05:00")
                .unwrap()
                .1,
            "2024-05-06T17:34:56Z"
        );
        // Basic-format offset without a colon.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56-0500")
                .unwrap()
                .1,
            "2024-05-06T17:34:56Z"
        );
        // Fractional seconds (JS toISOString / atproto createdAt) are accepted and dropped.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56.000Z")
                .unwrap()
                .1,
            "2024-05-06T12:34:56Z"
        );
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56.789Z")
                .unwrap()
                .1,
            "2024-05-06T12:34:56Z"
        );
        // Fractional seconds together with a numeric offset.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56.789+10:00")
                .unwrap()
                .1,
            "2024-05-06T02:34:56Z"
        );
        // The 'Z' and offset-less forms still parse unchanged.
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56Z").unwrap().1,
            "2024-05-06T12:34:56Z"
        );
        assert_eq!(
            parse_timestamp_and_iso("2024-05-06T12:34:56").unwrap().1,
            "2024-05-06T12:34:56Z"
        );
    }

    #[test]
    fn century_boundaries_follow_the_gregorian_rule() {
        // 1900 and 2100 are common years; 1600 and 2000 are leap years because 400 divides them.
        let cases: [((i32, u32, u32), i64); 11] = [
            ((1900, 2, 28), -25_509),
            ((1900, 3, 1), -25_508),
            ((1904, 2, 29), -24_048),
            ((2000, 2, 29), 11_016),
            ((2024, 5, 6), 19_849),
            ((2100, 2, 28), 47_540),
            ((2100, 3, 1), 47_541),
            ((1600, 2, 29), -135_081),
            ((1582, 10, 15), -141_427),
            ((1969, 12, 31), -1),
            ((2099, 12, 31), 47_481),
        ];
        for ((year, month, day), days) in cases {
            assert_eq!(
                days_from_civil(year, month, day),
                days,
                "{year}-{month}-{day}"
            );
            let (y, m, d) = civil_from_days(days);
            assert_eq!((y, m, d), (i64::from(year), month, day), "{days}");
        }
    }

    #[test]
    fn every_date_from_1900_to_2100_round_trips_both_ways() {
        // Month lengths are written out here, not taken from the module, so the test has its own reference.
        let month_length = |year: i32, month: u32| match month {
            2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let first = days_from_civil(1900, 1, 1);
        let last = days_from_civil(2100, 12, 31);
        assert_eq!(last - first + 1, 73_414);
        let mut dates = 0;
        for year in 1900..=2100 {
            for month in 1..=12 {
                for day in 1..=month_length(year, month) {
                    let days = days_from_civil(year, month, day);
                    assert!((first..=last).contains(&days), "{year}-{month}-{day}");
                    let (y, m, d) = civil_from_days(days);
                    assert_eq!((y, m, d), (i64::from(year), month, day), "{days}");
                    dates += 1;
                }
            }
        }
        assert_eq!(dates, 73_414);
        for days in first..=last {
            let (year, month, day) = civil_from_days(days);
            let year = i32::try_from(year).unwrap();
            assert!((1..=month_length(year, month)).contains(&day), "{days}");
            assert_eq!(days_from_civil(year, month, day), days, "{days}");
        }
    }

    #[test]
    fn non_ascii_offsets_are_refused_not_a_panic() {
        // "é" is two bytes, so slicing a four-byte offset at byte 2 split the character and panicked.
        assert_eq!(parse_timestamp_and_iso("2024-05-06T12:34:56+1é0"), None);
        assert_eq!(parse_timestamp_and_iso("2024-05-06T12:34:56-éé"), None);
    }

    #[test]
    fn malformed_offsets_are_refused_not_read_as_utc() {
        for bad in [
            "2024-05-06T12:34:56+1",
            "2024-05-06T12:34:56+10:0",
            "2024-05-06T12:34:56+10:60",
            "2024-05-06T12:34:56+24:00",
            "2024-05-06T12:34:56+10:00:00",
            "2024-05-06T12:34:56+1000:00",
            "2024-05-06T12:34:56+10 00",
        ] {
            assert_eq!(parse_timestamp_and_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn impossible_calendar_dates_are_refused_not_normalised() {
        // 2024-02-30 used to be accepted and silently read as 2024-03-01.
        for bad in [
            "2024-02-30",
            "2023-02-29",
            "1900-02-29",
            "2024-04-31",
            "2024-06-31",
            "2024-13-01",
            "2024-00-10",
        ] {
            assert_eq!(parse_timestamp_and_iso(bad), None, "{bad}");
        }
        for good in ["2024-02-29", "2000-02-29", "2024-12-31"] {
            assert!(parse_timestamp_and_iso(good).is_some(), "{good}");
        }
    }

    #[test]
    fn trailing_fields_and_empty_times_are_refused_not_ignored() {
        for bad in [
            "2024-05-06-garbage",
            "2024-05-06T",
            "2024-05-06T12:34:56:78",
            "2024-05-06T12:34:56.Z",
            "2024-05-06T12:34:56.12x",
            "2024-05-06T12:34:56.5+10:00:",
        ] {
            assert_eq!(parse_timestamp_and_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn extreme_timestamps_format_exactly_instead_of_as_year_zero() {
        // Once the year no longer fit in an i32, the old code printed year 0000 without an error.
        assert_eq!(format_unix(i64::MAX), "292277026596-12-04T15:30:07Z");
        assert_eq!(format_unix(i64::MIN), "-292277022657-01-27T08:29:52Z");
    }
}
