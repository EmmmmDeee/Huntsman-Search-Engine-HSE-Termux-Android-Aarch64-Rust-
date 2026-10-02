//! Lightweight timestamp parsing and formatting.

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

#[must_use]
pub fn civil_from_days(days: i64) -> (i32, u32, u32) {
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
    (
        i32::try_from(year).unwrap_or(0),
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

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

#[must_use]
pub fn parse_timestamp_and_iso(raw: &str) -> Option<(i64, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
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
        .unwrap_or((&normalised, ""));
    let mut date_bits = date_part.split('-');
    let year: i32 = date_bits.next()?.parse().ok()?;
    let month: u32 = date_bits.next()?.parse().ok()?;
    let day: u32 = date_bits.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut hour = 0_i64;
    let mut min = 0_i64;
    let mut sec = 0_i64;
    let mut offset = 0_i64;
    if !time_part.is_empty() {
        let (clock, zone) = time_part
            .strip_suffix('Z')
            .map_or((time_part, ""), |clock| (clock, "Z"));
        let mut bits = clock.split(':');
        hour = bits.next()?.parse().ok()?;
        min = bits.next().unwrap_or("0").parse().ok()?;
        sec = bits.next().unwrap_or("0").parse().ok()?;
        if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=59).contains(&sec) {
            return None;
        }
        if zone.is_empty() {
            if let Some((sign, tail)) = clock
                .char_indices()
                .skip(1)
                .find_map(|(i, c)| matches!(c, '+' | '-').then_some((c, &clock[i + 1..])))
            {
                let hhmm = tail.replace(':', "");
                if hhmm.len() == 4 {
                    let h: i64 = hhmm[..2].parse().ok()?;
                    let m: i64 = hhmm[2..].parse().ok()?;
                    offset = h * 3_600 + m * 60;
                    if sign == '+' {
                        offset = -offset;
                    }
                }
            }
        }
    }
    let ts = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec + offset;
    let iso = if time_part.is_empty() {
        format!("{year:04}-{month:02}-{day:02}")
    } else {
        format_unix(ts)
    };
    Some((ts, iso))
}

#[must_use]
pub fn parse_timestamp(raw: &str) -> Option<i64> {
    parse_timestamp_and_iso(raw).map(|(ts, _)| ts)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
