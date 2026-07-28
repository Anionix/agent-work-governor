use std::path::Path;

use serde_json::Value;

use crate::model::Finding;

use super::issue;

// LLM-CONTRACT
// id: agent-work-governor.rust-okf-scalars
// state: DECLARED_SCALAR -> PARSED_SCALAR -> VALID | INVALID
// preconditions: scalar values come from parsed OKF metadata or log headings
// invariant: date, datetime, and actor acceptance remains Python-profile compatible
// failure: reject malformed scalars or append the stable log reason code without mutation
// source: https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md
// knowledge: bundle:knowledge/references/okf-v0.2.md
// enforced_by: valid_datetime
// test: bundle:rust/tests/okf.rs

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CalendarDate {
    year: u32,
    month: u32,
    day: u32,
}

#[must_use]
fn parse_decimal(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u32>().ok()
}

#[must_use]
fn parse_calendar_date(raw: &str) -> Option<CalendarDate> {
    if !raw.is_ascii() {
        return None;
    }
    let (year, month, day) = if raw.len() == 10
        && raw.as_bytes().get(4) == Some(&b'-')
        && raw.as_bytes().get(7) == Some(&b'-')
    {
        (
            parse_decimal(&raw[0..4])?,
            parse_decimal(&raw[5..7])?,
            parse_decimal(&raw[8..10])?,
        )
    } else if raw.len() == 8 {
        (
            parse_decimal(&raw[0..4])?,
            parse_decimal(&raw[4..6])?,
            parse_decimal(&raw[6..8])?,
        )
    } else {
        return None;
    };
    if year == 0 {
        return None;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days {
        return None;
    }
    Some(CalendarDate { year, month, day })
}

#[must_use]
fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[must_use]
fn new_year_weekday(year: u32) -> u32 {
    let previous_year = year - 1;
    let sunday_based =
        (previous_year + previous_year / 4 - previous_year / 100 + previous_year / 400 + 1) % 7;
    if sunday_based == 0 { 7 } else { sunday_based }
}

#[must_use]
fn weeks_in_iso_year(year: u32) -> u32 {
    let weekday = new_year_weekday(year);
    if weekday == 4 || (weekday == 3 && is_leap_year(year)) {
        53
    } else {
        52
    }
}

#[must_use]
fn week_date_within_calendar_range(year: u32, week: u32, weekday: u32) -> bool {
    let new_year_weekday = i64::from(new_year_weekday(year));
    let week_one_monday = if new_year_weekday <= 4 {
        1 - new_year_weekday
    } else {
        8 - new_year_weekday
    };
    let day_offset = week_one_monday + i64::from((week - 1) * 7) + i64::from(weekday - 1);
    let days_in_year = if is_leap_year(year) { 366 } else { 365 };

    (year > 1 || day_offset >= 0) && (year < 9_999 || day_offset < i64::from(days_in_year))
}

#[must_use]
fn valid_week_date(raw: &str) -> bool {
    if !raw.is_ascii() {
        return false;
    }
    let (year, week, weekday) = if raw.len() == 10
        && raw.as_bytes().get(4) == Some(&b'-')
        && raw.as_bytes().get(5) == Some(&b'W')
        && raw.as_bytes().get(8) == Some(&b'-')
    {
        (
            raw.get(0..4).and_then(parse_decimal),
            raw.get(6..8).and_then(parse_decimal),
            raw.get(9..10).and_then(parse_decimal),
        )
    } else if raw.len() == 8
        && raw.as_bytes().get(4) == Some(&b'-')
        && raw.as_bytes().get(5) == Some(&b'W')
    {
        (
            raw.get(0..4).and_then(parse_decimal),
            raw.get(6..8).and_then(parse_decimal),
            Some(1),
        )
    } else if raw.len() == 8 && raw.as_bytes().get(4) == Some(&b'W') {
        (
            raw.get(0..4).and_then(parse_decimal),
            raw.get(5..7).and_then(parse_decimal),
            raw.get(7..8).and_then(parse_decimal),
        )
    } else if raw.len() == 7 && raw.as_bytes().get(4) == Some(&b'W') {
        (
            raw.get(0..4).and_then(parse_decimal),
            raw.get(5..7).and_then(parse_decimal),
            Some(1),
        )
    } else {
        return false;
    };
    let (Some(year), Some(week), Some(weekday)) = (year, week, weekday) else {
        return false;
    };
    year != 0
        && (1..=weeks_in_iso_year(year)).contains(&week)
        && (1..=7).contains(&weekday)
        && week_date_within_calendar_range(year, week, weekday)
}

#[must_use]
fn valid_iso_date(raw: &str) -> bool {
    parse_calendar_date(raw).is_some() || valid_week_date(raw)
}

#[must_use]
pub(super) fn valid_date(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(valid_iso_date)
}

#[must_use]
fn valid_time(raw: &str) -> bool {
    if !raw.is_ascii() || raw.len() < 2 {
        return false;
    }
    let Some(hour) = raw.get(0..2).and_then(parse_decimal) else {
        return false;
    };
    if hour > 23 {
        return false;
    }

    if raw.as_bytes().get(2) == Some(&b':') {
        let Some(minute) = raw.get(3..5).and_then(parse_decimal) else {
            return false;
        };
        if minute > 59 {
            return false;
        }
        let remainder = &raw[5..];
        if remainder.is_empty() {
            return true;
        }
        if !remainder.starts_with(':') || remainder.len() < 3 {
            return false;
        }
        let Some(second) = remainder.get(1..3).and_then(parse_decimal) else {
            return false;
        };
        if second > 59 {
            return false;
        }
        return valid_fraction(&remainder[3..]);
    }

    if raw.len() == 2 {
        return true;
    }
    let Some(minute) = raw.get(2..4).and_then(parse_decimal) else {
        return false;
    };
    if minute > 59 || raw.len() == 5 {
        return false;
    }
    if raw.len() == 4 {
        return true;
    }
    let Some(second) = raw.get(4..6).and_then(parse_decimal) else {
        return false;
    };
    second <= 59 && valid_fraction(&raw[6..])
}

#[must_use]
fn valid_fraction(fraction: &str) -> bool {
    fraction.is_empty()
        || ((fraction.starts_with('.') || fraction.starts_with(','))
            && fraction.len() > 1
            && fraction[1..].bytes().all(|byte| byte.is_ascii_digit()))
}

#[must_use]
fn valid_offset(raw: &str) -> bool {
    if !raw
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(*byte, b'+' | b'-'))
    {
        return false;
    }
    let Some(body) = raw.get(1..) else {
        return false;
    };
    let Some(hour) = body.get(0..2).and_then(parse_decimal) else {
        return false;
    };
    let (minute, second, fraction) = if body.as_bytes().get(2) == Some(&b':') {
        let Some(minute) = body.get(3..5).and_then(parse_decimal) else {
            return false;
        };
        let remainder = &body[5..];
        if remainder.is_empty() {
            (minute, 0, "")
        } else {
            if !remainder.starts_with(':') {
                return false;
            }
            let Some(second) = remainder.get(1..3).and_then(parse_decimal) else {
                return false;
            };
            (minute, second, &remainder[3..])
        }
    } else {
        let remainder = &body[2..];
        if remainder.is_empty() {
            (0, 0, "")
        } else {
            let Some(minute) = remainder.get(0..2).and_then(parse_decimal) else {
                return false;
            };
            let seconds = &remainder[2..];
            if seconds.is_empty() {
                (minute, 0, "")
            } else {
                let Some(second) = seconds.get(0..2).and_then(parse_decimal) else {
                    return false;
                };
                (minute, second, &seconds[2..])
            }
        }
    };
    valid_fraction(fraction) && hour * 3_600 + minute * 60 + second < 86_400
}

#[must_use]
fn datetime_clock(raw: &str) -> Option<&str> {
    [10, 8, 7].into_iter().find_map(|date_length| {
        if !raw.get(..date_length).is_some_and(valid_iso_date) {
            return None;
        }
        let suffix = raw.get(date_length..)?;
        let separator = suffix.chars().next()?;
        if separator == 'Z' {
            return None;
        }
        suffix
            .get(separator.len_utf8()..)
            .filter(|clock| !clock.is_empty())
    })
}

#[must_use]
pub(super) fn valid_datetime(value: Option<&Value>) -> bool {
    let Some(raw) = value.and_then(Value::as_str) else {
        return false;
    };
    if valid_iso_date(raw) || raw.strip_suffix('Z').is_some_and(valid_iso_date) {
        return true;
    }
    let Some(clock_and_offset) = datetime_clock(raw) else {
        return false;
    };
    if let Some(clock) = clock_and_offset.strip_suffix('Z') {
        return valid_time(clock);
    }
    let offset_index = clock_and_offset
        .char_indices()
        .rev()
        .find(|(index, character)| *index > 0 && matches!(character, '+' | '-'))
        .map(|(index, _)| index);
    if let Some(index) = offset_index {
        return valid_time(&clock_and_offset[..index]) && valid_offset(&clock_and_offset[index..]);
    }
    valid_time(clock_and_offset)
}

#[must_use]
pub(super) fn valid_actor(value: Option<&Value>) -> bool {
    let Some(actor) = value.and_then(Value::as_str) else {
        return false;
    };
    for prefix in ["human:", "process:"] {
        if let Some(identity) = actor.strip_prefix(prefix) {
            return !identity.is_empty() && !identity.chars().any(char::is_whitespace);
        }
    }
    let Some((namespace, identity)) = actor.split_once('/') else {
        return false;
    };
    !namespace.is_empty()
        && !identity.is_empty()
        && !identity.contains('/')
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:+-".contains(&byte))
}

pub(super) fn parse_log_dates(body: &str, path: &Path, core_errors: &mut Vec<Finding>) {
    let mut dates = Vec::new();
    for line in body.lines() {
        let Some(raw) = line.strip_prefix("## ") else {
            continue;
        };
        if raw.len() != 10
            || raw.as_bytes().get(4) != Some(&b'-')
            || raw.as_bytes().get(7) != Some(&b'-')
            || !raw
                .bytes()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
        {
            continue;
        }
        if let Some(date) = parse_calendar_date(raw) {
            dates.push(date);
        } else {
            core_errors.push(issue(
                "LOG_DATE_INVALID",
                path,
                format!("invalid date heading: {line}"),
            ));
        }
    }
    let mut descending = dates.clone();
    descending.sort_by(|left, right| right.cmp(left));
    if dates != descending {
        core_errors.push(issue(
            "LOG_ORDER_INVALID",
            path,
            "log dates must be newest first",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{CalendarDate, parse_calendar_date, valid_actor, valid_datetime};
    use serde_json::json;

    #[test]
    fn local_scalar_validators_reject_malformed_values() {
        assert_eq!(
            parse_calendar_date("2024-02-29"),
            Some(CalendarDate {
                year: 2024,
                month: 2,
                day: 29,
            })
        );
        assert!(parse_calendar_date("2023-02-29").is_none());
        assert!(valid_datetime(Some(&json!("2026-07-28T12:34:56+09:00"))));
        assert!(!valid_datetime(Some(&json!("2026-07-28T25:00:00Z"))));
        assert!(valid_actor(Some(&json!("process:okf-test"))));
        assert!(!valid_actor(Some(&json!("team:not-okf"))));
    }
}
