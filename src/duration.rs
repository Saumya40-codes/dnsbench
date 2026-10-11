use std::{num::IntErrorKind, time::Duration};

use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DurationParseError {
    #[error("expected an unsigned integer followed by ns, us, ms, s, m, or h (for example 250ms)")]
    InvalidFormat,

    #[error("duration is too large")]
    Overflow,
}

pub fn parse_duration(value: &str) -> Result<Duration, DurationParseError> {
    let (number, unit) = ["ns", "us", "ms", "s", "m", "h"]
        .into_iter()
        .find_map(|unit| value.strip_suffix(unit).map(|number| (number, unit)))
        .ok_or(DurationParseError::InvalidFormat)?;

    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DurationParseError::InvalidFormat);
    }

    let amount = number.parse::<u64>().map_err(|error| match error.kind() {
        IntErrorKind::PosOverflow => DurationParseError::Overflow,
        _ => DurationParseError::InvalidFormat,
    })?;

    match unit {
        "ns" => Ok(Duration::from_nanos(amount)),
        "us" => Ok(Duration::from_micros(amount)),
        "ms" => Ok(Duration::from_millis(amount)),
        "s" => Ok(Duration::from_secs(amount)),
        "m" | "h" => {
            let multiplier = if unit == "m" { 60 } else { 3_600 };
            let seconds = amount
                .checked_mul(multiplier)
                .ok_or(DurationParseError::Overflow)?;
            Ok(Duration::from_secs(seconds))
        }
        _ => Err(DurationParseError::InvalidFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_each_unit_and_zero() {
        for (input, expected) in [
            ("1ns", Duration::from_nanos(1)),
            ("2us", Duration::from_micros(2)),
            ("250ms", Duration::from_millis(250)),
            ("30s", Duration::from_secs(30)),
            ("2m", Duration::from_secs(120)),
            ("3h", Duration::from_secs(10_800)),
            ("0s", Duration::ZERO),
        ] {
            assert_eq!(parse_duration(input).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_values_outside_the_grammar() {
        for input in [
            "", "30", "s", "-1s", "+1s", "1.5s", "1m30s", " 1s", "1 s", "1s ", "1S", "1d", "１s",
            "1µs",
        ] {
            assert_eq!(
                parse_duration(input),
                Err(DurationParseError::InvalidFormat),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn checks_integer_and_unit_conversion_overflow() {
        for input in [
            "18446744073709551616s",
            "18446744073709551615m",
            "18446744073709551615h",
        ] {
            assert_eq!(parse_duration(input), Err(DurationParseError::Overflow));
        }
        assert_eq!(
            parse_duration("18446744073709551615s"),
            Ok(Duration::from_secs(u64::MAX))
        );
    }
}
