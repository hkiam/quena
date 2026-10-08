use quena_model::Micros;
use time::format_description::well_known::Rfc3339;

/// .NET round-trip format used by Fiddler (`2026-09-28T19:14:48.1234560+00:00`).
pub fn to_dotnet(us: Option<Micros>) -> String {
    let Some(us) = us.filter(|v| *v > 0) else { return "0001-01-01T00:00:00".into() };
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(us as i128 * 1000).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}+00:00",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.nanosecond() / 100
    )
}

pub fn from_dotnet(s: &str) -> Option<Micros> {
    if s.starts_with("0001-01-01") || s.is_empty() {
        return None;
    }
    let t = time::OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .or_else(|| time::OffsetDateTime::parse(&format!("{s}Z"), &Rfc3339).ok())?;
    Some((t.unix_timestamp_nanos() / 1000) as Micros)
}

/// ISO 8601 for HAR (`2026-09-28T19:14:48.123Z`).
pub fn to_iso(us: Micros) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(us as i128 * 1000).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

pub fn from_iso(s: &str) -> Option<Micros> {
    time::OffsetDateTime::parse(s, &Rfc3339).ok().map(|t| (t.unix_timestamp_nanos() / 1000) as Micros)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let us = 1_790_000_000_123_456;
        assert_eq!(from_dotnet(&to_dotnet(Some(us))), Some(us));
        assert_eq!(from_dotnet("2026-09-28T21:14:48.1234567+02:00").unwrap() % 1_000_000, 123_456);
        assert_eq!(from_dotnet("0001-01-01T00:00:00"), None);
        assert_eq!(from_iso(&to_iso(us)), Some(us - 456));
    }
}
