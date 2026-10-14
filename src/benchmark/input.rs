use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

use crate::dns::name::DnsName;

#[derive(Debug, Error)]
pub(crate) enum InputError {
    #[error("unable to read domains file {}: {source}", path.display())]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid domain on line {line}: {reason}")]
    InvalidDomain { line: usize, reason: &'static str },

    #[error("domains file contains no domains")]
    EmptyWorkload,
}

pub(crate) fn load_domains(domain_file: &Path) -> Result<Vec<DnsName>, InputError> {
    let text = fs::read_to_string(domain_file).map_err(|source| InputError::ReadFile {
        path: domain_file.to_path_buf(),
        source,
    })?;

    parse_domains(&text)
}

fn parse_domains(text: &str) -> Result<Vec<DnsName>, InputError> {
    let mut domains = Vec::new();

    for (index, raw_line) in text.lines().enumerate() {
        let domain = raw_line.trim();

        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }

        let name = DnsName::parse(domain).map_err(|reason| InputError::InvalidDomain {
            line: index + 1,
            reason,
        })?;

        domains.push(name);
    }

    if domains.is_empty() {
        return Err(InputError::EmptyWorkload);
    }

    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn normalizes_names_and_preserves_order_and_duplicates() {
        let domains =
            parse_domains("# comment\r\n\r\n Example.COM. \r\nb.com\r\nexample.com\r\n").unwrap();
        let names: Vec<&str> = domains.iter().map(DnsName::as_str).collect();
        assert_eq!(names, ["example.com", "b.com", "example.com"]);
    }

    #[test]
    fn errors_retain_original_line_numbers() {
        let error = parse_domains("# comment\n\na.com\na..com\n").unwrap_err();
        assert!(matches!(error, InputError::InvalidDomain { line: 4, .. }));
    }

    #[test]
    fn rejects_empty_workloads() {
        for text in ["", "\n \n# comment\n"] {
            assert!(matches!(
                parse_domains(text),
                Err(InputError::EmptyWorkload)
            ));
        }
    }

    #[test]
    fn rejects_unsupported_and_malformed_names() {
        for domain in [
            "a.com b.com",
            "é.com",
            "a\\.com",
            "a..com",
            ".a.com",
            "a.com..",
            "a\0.com",
        ] {
            assert!(DnsName::parse(domain).is_err(), "accepted {domain:?}");
        }
        assert_eq!(DnsName::parse(".").unwrap().as_str(), ".");
        assert_eq!(
            DnsName::parse("_service.example.com").unwrap().as_str(),
            "_service.example.com"
        );
    }

    #[test]
    fn enforces_label_and_wire_length_boundaries() {
        assert!(DnsName::parse(&"a".repeat(63)).is_ok());
        assert!(DnsName::parse(&"a".repeat(64)).is_err());

        let maximum = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(maximum.len(), 253);
        assert!(DnsName::parse(&maximum).is_ok());
        assert!(DnsName::parse(&format!("{maximum}.")).is_ok());
        assert!(DnsName::parse(&format!("{maximum}d")).is_err());
    }

    #[test]
    fn preserves_underlying_io_error() {
        let error = InputError::ReadFile {
            path: PathBuf::from("domains.txt"),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("domains.txt"));
    }
}
