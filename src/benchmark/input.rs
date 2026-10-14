use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

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

pub(crate) fn load_domains(domain_file: &Path) -> Result<Vec<String>, InputError> {
    let text = fs::read_to_string(domain_file).map_err(|source| InputError::ReadFile {
        path: domain_file.to_path_buf(),
        source,
    })?;

    parse_domains(&text)
}

fn parse_domains(text: &str) -> Result<Vec<String>, InputError> {
    let mut domains = Vec::new();

    for (index, raw_line) in text.lines().enumerate() {
        let domain = raw_line.trim();

        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }

        let normalized = validate_domain(domain).map_err(|reason| InputError::InvalidDomain {
            line: index + 1,
            reason,
        })?;

        domains.push(normalized.to_ascii_lowercase());
    }

    if domains.is_empty() {
        return Err(InputError::EmptyWorkload);
    }

    Ok(domains)
}

fn validate_domain(domain: &str) -> Result<&str, &'static str> {
    if !domain.is_ascii() {
        return Err("Unicode names are not supported yet");
    }

    if domain.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err("expected one domain without whitespace or control characters");
    }

    if domain.contains('\\') {
        return Err("escaped DNS names are not supported yet");
    }

    // this is actually the dns root (more like normally www.google.com.), aka top of the node
    if domain == "." {
        return Ok(domain);
    }

    // Remove at most one trailing dot.
    let name = domain.strip_suffix('.').unwrap_or(domain);

    if name.len() > 253 {
        return Err("encoded DNS name exceeds 255 bytes");
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err("domain contains an empty label");
        }

        if label.len() > 63 {
            return Err("domain label exceeds 63 bytes");
        }
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn normalizes_names_and_preserves_order_and_duplicates() {
        let domains =
            parse_domains("# comment\r\n\r\n Example.COM. \r\nb.com\r\nexample.com\r\n").unwrap();
        assert_eq!(domains, ["example.com", "b.com", "example.com"]);
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
            assert!(validate_domain(domain).is_err(), "accepted {domain:?}");
        }
        assert_eq!(validate_domain("."), Ok("."));
        assert_eq!(
            validate_domain("_service.example.com"),
            Ok("_service.example.com")
        );
    }

    #[test]
    fn enforces_label_and_wire_length_boundaries() {
        assert!(validate_domain(&"a".repeat(63)).is_ok());
        assert!(validate_domain(&"a".repeat(64)).is_err());

        let maximum = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(maximum.len(), 253);
        assert!(validate_domain(&maximum).is_ok());
        assert!(validate_domain(&format!("{maximum}.")).is_ok());
        assert!(validate_domain(&format!("{maximum}d")).is_err());
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
