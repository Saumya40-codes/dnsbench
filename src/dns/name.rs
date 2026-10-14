#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsName {
    text: String,
}

impl DnsName {
    pub(crate) fn parse(domain: &str) -> Result<Self, &'static str> {
        if !domain.is_ascii() {
            return Err("Unicode names are not supported yet");
        }

        if domain.bytes().any(|byte| !byte.is_ascii_graphic()) {
            return Err("expected one domain without whitespace or control characters");
        }

        if domain.contains('\\') {
            return Err("escaped DNS names are not supported yet");
        }

        if domain == "." {
            return Ok(Self {
                text: ".".to_owned(),
            });
        }

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

        Ok(Self {
            text: name.to_ascii_lowercase(),
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }
}
