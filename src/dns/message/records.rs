use std::{
    fmt::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};

use super::{
    HEADER_LEN, INTERNET_CLASS, ResponseError, TRUNCATED, WireName, read_name, read_question,
    read_u16,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    pub(crate) section: Section,
    pub(crate) name: String,
    pub(crate) ttl: u32,
    pub(crate) class: u16,
    pub(crate) record_type: u16,
    pub(crate) value: String,
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let record_type = match self.record_type {
            1 => "A".into(),
            2 => "NS".into(),
            5 => "CNAME".into(),
            12 => "PTR".into(),
            28 => "AAAA".into(),
            other => format!("TYPE{other}"),
        };
        let class = if self.class == INTERNET_CLASS {
            "IN".into()
        } else {
            format!("CLASS{}", self.class)
        };
        write!(
            f,
            "{} {} {class} {record_type} {}",
            self.name, self.ttl, self.value
        )
    }
}

pub(crate) fn decode_records(packet: &[u8]) -> Result<Vec<Record>, ResponseError> {
    if packet.len() < HEADER_LEN {
        return Err(ResponseError::TooShort);
    }
    let truncated = read_u16(packet, 2) & TRUNCATED != 0;
    let mut offset = HEADER_LEN;
    for _ in 0..read_u16(packet, 4) {
        read_question(packet, &mut offset)?;
    }
    let mut records = Vec::new();
    for (section, count_offset) in [
        (Section::Answer, 6),
        (Section::Authority, 8),
        (Section::Additional, 10),
    ] {
        for _ in 0..read_u16(packet, count_offset) {
            match read_record(packet, &mut offset, section) {
                Ok(record) => records.push(record),
                Err(ResponseError::TooShort) if truncated => return Ok(records),
                Err(error) => return Err(error),
            }
        }
    }
    if offset != packet.len() {
        return Err(ResponseError::TrailingData);
    }
    Ok(records)
}

fn read_record(
    packet: &[u8],
    offset: &mut usize,
    section: Section,
) -> Result<Record, ResponseError> {
    let name = display_name(read_name(packet, offset)?);
    let fields = packet
        .get(*offset..*offset + 10)
        .ok_or(ResponseError::TooShort)?;
    let record_type = read_u16(fields, 0);
    let class = read_u16(fields, 2);
    let ttl = u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]);
    let length = usize::from(read_u16(fields, 8));
    let start = *offset + 10;
    let end = start + length;
    let data = packet.get(start..end).ok_or(ResponseError::TooShort)?;
    let value = match (record_type, class) {
        (1, INTERNET_CLASS) => {
            Ipv4Addr::from(<[u8; 4]>::try_from(data).map_err(|_| ResponseError::InvalidRecord)?)
                .to_string()
        }
        (28, INTERNET_CLASS) => {
            Ipv6Addr::from(<[u8; 16]>::try_from(data).map_err(|_| ResponseError::InvalidRecord)?)
                .to_string()
        }
        (2 | 5 | 12, _) => {
            let mut name_offset = start;
            let value = read_name(packet, &mut name_offset).map_err(|error| {
                if error == ResponseError::TooShort {
                    ResponseError::InvalidRecord
                } else {
                    error
                }
            })?;
            if name_offset != end {
                return Err(ResponseError::InvalidRecord);
            }
            display_name(value)
        }
        _ => format!("<{length} bytes; not decoded>"),
    };
    *offset = end;
    Ok(Record {
        section,
        name,
        ttl,
        class,
        record_type,
        value,
    })
}

fn display_name(name: WireName) -> String {
    let mut output = String::new();
    let mut offset = 0;
    let bytes = name.as_slice();
    while bytes[offset] != 0 {
        let length = usize::from(bytes[offset]);
        for &byte in &bytes[offset + 1..offset + 1 + length] {
            if (b'!'..=b'~').contains(&byte) && !matches!(byte, b'.' | b'\\') {
                output.push(char::from(byte));
            } else {
                write!(output, "\\{byte:03}").expect("writing to a String cannot fail");
            }
        }
        output.push('.');
        offset += length + 1;
    }
    if output.is_empty() {
        output.push('.');
    }
    output
}

#[cfg(test)]
mod tests;
