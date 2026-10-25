use thiserror::Error;

mod records;
pub(crate) use records::{Record, decode_records};

use crate::config::QueryType;

use super::name::DnsName;

const HEADER_LEN: usize = 12;
const RESPONSE: u16 = 1 << 15;
const OPCODE_MASK: u16 = 0x7800;
const TRUNCATED: u16 = 1 << 9;
const RECURSION_DESIRED: u16 = 1 << 8;
const RCODE_MASK: u16 = 0x000F;
const INTERNET_CLASS: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl std::fmt::Display for Rcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoError => f.write_str("NOERROR"),
            Self::FormErr => f.write_str("FORMERR"),
            Self::ServFail => f.write_str("SERVFAIL"),
            Self::NxDomain => f.write_str("NXDOMAIN"),
            Self::NotImp => f.write_str("NOTIMP"),
            Self::Refused => f.write_str("REFUSED"),
            Self::Other(code) => write!(f, "RCODE{code}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseSummary {
    pub(crate) rcode: Rcode,
    pub(crate) truncated: bool,
    pub(crate) answer_count: u16,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseError {
    #[error("query is not a supported single-question DNS query")]
    InvalidQuery,

    #[error("response is too short to answer the query")]
    TooShort,

    #[error("packet is not a DNS response")]
    NotAResponse,

    #[error("response operation does not match the query")]
    OpcodeMismatch,

    #[error("response ID does not match the query")]
    IdMismatch,

    #[error("response question does not match the query")]
    QuestionMismatch,

    #[error("packet contains an invalid DNS name or compression pointer")]
    InvalidName,

    #[error("packet contains an invalid resource record")]
    InvalidRecord,

    #[error("packet contains bytes beyond its declared sections")]
    TrailingData,
}

pub(crate) fn encode_query(
    name: &DnsName,
    id: u16,
    query_type: QueryType,
    recursion_desired: bool,
    output: &mut Vec<u8>,
) {
    output.clear();

    let flags = if recursion_desired {
        RECURSION_DESIRED
    } else {
        0
    };

    // ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
    for field in [id, flags, 1, 0, 0, 0] {
        output.extend_from_slice(&field.to_be_bytes());
    }

    if name.as_str() != "." {
        for label in name.as_str().split('.') {
            // DnsName guarantees that label lengths fit in 6 bits.
            output.push(label.len() as u8);
            output.extend_from_slice(label.as_bytes());
        }
    }
    output.push(0);

    output.extend_from_slice(&(query_type as u16).to_be_bytes());
    output.extend_from_slice(&INTERNET_CLASS.to_be_bytes());
}

pub(crate) fn validate_response(
    query: &[u8],
    response: &[u8],
) -> Result<ResponseSummary, ResponseError> {
    if query.len() < HEADER_LEN
        || read_u16(query, 2) & (RESPONSE | OPCODE_MASK) != 0
        || read_u16(query, 4) != 1
        || [6, 8, 10]
            .into_iter()
            .any(|offset| read_u16(query, offset) != 0)
    {
        return Err(ResponseError::InvalidQuery);
    }
    let mut query_offset = HEADER_LEN;
    let expected =
        read_question(query, &mut query_offset).map_err(|_| ResponseError::InvalidQuery)?;
    if query_offset != query.len() {
        return Err(ResponseError::InvalidQuery);
    }

    if response.len() < HEADER_LEN {
        return Err(ResponseError::TooShort);
    }

    let flags = read_u16(response, 2);

    if flags & RESPONSE == 0 {
        return Err(ResponseError::NotAResponse);
    }

    if flags & OPCODE_MASK != read_u16(query, 2) & OPCODE_MASK {
        return Err(ResponseError::OpcodeMismatch);
    }

    if response[..2] != query[..2] {
        return Err(ResponseError::IdMismatch);
    }

    if read_u16(response, 4) != 1 {
        return Err(ResponseError::QuestionMismatch);
    }

    let mut offset = HEADER_LEN;
    let actual = read_question(response, &mut offset)?;
    if !expected
        .name
        .as_slice()
        .eq_ignore_ascii_case(actual.name.as_slice())
        || expected.query_type != actual.query_type
        || expected.class != actual.class
    {
        return Err(ResponseError::QuestionMismatch);
    }

    let summary = ResponseSummary {
        rcode: match flags & RCODE_MASK {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            other => Rcode::Other(other as u8),
        },
        truncated: flags & TRUNCATED != 0,
        answer_count: read_u16(response, 6),
    };

    for count_offset in [6, 8, 10] {
        for _ in 0..read_u16(response, count_offset) {
            match skip_record(response, &mut offset) {
                Ok(()) => {}
                Err(ResponseError::TooShort) if summary.truncated => return Ok(summary),
                Err(error) => return Err(error),
            }
        }
    }
    if offset != response.len() {
        return Err(ResponseError::TrailingData);
    }

    Ok(summary)
}

struct WireName {
    bytes: [u8; 255],
    len: usize,
}

impl WireName {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct Question {
    name: WireName,
    query_type: u16,
    class: u16,
}

fn read_question(packet: &[u8], offset: &mut usize) -> Result<Question, ResponseError> {
    let name = read_name(packet, offset)?;
    let fields = packet
        .get(*offset..*offset + 4)
        .ok_or(ResponseError::TooShort)?;
    *offset += 4;
    Ok(Question {
        name,
        query_type: read_u16(fields, 0),
        class: read_u16(fields, 2),
    })
}

// Expand a DNS name, following compression pointers, and advance past its original encoding.
fn read_name(packet: &[u8], offset: &mut usize) -> Result<WireName, ResponseError> {
    let mut name = WireName {
        bytes: [0; 255],
        len: 0,
    };
    let mut cursor = *offset;
    let mut limit = packet.len();
    let mut end = None;

    loop {
        if cursor >= limit {
            return Err(if end.is_some() {
                ResponseError::InvalidName
            } else {
                ResponseError::TooShort
            });
        }
        let length = packet[cursor];
        match length & 0xC0 {
            0xC0 => {
                if cursor + 2 > limit {
                    return Err(if end.is_some() {
                        ResponseError::InvalidName
                    } else {
                        ResponseError::TooShort
                    });
                }
                let target = (usize::from(length & 0x3F) << 8) | usize::from(packet[cursor + 1]);
                if target < HEADER_LEN || target >= cursor {
                    return Err(ResponseError::InvalidName);
                }
                // Resume after the first pointer once the name has been expanded.
                end.get_or_insert(cursor + 2);
                // Lower the read boundary on every jump to prevent compression cycles.
                limit = cursor;
                cursor = target;
            }
            0 => {
                let next = cursor + 1 + usize::from(length);
                if next > limit {
                    return Err(if end.is_some() {
                        ResponseError::InvalidName
                    } else {
                        ResponseError::TooShort
                    });
                }
                let new_len = name.len + 1 + usize::from(length);
                if new_len > name.bytes.len() {
                    return Err(ResponseError::InvalidName);
                }
                name.bytes[name.len..new_len].copy_from_slice(&packet[cursor..next]);
                name.len = new_len;
                cursor = next;
                if length == 0 {
                    *offset = end.unwrap_or(cursor);
                    return Ok(name);
                }
            }
            _ => return Err(ResponseError::InvalidName),
        }
    }
}

fn skip_record(packet: &[u8], offset: &mut usize) -> Result<(), ResponseError> {
    read_name(packet, offset)?;
    let fields = packet
        .get(*offset..*offset + 10)
        .ok_or(ResponseError::TooShort)?;
    let record_type = read_u16(fields, 0);
    let class = read_u16(fields, 2);
    let length = usize::from(read_u16(fields, 8));
    let start = *offset + 10;
    let end = start + length;
    packet.get(start..end).ok_or(ResponseError::TooShort)?;
    validate_record_data(packet, record_type, class, start, end)?;
    *offset = end;
    Ok(())
}

fn validate_record_data(
    packet: &[u8],
    record_type: u16,
    class: u16,
    start: usize,
    end: usize,
) -> Result<(), ResponseError> {
    let length = end - start;
    if class == INTERNET_CLASS && record_type == 1 && length != 4 {
        return Err(ResponseError::InvalidRecord);
    }
    if class == INTERNET_CLASS && record_type == 28 && length != 16 {
        return Err(ResponseError::InvalidRecord);
    }
    let mut offset = start;
    match record_type {
        2 | 5 | 12 => {
            read_rdata_name(packet, &mut offset, end)?;
        }
        15 => {
            if length < 3 {
                return Err(ResponseError::InvalidRecord);
            }
            offset += 2;
            read_rdata_name(packet, &mut offset, end)?;
        }
        6 => {
            read_rdata_name(packet, &mut offset, end)?;
            read_rdata_name(packet, &mut offset, end)?;
            offset += 20;
        }
        16 => {
            if length == 0 {
                return Err(ResponseError::InvalidRecord);
            }
            while offset < end {
                offset += 1 + usize::from(packet[offset]);
            }
        }
        _ => offset = end,
    }
    if offset != end {
        return Err(ResponseError::InvalidRecord);
    }
    Ok(())
}

fn read_rdata_name(
    packet: &[u8],
    offset: &mut usize,
    end: usize,
) -> Result<WireName, ResponseError> {
    // RDATA is complete; a name that exceeds it is malformed even when TC is set.
    let name = read_name(packet, offset).map_err(|error| match error {
        ResponseError::TooShort => ResponseError::InvalidRecord,
        other => other,
    })?;
    if *offset > end {
        return Err(ResponseError::InvalidRecord);
    }
    Ok(name)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes(domain: &str, id: u16, query_type: QueryType) -> Vec<u8> {
        let mut output = Vec::new();
        encode_query(
            &DnsName::parse(domain).unwrap(),
            id,
            query_type,
            true,
            &mut output,
        );
        output
    }

    fn response_to(query: &[u8], flags: u16, answer_count: u16) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response[6..8].copy_from_slice(&answer_count.to_be_bytes());
        response
    }

    #[test]
    fn accepts_matching_response_with_compressed_answer_owner() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8180, 1);
        response.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);

        assert_eq!(
            validate_response(&query, &response),
            Ok(ResponseSummary {
                rcode: Rcode::NoError,
                truncated: false,
                answer_count: 1,
            })
        );
    }

    #[test]
    fn reports_rcode_and_truncation() {
        let query = query_bytes("example.com", 7, QueryType::A);

        for (flags, rcode, truncated) in [
            (0x8183, Rcode::NxDomain, false),
            (0x8182, Rcode::ServFail, false),
            (0x8185, Rcode::Refused, false),
            (0x838F, Rcode::Other(15), true),
        ] {
            let summary = validate_response(&query, &response_to(&query, flags, 0)).unwrap();
            assert_eq!((summary.rcode, summary.truncated), (rcode, truncated));
        }
    }

    #[test]
    fn rejects_short_packets_and_echoed_queries() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let response = response_to(&query, 0x8180, 0);

        for length in [0, 11, query.len() - 1] {
            assert_eq!(
                validate_response(&query, &response[..length]),
                Err(ResponseError::TooShort)
            );
        }
        assert_eq!(
            validate_response(&query, &query),
            Err(ResponseError::NotAResponse)
        );
    }

    #[test]
    fn rejects_responses_to_a_different_query() {
        let query = query_bytes("example.com", 7, QueryType::A);

        for (other, expected) in [
            (
                query_bytes("example.com", 8, QueryType::A),
                ResponseError::IdMismatch,
            ),
            (
                query_bytes("example.org", 7, QueryType::A),
                ResponseError::QuestionMismatch,
            ),
            (
                query_bytes("example.com", 7, QueryType::Aaaa),
                ResponseError::QuestionMismatch,
            ),
        ] {
            assert_eq!(
                validate_response(&query, &response_to(&other, 0x8180, 0)),
                Err(expected)
            );
        }

        let mut no_question = response_to(&query, 0x8180, 0);
        no_question[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            validate_response(&query, &no_question),
            Err(ResponseError::QuestionMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_opcode() {
        let query = query_bytes("example.com", 7, QueryType::A);
        assert_eq!(
            validate_response(&query, &response_to(&query, 0x8980, 0)),
            Err(ResponseError::OpcodeMismatch)
        );
    }

    #[test]
    fn accepts_independently_constructed_mixed_case_response() {
        let query = query_bytes("example.com", 0x1234, QueryType::A);
        let response = [
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'E', b'X', b'A', b'M', b'P', b'L',
            b'E', 3, b'C', b'O', b'M', 0, 0, 1, 0, 1, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
            192, 0, 2, 1,
        ];
        assert_eq!(
            validate_response(&query, &response),
            Ok(ResponseSummary {
                rcode: Rcode::NoError,
                truncated: false,
                answer_count: 1,
            })
        );
    }

    #[test]
    fn matches_name_case_insensitively_but_type_and_class_exactly() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8180, 0);
        response[13..20].make_ascii_uppercase();
        assert!(validate_response(&query, &response).is_ok());

        for field_offset in [query.len() - 4, query.len() - 2] {
            let mut different_query = query.clone();
            different_query[field_offset..field_offset + 2].copy_from_slice(&65u16.to_be_bytes());
            let mut different_response = response_to(&different_query, 0x8180, 0);
            different_response[field_offset..field_offset + 2]
                .copy_from_slice(&97u16.to_be_bytes());
            assert_eq!(
                validate_response(&different_query, &different_response),
                Err(ResponseError::QuestionMismatch)
            );
        }
    }

    #[test]
    fn question_comparison_preserves_label_boundaries() {
        let query = query_bytes("a.bc", 7, QueryType::A);
        let other = query_bytes("ab.c", 7, QueryType::A);
        assert_eq!(
            validate_response(&query, &response_to(&other, 0x8180, 0)),
            Err(ResponseError::QuestionMismatch)
        );
    }

    #[test]
    fn rejects_missing_records_in_every_section() {
        let query = query_bytes("example.com", 7, QueryType::A);
        for count_offset in [6, 8, 10] {
            let mut response = response_to(&query, 0x8180, 0);
            response[count_offset..count_offset + 2].copy_from_slice(&1u16.to_be_bytes());
            assert_eq!(
                validate_response(&query, &response),
                Err(ResponseError::TooShort)
            );
        }
    }

    #[test]
    fn validates_all_sections_and_rejects_partial_record_frames() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let record = [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1];
        for count_offset in [6, 8, 10] {
            let mut response = response_to(&query, 0x8180, 0);
            response[count_offset..count_offset + 2].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record);
            assert!(validate_response(&query, &response).is_ok());
            for end in 0..response.len() {
                assert!(
                    validate_response(&query, &response[..end]).is_err(),
                    "accepted prefix {end}"
                );
            }
        }
    }

    #[test]
    fn rejects_wrong_address_record_lengths_even_when_tc_is_set() {
        let query = query_bytes("example.com", 7, QueryType::A);
        for record_type in [1u16, 28] {
            let mut response = response_to(&query, 0x8380, 1);
            response.extend_from_slice(&[0xC0, 0x0C]);
            response.extend_from_slice(&record_type.to_be_bytes());
            response.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, 3, 192, 0, 2]);
            assert_eq!(
                validate_response(&query, &response),
                Err(ResponseError::InvalidRecord)
            );
        }
    }

    #[test]
    fn accepts_aaaa_records_and_opaque_unknown_records() {
        let query = query_bytes("example.com", 7, QueryType::Aaaa);
        for (record_type, length) in [(28u16, 16u16), (65_000, 3)] {
            let mut response = response_to(&query, 0x8180, 1);
            response.extend_from_slice(&[0xC0, 0x0C]);
            response.extend_from_slice(&record_type.to_be_bytes());
            response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            response.extend_from_slice(&length.to_be_bytes());
            response.resize(response.len() + usize::from(length), 0);
            assert!(validate_response(&query, &response).is_ok());
        }
    }

    #[test]
    fn validates_compressed_names_inside_name_records() {
        let query = query_bytes("example.com", 7, QueryType::A);
        for record_type in [2u16, 5, 12] {
            let mut response = response_to(&query, 0x8180, 1);
            response.extend_from_slice(&[0xC0, 0x0C]);
            response.extend_from_slice(&record_type.to_be_bytes());
            response.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x0C]);
            assert!(validate_response(&query, &response).is_ok());
            let end = response.len();
            response[end - 1] = 0xFF;
            assert_eq!(
                validate_response(&query, &response),
                Err(ResponseError::InvalidName)
            );
        }
    }

    #[test]
    fn distinguishes_truncation_from_missing_records() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8380, 1);
        for fragment in [&[][..], &[0xC0][..], &[0xC0, 0x0C, 0][..]] {
            response.truncate(query.len());
            response.extend_from_slice(fragment);
            let summary = validate_response(&query, &response).unwrap();
            assert!(summary.truncated);
            assert_eq!(summary.answer_count, 1);
        }
    }

    #[test]
    fn tc_does_not_excuse_malformed_complete_name_rdata() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8380, 1);
        response.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 1, 0xC0]);
        assert_eq!(
            validate_response(&query, &response),
            Err(ResponseError::InvalidRecord)
        );
    }

    #[test]
    fn rejects_trailing_bytes_outside_declared_sections() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8180, 0);
        response.push(0);
        assert_eq!(
            validate_response(&query, &response),
            Err(ResponseError::TrailingData)
        );
    }

    #[test]
    fn rejects_invalid_compression_and_label_types_without_looping() {
        for encoded in [
            vec![0xC0, 0x0C],
            vec![0xC0, 0x0E, 0],
            vec![0xFF, 0xFF],
            vec![0xC0, 0],
            vec![0x40, 0],
            vec![0x80, 0],
            vec![1, b'a', 0xC0, 0x0C],
        ] {
            let mut packet = vec![0; HEADER_LEN];
            packet.extend_from_slice(&encoded);
            let mut offset = HEADER_LEN;
            assert!(matches!(
                read_name(&packet, &mut offset),
                Err(ResponseError::InvalidName)
            ));
        }
    }

    #[test]
    fn accepts_backward_pointer_chains() {
        let mut packet = vec![0; HEADER_LEN];
        packet.extend_from_slice(&[1, b'a', 0, 0xC0, 0x0C, 0xC0, 0x0F]);
        let mut offset = 17;
        let name = read_name(&packet, &mut offset).unwrap();
        assert_eq!(name.as_slice(), &[1, b'a', 0]);
        assert_eq!(offset, 19);
    }

    #[test]
    fn rejects_overlong_expanded_names() {
        let mut packet = vec![0; HEADER_LEN];
        for _ in 0..4 {
            packet.push(63);
            packet.extend_from_slice(&[b'a'; 63]);
        }
        packet.push(0);
        let mut offset = HEADER_LEN;
        assert!(matches!(
            read_name(&packet, &mut offset),
            Err(ResponseError::InvalidName)
        ));
    }

    #[test]
    fn arbitrary_packets_and_queries_do_not_panic() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut state = 0x12345678u64;
        for length in 0..512 {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            let _ = validate_response(&query, &bytes);
            let _ = validate_response(&bytes, &query);
        }
    }

    #[test]
    fn single_byte_mutations_of_a_response_do_not_panic() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8180, 1);
        response.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        for index in 0..response.len() {
            let original = response[index];
            for byte in 0..=u8::MAX {
                response[index] = byte;
                let _ = validate_response(&query, &response);
            }
            response[index] = original;
        }
    }

    #[test]
    fn encodes_supported_query_type_numbers_and_matches_questions() {
        for (query_type, code) in [
            (QueryType::A, 1u16),
            (QueryType::Ns, 2),
            (QueryType::Cname, 5),
            (QueryType::Soa, 6),
            (QueryType::Ptr, 12),
            (QueryType::Mx, 15),
            (QueryType::Txt, 16),
            (QueryType::Aaaa, 28),
        ] {
            let query = query_bytes("example.com", 7, query_type);
            assert_eq!(&query[query.len() - 4..], &[0, code as u8, 0, 1]);
            let response = response_to(&query, 0x8180, 0);
            assert!(validate_response(&query, &response).is_ok());
            let wrong_type = if query_type == QueryType::A {
                QueryType::Mx
            } else {
                QueryType::A
            };
            let other = query_bytes("example.com", 7, wrong_type);
            assert_eq!(
                validate_response(&other, &response),
                Err(ResponseError::QuestionMismatch)
            );
        }
    }

    #[test]
    fn encodes_a_query_as_exact_wire_bytes() {
        let name = DnsName::parse("Example.COM.").unwrap();
        let mut output = Vec::new();

        encode_query(&name, 0x1234, QueryType::A, true, &mut output);

        assert_eq!(
            output,
            [
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
                0x01,
            ]
        );
    }

    #[test]
    fn encodes_root_aaaa_without_recursion() {
        let name = DnsName::parse(".").unwrap();
        let mut output = Vec::new();

        encode_query(&name, 0xABCD, QueryType::Aaaa, false, &mut output);

        assert_eq!(
            output,
            [
                0xAB, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x1C, 0x00, 0x01,
            ]
        );
    }

    #[test]
    fn reuses_buffer_without_leaving_previous_query_bytes() {
        let longer = DnsName::parse("example.com").unwrap();
        let shorter = DnsName::parse(".").unwrap();
        let mut output = Vec::with_capacity(512);
        let capacity = output.capacity();

        encode_query(&longer, 1, QueryType::A, true, &mut output);
        encode_query(&shorter, 2, QueryType::A, false, &mut output);

        assert_eq!(output.len(), 17);
        assert_eq!(&output[..2], &[0, 2]);
        assert_eq!(output.capacity(), capacity);
    }

    #[test]
    fn encodes_maximum_length_name_with_question_fields_after_it() {
        let text = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let name = DnsName::parse(&text).unwrap();
        let mut output = Vec::new();

        encode_query(&name, 0, QueryType::A, true, &mut output);

        assert_eq!(output.len(), 12 + 255 + 4);
        assert_eq!(output[12], 63);
        assert_eq!(output[76], 63);
        assert_eq!(output[140], 63);
        assert_eq!(output[204], 61);
        assert_eq!(output[266], 0);
        assert_eq!(&output[267..], &[0, 1, 0, 1]);
    }
}
