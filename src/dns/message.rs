use thiserror::Error;

use crate::config::QueryType;

use super::name::DnsName;

const HEADER_LEN: usize = 12;
const RESPONSE: u16 = 1 << 15;
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

impl Rcode {
    fn from_flags(flags: u16) -> Self {
        match flags & RCODE_MASK {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            // masked to 4 bits, so this always fits
            other => Self::Other(other as u8),
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
    #[error("response is too short to answer the query")]
    TooShort,

    #[error("packet is not a DNS response")]
    NotAResponse,

    #[error("response ID does not match the query")]
    IdMismatch,

    #[error("response question does not match the query")]
    QuestionMismatch,
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

    // root will only need a terminating zero
    if name.as_str() != "." {
        for label in name.as_str().split('.') {
            // DnsName guarantees that each label is at most 63 bytes.
            output.push(label.len() as u8);
            output.extend_from_slice(label.as_bytes());
        }
    }
    output.push(0);

    let type_code: u16 = match query_type {
        QueryType::A => 1,
        QueryType::Aaaa => 28,
    };

    output.extend_from_slice(&type_code.to_be_bytes());
    output.extend_from_slice(&INTERNET_CLASS.to_be_bytes());
}

/// Validates `response` against the exact bytes produced by `encode_query`.
pub(crate) fn validate_response(
    query: &[u8],
    response: &[u8],
) -> Result<ResponseSummary, ResponseError> {
    debug_assert!(
        query.len() > HEADER_LEN,
        "query must come from encode_query"
    );

    // The echoed question makes a valid response at least as long as the query.
    if response.len() < query.len() {
        return Err(ResponseError::TooShort);
    }

    let flags = read_u16(response, 2);

    if flags & RESPONSE == 0 {
        return Err(ResponseError::NotAResponse);
    }

    if response[..2] != query[..2] {
        return Err(ResponseError::IdMismatch);
    }

    let question_count = read_u16(response, 4);

    if question_count != 1 || response[HEADER_LEN..query.len()] != query[HEADER_LEN..] {
        return Err(ResponseError::QuestionMismatch);
    }

    Ok(ResponseSummary {
        rcode: Rcode::from_flags(flags),
        truncated: flags & TRUNCATED != 0,
        answer_count: read_u16(response, 6),
    })
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
    fn accepts_matching_response_and_ignores_answer_records() {
        let query = query_bytes("example.com", 7, QueryType::A);
        let mut response = response_to(&query, 0x8180, 1); // QR, RD, RA, NOERROR.
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
    fn encodes_a_query_as_exact_wire_bytes() {
        let name = DnsName::parse("Example.COM.").unwrap();
        let mut output = Vec::new();

        encode_query(&name, 0x1234, QueryType::A, true, &mut output);

        assert_eq!(
            output,
            [
                0x12, 0x34, // ID.
                0x01, 0x00, // RD.
                0x00, 0x01, // One question.
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // No records.
                0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
                0x01, // A.
                0x00, 0x01, // IN.
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
                0xAB, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // Root name.
                0x00, 0x1C, // AAAA.
                0x00, 0x01, // IN.
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
