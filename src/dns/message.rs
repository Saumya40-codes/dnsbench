use crate::config::QueryType;

use super::name::DnsName;

const RECURSION_DESIRED: u16 = 1 << 8;
const INTERNET_CLASS: u16 = 1;

/// Replace the buffer contents with one uncompressed DNS question.
/// The caller retains the buffer allocation for reuse after sending.
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

    // The root has no nonempty labels; it only needs the terminating zero.
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

#[cfg(test)]
mod tests {
    use super::*;

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
