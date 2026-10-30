use super::*;
use crate::{
    config::QueryType,
    dns::{
        message::{encode_query, validate_response},
        name::DnsName,
    },
};

fn response(answers: u16, authority: u16, additional: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    encode_query(
        &DnsName::parse("example.com").unwrap(),
        7,
        QueryType::A,
        true,
        &mut packet,
    );
    packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    for (offset, count) in [(6, answers), (8, authority), (10, additional)] {
        packet[offset..offset + 2].copy_from_slice(&count.to_be_bytes());
    }
    packet
}

fn record(packet: &mut Vec<u8>, record_type: u16, data: &[u8]) {
    packet.extend_from_slice(&[0xC0, 0x0C]);
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
    packet.extend_from_slice(data);
}

#[test]
fn decodes_addresses_compressed_names_sections_and_ttl() {
    let mut packet = response(3, 1, 1);
    record(&mut packet, 5, &[3, b'w', b'w', b'w', 0xC0, 0x0C]);
    record(&mut packet, 1, &[192, 0, 2, 1]);
    record(
        &mut packet,
        28,
        &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets(),
    );
    record(&mut packet, 2, &[2, b'n', b's', 0xC0, 0x0C]);
    record(&mut packet, 65_000, &[1, 2, 3]);
    let records = decode_records(&packet).unwrap();
    assert_eq!(records.len(), 5);
    assert_eq!(records[0].value, "www.example.com.");
    assert_eq!(records[1].value, "192.0.2.1");
    assert_eq!(records[2].value, "2001:db8::1");
    assert_eq!(records[3].value, "ns.example.com.");
    assert_eq!(records[3].section, Section::Authority);
    assert_eq!(records[4].section, Section::Additional);
    assert_eq!(records[4].value, "<3 bytes; not decoded>");
    assert!(
        records
            .iter()
            .all(|record| record.name == "example.com." && record.ttl == 60 && record.class == 1)
    );
    assert!(records[3].to_string().contains("IN NS ns.example.com."));
}

#[test]
fn returns_only_complete_records_from_truncated_responses() {
    let mut packet = response(2, 0, 0);
    packet[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
    record(&mut packet, 1, &[192, 0, 2, 1]);
    packet.push(0xC0);
    assert_eq!(decode_records(&packet).unwrap().len(), 1);
    packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    assert_eq!(decode_records(&packet), Err(ResponseError::TooShort));
}

#[test]
fn binary_and_embedded_dot_labels_are_escaped_for_display() {
    let mut packet = response(1, 0, 0);
    record(&mut packet, 2, &[3, b'.', 27, b'\\', 0xC0, 0x0C]);
    let records = decode_records(&packet).unwrap();
    assert_eq!(records[0].value, "\\046\\027\\092.example.com.");
    assert!(!records[0].to_string().contains(char::from(27)));
}

#[test]
fn malformed_address_and_name_data_are_rejected_without_panics() {
    for (record_type, data) in [(1, vec![192, 0, 2]), (2, vec![0xC0, 0xFF])] {
        let mut packet = response(1, 0, 0);
        record(&mut packet, record_type, &data);
        assert!(decode_records(&packet).is_err());
    }
    for len in 0..12 {
        assert!(decode_records(&vec![0; len]).is_err());
    }
}

#[test]
fn decodes_mx_soa_and_binary_txt_records() {
    let mut packet = response(4, 0, 0);
    let query = packet.clone();
    record(
        &mut packet,
        15,
        &[0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 0x0C],
    );
    record(&mut packet, 15, &[0, 0, 0]);
    let mut soa = vec![2, b'n', b's', 0xC0, 0x0C, 10];
    soa.extend_from_slice(b"hostmaster");
    soa.extend_from_slice(&[0xC0, 0x0C]);
    for number in [u32::MAX, 3600, 600, 86400, 60] {
        soa.extend_from_slice(&number.to_be_bytes());
    }
    record(&mut packet, 6, &soa);
    record(
        &mut packet,
        16,
        &[
            5, b'h', b'e', b'l', b'l', b'o', 0, 6, b'a', b'"', b'\\', 0, 27, 255,
        ],
    );
    let records = decode_records(&packet).unwrap();
    assert_eq!(records[0].value, "10 mail.example.com.");
    assert_eq!(records[1].value, "0 .");
    assert_eq!(
        records[2].value,
        "ns.example.com. hostmaster.example.com. 4294967295 3600 600 86400 60"
    );
    assert_eq!(records[3].value, r#""hello" "" "a\"\\\000\027\255""#);
    assert!(
        records[0]
            .to_string()
            .contains("IN MX 10 mail.example.com.")
    );
    assert!(records[2].to_string().contains("IN SOA ns.example.com."));
    assert!(records[3].to_string().contains("IN TXT"));
    let mut query = query;
    query[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    query[6..8].copy_from_slice(&0u16.to_be_bytes());
    assert!(validate_response(&query, &packet).is_ok());
}

#[test]
fn rejects_malformed_known_rdata_even_when_truncated_flag_is_set() {
    let mut short_soa = vec![0, 0];
    short_soa.extend_from_slice(&[0; 19]);
    let mut long_soa = vec![0, 0];
    long_soa.extend_from_slice(&[0; 21]);
    for (kind, data) in [
        (15, vec![]),
        (15, vec![0, 10]),
        (15, vec![0, 10, 0, 99]),
        (15, vec![0, 10, 0xC0, 0xFF]),
        (6, short_soa),
        (6, long_soa),
        (6, vec![0xC0, 0x0C]),
        (16, vec![]),
        (16, vec![2, b'a']),
        (16, vec![0, 1]),
    ] {
        for flags in [0x8180u16, 0x8380] {
            let mut packet = response(1, 0, 0);
            let mut query = packet.clone();
            query[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
            query[6..8].fill(0);
            packet[2..4].copy_from_slice(&flags.to_be_bytes());
            record(&mut packet, kind, &data);
            assert!(
                validate_response(&query, &packet).is_err(),
                "accepted type {kind}: {data:?}"
            );
            assert!(
                decode_records(&packet).is_err(),
                "decoded type {kind}: {data:?}"
            );
        }
    }
}

#[test]
fn txt_accepts_empty_strings_and_maximum_length_strings() {
    for (data, expected) in [
        (vec![0], "\"\"".to_owned()),
        (
            {
                let mut data = vec![255];
                data.extend_from_slice(&[b'a'; 255]);
                data
            },
            format!("\"{}\"", "a".repeat(255)),
        ),
    ] {
        let mut packet = response(1, 0, 0);
        record(&mut packet, 16, &data);
        assert_eq!(decode_records(&packet).unwrap()[0].value, expected);
    }
}

#[test]
fn mutations_of_mx_soa_and_txt_packets_do_not_panic() {
    let mut soa = vec![0, 0];
    soa.extend_from_slice(&[0; 20]);
    for (kind, data) in [(15, vec![0, 10, 0xC0, 0x0C]), (6, soa), (16, vec![1, b'a'])] {
        let mut packet = response(1, 0, 0);
        record(&mut packet, kind, &data);
        for index in 0..packet.len() {
            let original = packet[index];
            for byte in 0..=u8::MAX {
                packet[index] = byte;
                let _ = decode_records(&packet);
            }
            packet[index] = original;
        }
    }
}
