use super::*;
use crate::{
    config::QueryType,
    dns::{message::encode_query, name::DnsName},
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
