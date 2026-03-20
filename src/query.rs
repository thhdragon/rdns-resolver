const ZONE: &[u8; 14] = b"\x07in-addr\x04arpa\x00";
const QTYPE_PTR: &[u8; 2] = &12u16.to_be_bytes();
const QCLASS_IN: &[u8; 2] = &1u16.to_be_bytes();
const PREFIX: &[u8; 12] = &[
    0x12, 0x34, // transaction ID
    0x01, 0x00, // set flags to standard query and enable recursion.
    0x00, 0x01, // question count
    0, 0, // empty answer RR
    0, 0, // empty auth RR
    0, 0, // empty additional RR
];

pub(crate) fn build_packet(target: &str) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    // split the IP address on the '.' separators in reverse order and collect into vec
    let parts: Vec<&str> = target.split('.').rev().collect();
    packet.extend(PREFIX);
    // add the reversed octets to the packet with length labels
    // for each part, add the length of the part as a byte, then add the part itself as bytes
    for part in parts {
        packet.push(part.len() as u8);
        packet.extend(part.as_bytes());
    }
    // add ZONE
    packet.extend(ZONE);
    // add QTYPE 12 for PTR
    packet.extend(QTYPE_PTR);
    // add QCLASS 1 for IN
    packet.extend(QCLASS_IN);

    packet
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_reverse_octets() {
//         let result = reverse_octets("8.8.4.4").unwrap();
//         // use the vec macro to make a vec to compare to
//         let expected = vec!["4", "4", "8", "8"];
//         assert_eq!(result, expected)
//     }
// #[test]
// fn test_to_wire_is_valid() {
//     let parts = vec!["4", "20"]; // arbitrary input to run the function
//     let result = to_wire(&parts);

//     // test the prefix header
//     assert_eq!(&result[0..12], &[12, 13, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

//     // added [4,20] and length labels so 4 bytes for a total of 17.
//     // check that the header is 17 bytes
//     assert_eq!(result.len(), 17);

//     // test a small part of the encoding to see if adds length label correctly
//     assert_eq!((result[12], result[13]), (1, b'4'));
//     assert_eq!((result[14], result[15]), (2, b'2'));
// }
