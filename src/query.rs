use std::io;

pub(crate) fn reverse_octets(target: &str) -> io::Result<Vec<&str>> {
    let mut parts: Vec<&str> = target.split(".").collect();
    parts.reverse();
    Ok(parts)
}

// use slice instead of borrowing or owning the vector
// generic reader that can read from anything that an slice
pub(crate) fn to_wire(parts: &[&str]) -> Vec<u8> {
    // setup prefix
    let prefix: &[u8; 12] = &[
        12, 13, // arbitrary  transaction ID
        1, 0, // set flags to standard query and enable recursion.
        0, 1, // question count
        0, 0, // junk
        0, 0, // junk
        0, 0, // junk
    ];

    // create vector to hold the wire format u8
    let mut wired: Vec<u8> = Vec::new();
    // read the prefix into the vector
    wired.extend(prefix);

    // setup reversed ip in wired
    for part in parts {
        let len = part.len() as u8;
        // get element length push to vec
        wired.push(len);
        wired.extend(part.as_bytes());
    }

    // setup header tail todo
    wired
}

// craft header
// craft tail

// convert reversed IP to wire format.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_octets() {
        let result = reverse_octets("8.8.4.4").unwrap();
        // use the vec macro to make a vec to compare to
        let expected = vec!["4", "4", "8", "8"];
        assert_eq!(result, expected)
    }
    #[test]
    fn test_to_wire_is_valid() {
        let parts = vec!["4", "20"]; // arbitrary input to run the function
        let result = to_wire(&parts);

        // test the prefix header
        assert_eq!(&result[0..12], &[12, 13, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        // added [4,20] and length labels so 4 bytes for a total of 17.
        // check that the header is 17 bytes
        assert_eq!(result.len(), 17);

        // test a small part of the encoding to see if adds length label correctly
        assert_eq!((result[12], result[13]), (1, b'4'));
        assert_eq!((result[14], result[15]), (2, b'2'));
    }
}
