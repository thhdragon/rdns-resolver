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
    let prefix = &[
        12, 13, // arbitrary  transaction ID
        1, 0, // set flags to standard query and enable recursion.
        0, 1, // question count
        0, 0, // junk
        0, 0, // junk
        0, 0, // junk
    ];

    let mut wired = Vec::new();
    // setup reversed ip in wired
    for part in parts {
        let len = part.len() as u8;
        // get element length push to vec
        wired.push(len);
        wired.extend(part.as_bytes());
    }
    // setup header tail
    todo!()
}

// craft header
// craft tail

// convert reversed IP to wire format.
