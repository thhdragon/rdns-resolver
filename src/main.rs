use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Dns struct holds a DNS socket
#[derive(Debug)]
struct Dns {
    /// rDNS UDP Socket
    socket: Socket,
}

impl Dns {
    /// Create a new DNS resolver with an unbound UDP socket
    ///
    /// # Returns
    ///
    /// Returns a new instance of `Dns` bound to port 0, or an error
    /// if creating the socket or binding fails.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the UDP socket cant be created or bound.
    fn new() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let address = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let address = address.into();
        socket.bind(&address)?;
        Ok(Self { socket })
    }
}

/// Performs a reverse DNS lookup on the IP address (currently 8.8.4.4 HC)
///
/// Constructs a DNS query packet in the standard wire format, sends it to
/// the requested DNS server, and parses the response to extract the PTR record.
///
/// # Errors
///
/// Returns an `io::Error` if socket operations fail or the DNS server doesn't respond
/// within the configured timeout (currently 300ms HC)
fn main() -> io::Result<()> {
    let mut dns = Dns::new()?;

    // phase 1 construct dns query packet
    let ip = "8.8.4.4";
    // split input IP string on periods. collect into vector
    let mut parts: Vec<&str> = ip.split(".").collect();
    // reverse the order of elements not reverse the elements. 127 stays 127
    parts.reverse();
    // for each element in parts get the length of the element
    // push the length and the element to the new vector
    // get the len, push len to vector, push element
    let mut query = Vec::new();
    // DNS packet structure: Header (12 bytes) + Question section
    query.extend([12, 34]); // TX ID: arbitrary 16-bit identifier for matching query/response
    query.extend([1, 0]); // Flags: standard query (0x0100), recursion desired
    query.extend([0, 1]); // QDCOUNT: 1 question in this packet
    query.extend([0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT: all 0 (standard query, not response)

    // Encode reversed IP as DNS labels (e.g., 8.8.4.4 -> 4.4.8.8 -> [4][4][8][8][in-addr][arpa])
    for part in parts {
        let len = part.len() as u8;
        query.push(len); // Push label length
        query.extend(part.as_bytes()); // Push label bytes
    }

    query.push(7); // length of "in-addr"
    query.extend_from_slice(b"in-addr");
    query.push(4); // length of "arpa"
    query.extend_from_slice(b"arpa");
    query.push(0); // null terminator
    query.extend([0, 12, 0, 1]); // QTYPE=PTR (12), QCLASS=IN (1)
    let mut cursor: usize = query.len();

    // phase 2: send query to dns server
    let ip: Ipv4Addr = ip.parse().expect("you suck. bad ip address");
    let addr = SocketAddr::from((ip, 53));
    let addr: SockAddr = addr.into();
    dns.socket
        .set_write_timeout(Some(Duration::from_millis(300)))?;
    dns.socket.send_to(&query, &addr)?;
    dns.socket
        .set_read_timeout(Some(Duration::from_millis(300)))?;

    // phase 3: receive and parse response
    let mut buf = [0u8; 512]; // DNS packets capped at 512b

    if dns.socket.read(&mut buf).is_err() {
        println!("error")
    }

    // DNS response format: Header (12 bytes) + Question echo + Answer section
    // Skip past question section (name pointer + type/class = 10 bytes)
    println!("{}, {}", buf[cursor], buf[cursor + 1]); // Name pointer: 0xC0 = pointer to byte 12
    cursor += 10;
    // Read RDLENGTH (2 bytes) to determine length of RDATA
    println!("{}, {}", buf[cursor], buf[cursor + 1]); // RDLENGTH
    // Convert RDLENGTH from big-endian bytes to usize
    let rdlength: usize = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]).into();
    println!("u16: {}", rdlength);
    // Move cursor past RDLENGTH to start of RDATA
    cursor += 2;
    // Read RDATA based on RDLENGTH (should be the PTR record string)
    let rdata = &buf[cursor..(cursor + rdlength)];
    println!("{:?}", rdata);

    // example output: [3, 100, 110, 115, 6, 103, 111, 111, 103, 108, 101, 0]
    // which corresponds to "dns.google" (3=dns, 6=google, 0=null terminator)
    // init len to idx 0 of rdata. should be the first length identifier
    parse_dns_name(rdata);
    Ok(())
}

/// Parses a DNS name from the given RDATA bytes, extracting the labels and returning them as a vector of strings.
///
/// # Arguments
///
/// - `rdata` (`&[u8]`) - The raw bytes of the DNS name to parse.
///
/// # Returns
///
/// - `Vec<String>` - A vector containing the parsed labels of the DNS name.
///
/// # Examples
///
/// ```
/// let rdata = [3, 100, 110, 115, 6, 103, 111, 111, 103, 108, 101, 0]; // corresponds to "dns.google"
/// let labels = parse_dns_name(&rdata);
/// assert_eq!(labels, vec!["dns".to_string(), "google".to_string()]);
/// ```
fn parse_dns_name(rdata: &[u8]) -> Vec<String> {
    // DNS names are encoded as a series of labels, each prefixed by its length, and terminated by a zero-length label.
    // Initialize a mutable slice to traverse the RDATA
    let mut rest = rdata;
    // Initialize an empty vector to hold the parsed labels
    let mut labels: Vec<String> = Vec::new();

    // Loop until we encounter a zero-length label (indicating the end of the name)
    // In each iteration, we read the length of the next label, extract the label, and update our position in the RDATA
    // The loop continues as long as there are bytes left to read and the length of the next label is not zero
    while let Some((&len, tail)) = rest.split_first() {
        // If the length is zero, we've reached the end of the name
        if len == 0 {
            // Break the loop if we encounter a zero-length label, which indicates the end of the name
            break;
        }
        // Extract the label based on the length and update the remaining slice
        let (label, remaining) = tail.split_at(len as usize);
        // Convert the label bytes to a string and add it to the labels vector
        labels.push(String::from_utf8_lossy(label).to_string());
        // Update the rest slice to continue parsing the next label
        rest = remaining
    }

    // Return the vector of parsed labels, which represents the components of the domain name
    labels
}
