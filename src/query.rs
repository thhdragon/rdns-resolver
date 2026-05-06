use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

// set constants for sections of the header that don't change

// _in_addr_arpa is the domain name suffix for reverse DNS lookups.
const ZONE: &[u8; 14] = b"\x07in-addr\x04arpa\x00";
// qtype 12 is for PTR
const QTYPE_PTR: &[u8; 2] = &12u16.to_be_bytes();
// qclass 1 is for IN
const QCLASS_IN: &[u8; 2] = &1u16.to_be_bytes();
// length of the header in bytes
const HEADER_LENGTH: usize = 12;
// first 12 bytes of the query
const PREFIX: &[u8; 12] = &[
    0x12, 0x34, // transaction ID
    0x01, 0x00, // set flags to standard query and enable recursion.
    0x00, 0x01, // question count
    0, 0, // empty answer RR
    0, 0, // empty auth RR
    0, 0, // empty additional RR
];

/// Builds the dns query packet from a target IP.
///
/// # Arguments
///
/// - `target` (`&str`) - The IP address to build the query packet for.
///
/// # Returns
///
/// - `Vec<u8>` - The DNS query packet.
///
/// # Examples
///
/// ```
/// let packet = build_packet("8.8.8.8");
/// ```
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

/// A UDP socket for DNS queries.
///
/// # Fields
///
/// - `socket` (`Socket`) - The UDP socket.
pub(crate) struct DnsSocket {
    pub(crate) socket: Socket,
}

impl DnsSocket {
    /// Creates a new UDP socket for DNS queries.
    ///
    /// # Returns
    ///
    /// - `io::Result<Self>` - A result containing a new `DnsSocket` if successful, or an I/O error if the socket could not be created.
    ///
    /// # Errors
    ///
    /// - Returns an `io::Error` if the socket could not be created, bound, or if the timeout could not be set.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = DnsSocket::new();
    /// ```
    pub(crate) fn new() -> io::Result<Self> {
        // create a new ipv4 UDP socket
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // bind the socket to any available port on the loopback interface
        let address = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let address = address.into();
        socket.bind(&address)?;

        // set timeout to 200ms for both send and receive operations
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;

        Ok(Self { socket })
    }
}

/// Sends a DNS query to the DNS server and returns the response.
///
/// # Arguments
///
/// - `query` (`&[u8]`) - The DNS query packet.
///
/// # Returns
///
/// - `io::Result<Vec<u8>>` - The DNS response packet.
///
/// # Errors
///
/// - Returns an `io::Error` if the socket could not be created, bound, or if the timeout could not be set.
///
/// # Examples
///
/// ```
/// let query: Vec<u8> = Vec::new();
/// let result = query_dns_server(&query);
/// assert!(result.is_err());
/// ```
pub(crate) fn query_dns_server(query: &[u8]) -> io::Result<Vec<u8>> {
    // create dns socket
    let mut dns_socket = DnsSocket::new()?;

    // set google dns as the target server
    let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let dns_server: SockAddr = dns_server.into();

    // send query to dns server
    dns_socket.socket.send_to(query, &dns_server)?;

    // create buffer for the response
    let mut buf = [0u8; 512]; // DNS max packet size

    // read dns response into buffer
    let bytes = dns_socket.socket.read(&mut buf)?;

    // trim the fat and return only answer section
    Ok(buf[(query.len() + HEADER_LENGTH)..bytes].to_vec())
}

/// Extracts the PTR record from the DNS answer.
///
/// # Arguments
///
/// - `answer` (`&[u8]`) - The DNS answer packet.
///
/// # Returns
///
/// - `String` - The hostname.
///
/// # Examples
///
/// ```
/// let answer = vec![3, b'd', b'n', b's', 6, b'g', b'o', b'o', b'g', b'l', b'e', 0];
/// let result = parse_answer(&answer);
/// assert_eq!(result, "dns.google");
/// ```
pub(crate) fn parse_answer(answer: &[u8]) -> String {
    // idx tracks cursor position in the answer
    let mut idx = 0;
    // create an empty string to build the hostname
    let mut host = String::new();
    // hostname in label format ends with a 0 byte. loop until we hit it
    while answer[idx] != 0 {
        // grab the `len` from idx at [0]
        let len = answer[idx];
        // move cursor past the len byte
        idx += 1;
        // copy `len` bytes, starting from `idx`, into `host`
        if let Ok(chunk) = str::from_utf8(&answer[idx..idx + (len as usize)]) {
            host.push_str(chunk);
        };
        // advance the cursor by the number of bytes we just read
        idx += len as usize;
        // add '.' if not at the end
        if answer[idx] != 0 {
            host.push('.');
        }
    }
    host
}
