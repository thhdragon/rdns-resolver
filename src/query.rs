use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io::{self, Error, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const ZONE: &[u8; 14] = b"\x07in-addr\x04arpa\x00";
const QTYPE_PTR: &[u8; 2] = &12u16.to_be_bytes();
const QCLASS_IN: &[u8; 2] = &1u16.to_be_bytes();
const HEADER_LENGTH: usize = 12;
const PREFIX: &[u8; 12] = &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

/// Builds a DNS PTR query packet for reverse IP lookup.
///
/// Constructs a well-formed DNS query in wire format by reversing the octets
/// of the given IP address, appending the `in-addr.arpa` zone suffix, and
/// prepending a fixed 12-byte header with a static transaction ID (`0x1234`),
/// standard query flags, and a question count of 1. The resulting packet is
/// ready to be sent directly to a DNS server over UDP.
///
/// # Arguments
///
/// - `target` (`IpAddr`) - The IP address to build the reverse lookup query for.
///
/// # Returns
///
/// - `Vec<u8>` - The raw DNS query packet in wire format.
///
/// # Examples
///
/// ```
/// use std::net::IpAddr;
///
/// let ip: IpAddr = "8.8.8.8".parse().unwrap();
/// let packet = build_packet(ip);
///
/// // Packet starts with the fixed 12-byte header prefix
/// assert_eq!(&packet[..2], &[0x12, 0x34]); // transaction ID
/// assert!(packet.len() > 12);
/// ```
///
/// # Notes
///
/// The transaction ID is hardcoded to `0x1234`. If you need to match
/// responses to concurrent queries, consider randomizing it per call and
/// storing the mapping before sending. Only IPv4 addresses produce a valid
/// `in-addr.arpa` PTR query; passing an IPv6 address will encode it as a
/// dotted-decimal string, which is not a valid `ip6.arpa` query.
pub(crate) fn build_packet(target: IpAddr) -> Vec<u8> {
    let target = target.to_string();
    let mut packet: Vec<u8> = Vec::new();
    let parts: Vec<&str> = target.split('.').rev().collect();
    packet.extend(PREFIX);
    for part in parts {
        packet.push(part.len() as u8);
        packet.extend(part.as_bytes());
    }
    packet.extend(ZONE);
    packet.extend(QTYPE_PTR);
    packet.extend(QCLASS_IN);
    packet
}

/// A UDP socket configured for sending DNS queries.
///
/// Wraps a [`socket2::Socket`] bound to an ephemeral local port on the
/// unspecified IPv4 address (`0.0.0.0:0`), with 200ms read/write timeouts
/// pre-applied. Intended to be created fresh per query rather than reused
/// across multiple requests.
///
/// # Fields
///
/// - `socket` (`Socket`) - The underlying UDP socket.
pub(crate) struct DnsSocket {
    pub(crate) socket: Socket,
}

impl DnsSocket {
    /// Creates a new UDP socket bound to an ephemeral local port, ready to send DNS queries.
    ///
    /// Allocates a new IPv4 UDP socket, binds it to `0.0.0.0:0` so the OS
    /// assigns an available port, and sets both the send and receive timeouts
    /// to 200ms. The socket is not connected to any server at construction
    /// time — the destination is supplied later via `send_to`.
    ///
    /// # Returns
    ///
    /// - `io::Result<Self>` - A new `DnsSocket` on success.
    ///
    /// # Errors
    ///
    /// - [`io::Error`] if socket creation fails (e.g. OS resource limits).
    /// - [`io::Error`] if binding to `0.0.0.0:0` fails.
    /// - [`io::Error`] if setting read or write timeouts fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let sock = DnsSocket::new().expect("failed to create DNS socket");
    /// // Socket is now bound and ready; use sock.socket.send_to(...) to query a server.
    /// ```
    pub(crate) fn new() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        let address = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let address = address.into();
        socket.bind(&address)?;

        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;

        Ok(Self { socket })
    }
}

/// Sends a DNS query packet to Google's public DNS server and returns the answer section.
///
/// Creates a fresh [`DnsSocket`], sends `query` to `8.8.8.8:53` over UDP, reads
/// up to 512 bytes of response (the DNS UDP maximum), and strips the echoed
/// question and 12-byte response header, returning only the raw answer section.
/// A new socket is created on every call, so this function is stateless and
/// safe to call concurrently from multiple threads.
///
/// # Arguments
///
/// - `query` (`&[u8]`) - A well-formed DNS query packet, as produced by [`build_packet`].
///
/// # Returns
///
/// - `io::Result<Vec<u8>>` - The raw bytes of the DNS answer section on success.
///
/// # Errors
///
/// - [`io::Error`] with kind `TimedOut` if the server does not respond within 200ms.
/// - [`io::Error`] with message `"Invalid Packet Size"` if the response is shorter
///   than `query.len() + 12` bytes (i.e. it doesn't contain a complete header).
/// - Any [`io::Error`] from socket creation, binding, or I/O operations.
///
/// # Examples
///
/// ```
/// use std::net::IpAddr;
///
/// let ip: IpAddr = "8.8.8.8".parse().unwrap();
/// let query = build_packet(ip);
/// match query_dns_server(&query) {
///     Ok(answer) => println!("Answer section: {:?}", answer),
///     Err(e) => eprintln!("DNS query failed: {e}"),
/// }
/// ```
///
/// # Notes
///
/// The DNS server is hardcoded to `8.8.8.8:53`. Responses larger than 512
/// bytes will be silently truncated, which is consistent with the DNS UDP
/// specification (RFC 1035 §2.3.4) — a real resolver should handle the TC
/// (truncation) flag and retry over TCP if needed, but this implementation
/// does not.
pub(crate) fn query_dns_server(query: &[u8]) -> io::Result<Vec<u8>> {
    let mut dns_socket = DnsSocket::new()?;

    let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let dns_server: SockAddr = dns_server.into();

    dns_socket.socket.send_to(query, &dns_server)?;

    let mut buf = [0u8; 512];
    let bytes = dns_socket.socket.read(&mut buf)?;

    let start = query.len() + HEADER_LENGTH;
    if bytes < start {
        return Err(Error::other("Invalid Packet Size"));
    }
    Ok(buf[(query.len() + HEADER_LENGTH)..bytes].to_vec())
}

/// Decodes a DNS name in label-encoded wire format into a dot-separated hostname string.
///
/// Walks the byte slice label by label — each label is prefixed with a
/// single length byte followed by that many ASCII bytes — until a zero-length
/// terminator is reached. Labels are joined with `.` separators. This is the
/// format used in PTR record RDATA as specified in RFC 1035 §3.1.
///
/// # Arguments
///
/// - `answer` (`&[u8]`) - The raw RDATA bytes of a DNS PTR answer, starting
///   immediately at the first length byte of the encoded name.
///
/// # Returns
///
/// - `io::Result<String>` - The decoded hostname (e.g. `"dns.google"`) on success.
///
/// # Errors
///
/// - [`io::Error`] with message `"Invalid Packet Size"` if a label's declared
///   length would read past the end of `answer`.
///
/// # Examples
///
/// ```
/// // Wire encoding of "dns.google": \x03dns\x06google\x00
/// let answer = vec![3, b'd', b'n', b's', 6, b'g', b'o', b'o', b'g', b'l', b'e', 0];
/// let hostname = parse_answer(&answer).unwrap();
/// assert_eq!(hostname, "dns.google");
///
/// // Single-label hostname
/// let answer = vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0];
/// let hostname = parse_answer(&answer).unwrap();
/// assert_eq!(hostname, "localhost");
/// ```
///
/// # Notes
///
/// This parser does **not** handle DNS message compression pointers (the
/// `0xC0` two-byte pointer form defined in RFC 1035 §4.1.4). If the answer
/// section uses compression, the pointer byte will be misread as a label
/// length and the result will be incorrect or an error.
pub(crate) fn parse_answer(answer: &[u8]) -> io::Result<String> {
    let mut idx = 0;
    let mut host = String::new();
    while answer[idx] != 0 {
        let len = answer[idx];
        idx += 1;
        if idx + (len as usize) > answer.len() {
            return Err(io::Error::other("Invalid Packet Size"));
        }
        if let Ok(chunk) = str::from_utf8(&answer[idx..idx + (len as usize)]) {
            host.push_str(chunk);
        };
        idx += len as usize;
        if answer[idx] != 0 {
            host.push('.');
        }
    }
    Ok(host)
}
