use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const ZONE: &[u8; 14] = b"\x07in-addr\x04arpa\x00";
const QTYPE_PTR: &[u8; 2] = &12u16.to_be_bytes();
const QCLASS_IN: &[u8; 2] = &1u16.to_be_bytes();
const HEADER_LENGTH: usize = 12;

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
    /// use crate::rdns_resolver::transport;
    ///
    /// let s = DnsSocket::new();
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

// ---------response parsing---------------
// function to extract the ptr record from the response
// ==find the PTR record in the answer section and return the hostname==
