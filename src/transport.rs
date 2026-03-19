use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use socket2::{Domain, Protocol, Socket, Type};
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
        socket.set_write_timeout(Some(Duration::from_millis(100)))?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        Ok(Self { socket })
    }
}

// function to receive the response
// ==receive into buffer, return bytes==
