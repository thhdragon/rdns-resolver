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
    let rdata = &buf[cursor..(cursor + rdlength)]; // don't read in the null
    println!("{:?}", rdata);

    // example output: [3, 100, 110, 115, 6, 103, 111, 111, 103, 108, 101, 0]
    // which corresponds to "dns.google" (3=dns, 6=google, 0=null terminator)
    let mut idx = 0;
    let len = rdata[idx];
    println!("{}", len);

    Ok(())
}
