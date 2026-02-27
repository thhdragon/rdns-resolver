use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Debug)]
struct Dns {
    socket: Socket,
}

impl Dns {
    fn new() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let address = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let address = address.into();
        socket.bind(&address)?;
        Ok(Self { socket })
    }
}

fn main() -> io::Result<()> {
    let mut dns = Dns::new()?;
    let ip = "8.8.4.4";
    // split input IP string on periods. collect into vector
    let mut parts: Vec<&str> = ip.split(".").collect();
    // reverse the order of elements not reverse the elements. 127 stays 127
    parts.reverse();
    // for each element in parts get the length of the element
    // push the length and the element to the new vector
    // get the len, push len to vector, push element
    let mut query = Vec::new();
    // add header
    query.extend([12, 34]); // TX ID
    query.extend([1, 0]); // Flags: standard query, recursion desired
    query.extend([0, 1]); // QDCOUNT = 1 question
    query.extend([0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT

    for part in parts {
        let len = part.len() as u8;
        query.push(len);
        query.extend(part.as_bytes()); // moves element as bytes each loop. super clean
    }

    query.push(7); // length of "in-addr"
    query.extend_from_slice(b"in-addr");
    query.push(4); // length of "arpa"
    query.extend_from_slice(b"arpa");
    query.push(0); // null terminator
    query.extend([0, 12, 0, 1]); // QTYPE=PTR (12), QCLASS=IN (1)
    let ip: Ipv4Addr = ip.parse().expect("you suck. bad ip address");
    let addr = SocketAddr::from((ip, 53));
    let addr: SockAddr = addr.into();
    dns.socket
        .set_write_timeout(Some(Duration::from_millis(300)))?;
    dns.socket.send_to(&query, &addr)?;
    dns.socket
        .set_read_timeout(Some(Duration::from_millis(300)))?;
    let mut buf = [0u8; 512]; // DNS packets capped at 512b

    if dns.socket.read(&mut buf).is_err() {
        println!("error")
    }

    // skip forward 12 bytes and then iterate until find element `0` (null terminator)
    let cursor: usize = 12;
    
    Ok(())
}
