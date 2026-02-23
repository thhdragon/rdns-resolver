use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use socket2::{Domain, Protocol, Socket, Type};

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
        println!("{:?}", socket);
        Ok(Self { socket })
    }
}

fn main() -> io::Result<()> {
    Dns::new()?;
    Ok(())
}
