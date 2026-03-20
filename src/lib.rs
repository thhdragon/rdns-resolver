use std::io;

use query::*;
use transport::*;

mod query;
mod response;
mod transport;

// ---------lib api---------------
// function to perform the reverse dns lookup
// ==calls the functions in order==
pub fn lookup(target: &str) -> io::Result<String> {
    // pass ip str to function to build query packet
    let query = build_packet(target);
    let dns = DnsSocket::new()?;
    // dns.socket.send_to(packet, address)?;

    let mut buf = [0u8; 512]; // DNS packets capped at 512b
    // dns.socket.read(&mut buf)?;
    Ok(todo!())
}
