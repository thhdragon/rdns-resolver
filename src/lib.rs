use std::{io, net::IpAddr};

use query::*;

pub(crate) mod query;

/// Public API for reverse DNS resolution
///
/// # Arguments
///
/// - `target` (`&str`) - The IP address to reverse lookup.
///
/// # Returns
///
/// - `io::Result<String>` - The hostname.
///
/// # Errors
///
/// - Returns an `io::Error` if the socket could not be created, bound, or if the timeout could not be set.
/// - Returns an `io::Error` if the query could not be sent to the DNS server.
///
/// # Examples
///
/// ```
/// let hostname = lookup("8.8.8.8").expect("Failed to resolve hostname");
/// println!("Hostname: {}", hostname);
/// ```
pub fn lookup(target: IpAddr) -> io::Result<String> {
    // pass ip str to function to build query packet
    let query = build_packet(target);

    // ask the dns server our question
    let answer = query_dns_server(&query)?;

    // parse hostname from answer
    let hostname = parse_answer(&answer)?;

    Ok(hostname)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_lookup_reverse() {
        let result = lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        let expected = String::from("dns.google");
        assert_eq!(result, expected);
    }
}
