use std::io;

use query::*;

mod query;

pub fn lookup(target: &str) -> io::Result<String> {
    // pass ip str to function to build query packet
    let query = build_packet(target);

    // ask the dns server our question
    let answer = query_dns_server(&query)?;

    // parse hostname from answer
    let hostname = parse_answer(&answer);

    Ok(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_reverse() {
        let result = lookup("8.8.8.8").unwrap();
        let expected = String::from("dns.google");
        assert_eq!(result, expected);
    }
}
