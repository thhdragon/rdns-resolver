use std::io;

use query::*;

mod query;

// ---------lib api---------------
// function to perform the reverse dns lookup
// ==calls the functions in order==
pub fn lookup(target: &str) -> io::Result<String> {
    // pass ip str to function to build query packet
    let query = build_packet(target);

    // ask the dns server our question
    let labeled_answer = query_dns_server(&query)?;

    //

    Ok("todo!()".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_reverse() {
        // Set a breakpoint on the next line and step through
        let result = lookup("8.8.8.8");
        assert!(result.is_ok());
    }
}
