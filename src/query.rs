use std::io;

/// Parses the target IP address and reverses its octets.
///
/// # Arguments
///
/// - `target` (`&str`) - The target IP address as a string.
///
/// # Returns
///
/// - `io::Result<Vec<&str>>` - A result containing a vector of the reversed octets if successful, or an I/O error if parsing fails.
///
/// # Errors
///
/// - Returns an `io::Error` if the input string is not a valid IP address or if any other parsing error occurs.
///
/// # Examples
///
/// ```
/// use rdns_resolver::try_from_target;
/// let ip = try_from_target(target)?;
/// assert_eq!(ip, vec!["192", "168", "1", "1"]);
/// ```
pub(crate) fn try_from_target(target: &str) -> io::Result<Vec<&str>> {
    let mut parts = target.split(".").collect::<Vec<&str>>();
    parts.reverse();
    Ok(parts)
}

// function to build ptr query
// ==encode as x.x.x.x.in-addr.arpa, assemble DNS wire format==
