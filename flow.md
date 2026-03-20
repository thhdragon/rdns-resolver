# RDNS Lookup

## IP Address Processing

- [x] User initiates a reverse DNS lookup for an IP address.  
- [ ] The system checks if the IP address is valid and properly formatted.  
- [x] Split the IP address into its octets and reverse their order.  
- [x] Convert reversed IP to wire format.  
  - for each octet  
    - [x] get length of the octet and push to vector
    - [x] convert octet to ASCII bytes and push to vector

## Build Packet

### Header

- [x] craft header
  - [x] two bytes for the transaction ID (randomly generated)
  - [x] two bytes for flags (set to 0x0100 `[1,0]` for a standard query) enable recursion
  - [x] two bytes for the number of questions (set to 0x0001 `1` for one question)
  - [x] fill remaining 6 bytes with zeros `[0;6]`

### Wire format the IP section of the question

- [x] craft question section from IP
  - [x] split the reversed IP address into its octets
  - [x] for each octet, add a length byte followed by the octet's ASCII representation

### Question Tail in wire format

- [x] craft question tail
  - [x] length 7 - b"in-addr"
  - [x] length 3 - b"arpa"
  - [x] length 0 - end of domain name
  - [x] two bytes for the query type (set to 0x000C `12u16.to_be_bytes()` for PTR record)
  - [x] two bytes for the query class (set to 0x0001 `1u16.to_be_bytes()` for IN)

### Combine all sections into a single packet

- [ ] combine header, question section, and question tail into a single packet
