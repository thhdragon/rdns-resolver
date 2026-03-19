# RDNS Lookup

## IP Address Processing

- [x] User initiates a reverse DNS lookup for an IP address.  
- [x] The system checks if the IP address is valid and properly formatted.  
- [x] Split the IP address into its octets and reverse their order.  
- [ ] Convert reversed IP to wire format.  
  - for each octet  
    - [ ] get length of the octet and push to vector
    - [ ] convert octet to ASCII bytes and push to vector

## Build Packet

### Header

- [ ] craft header
  - [ ] two bytes for the transaction ID (randomly generated)
  - [ ] two bytes for flags (set to 0x0100 `[1,0]` for a standard query) enable recursion
  - [ ] two bytes for the number of questions (set to 0x0001 `1` for one question)
  - [ ] fill remaining 6 bytes with zeros `[0;6]`

### Wire format the IP section of the question

- [ ] craft question section from IP
  - [ ] split the reversed IP address into its octets
  - [ ] for each octet, add a length byte followed by the octet's ASCII representation
  - [ ] append a zero byte to indicate the end of the domain name

### Question Tail in wire format

- [ ] craft question tail
  - [ ] length 7 - b"in-addr"
  - [ ] length 3 - b"arpa"
  - [ ] length 0 - end of domain name
  - [ ] two bytes for the query type (set to 0x000C `[0,12]` for PTR record)
  - [ ] two bytes for the query class (set to 0x0001 `[0,1]` for IN)

### Combine all sections into a single packet

- [ ] combine header, question section, and question tail into a single packet
