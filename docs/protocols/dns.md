# DNS Protocol

The DNS client library provides hostname-to-IPv4 resolution via standard
DNS A record queries over UDP. It is used by user-space programs (e.g.,
`http-client`) to resolve hostnames before making TCP connections.

Implementation: `lib/rvos/src/dns.rs`

## API

```rust
/// Resolve a hostname to an IPv4 address using the specified DNS server.
pub fn resolve(name: &str, dns_server: [u8; 4]) -> Result<[u8; 4], DnsError>;

/// Resolve using the DNS server from network configuration (DHCP-provided).
pub fn resolve_default(name: &str) -> Result<[u8; 4], DnsError>;
```

## Protocol

The resolver builds a standard DNS query packet (RFC 1035) and sends it
via UDP to port 53 on the configured DNS server:

```
Client                         DNS Server
  |                                 |
  |-- UDP query (A record) ------->|  port 53
  |<-- UDP response (A record) ----|
  |                                 |
```

### Query Format

- 12-byte header: ID=`0x1234`, flags=`RD` (recursion desired), QDCOUNT=1
- Question section: QNAME (encoded as length-prefixed labels), QTYPE=A (1),
  QCLASS=IN (1)
- Maximum query size: 512 bytes

### Response Parsing

1. Validate QR=1 (response), RCODE=0 (no error)
2. Skip question section (using name compression pointer handling)
3. Scan answer section for the first A record (RTYPE=1, RDLENGTH=4)
4. Return the 4-byte IPv4 address

## Error Handling

**DnsError** variants:

| Variant     | Meaning                                    |
|-------------|--------------------------------------------|
| Socket      | UDP socket operation failed                |
| InvalidName | Empty hostname or length > 253 bytes       |
| NoAnswer    | Server returned error or no A records      |
| Malformed   | Response packet could not be parsed        |

## Limitations

- A records only (no AAAA, CNAME following, SRV, MX, etc.)
- No response caching
- Single query per resolution (no retries or fallback servers)
- Maximum label length: 63 bytes; maximum name length: 253 bytes
- Fixed query ID (adequate for single-threaded sequential use)

## Usage Example

```rust
use rvos::dns;
use rvos::socket;

// Using explicit DNS server
let ip = dns::resolve("example.com", [8, 8, 8, 8])?;

// Using DHCP-provided DNS server
let ip = dns::resolve_default("example.com")?;
```
