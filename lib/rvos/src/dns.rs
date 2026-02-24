//! Minimal DNS resolver using UDP sockets.
//!
//! Supports A record lookups only (no CNAME following, no AAAA, no caching).

use crate::socket::{SocketAddr, SocketError, UdpSocket};

/// DNS resolution error.
#[derive(Debug)]
pub enum DnsError {
    /// Socket operation failed.
    Socket(SocketError),
    /// Invalid or empty hostname.
    InvalidName,
    /// DNS server returned an error or no answers.
    NoAnswer,
    /// Response packet was malformed.
    Malformed,
}

impl From<SocketError> for DnsError {
    fn from(e: SocketError) -> Self {
        DnsError::Socket(e)
    }
}

/// Resolve a hostname to an IPv4 address using the specified DNS server.
pub fn resolve(name: &str, dns_server: [u8; 4]) -> Result<[u8; 4], DnsError> {
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::InvalidName);
    }

    // Build DNS query packet
    let mut query = [0u8; 512];
    let len = build_query(name, &mut query)?;

    // Bind to an ephemeral port (port 0 is rejected by many DNS servers)
    let mut sock = UdpSocket::bind(SocketAddr::Inet4 {
        a: 0, b: 0, c: 0, d: 0, port: 0,
    })?;
    let server_addr = SocketAddr::Inet4 {
        a: dns_server[0],
        b: dns_server[1],
        c: dns_server[2],
        d: dns_server[3],
        port: 53,
    };
    sock.send_to(&query[..len], server_addr)?;

    // Receive response
    let mut resp = [0u8; 512];
    let (resp_len, _from) = sock.recv_from(&mut resp)?;

    // Parse response
    parse_response(&resp[..resp_len])
}

/// Resolve a hostname using the DNS server from the network configuration.
pub fn resolve_default(name: &str) -> Result<[u8; 4], DnsError> {
    let config = crate::socket::get_net_config().map_err(DnsError::Socket)?;
    resolve(name, config.dns)
}

/// Build a DNS query for an A record.
/// Returns the length of the query written to `buf`.
fn build_query(name: &str, buf: &mut [u8; 512]) -> Result<usize, DnsError> {
    // Header: 12 bytes
    // ID = 0x1234 (arbitrary, we only send one query at a time)
    buf[0] = 0x12;
    buf[1] = 0x34;
    // Flags: RD=1 (recursion desired), everything else 0
    buf[2] = 0x01;
    buf[3] = 0x00;
    // QDCOUNT = 1
    buf[4] = 0x00;
    buf[5] = 0x01;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    // (already zeroed)

    // Question section: QNAME + QTYPE + QCLASS
    let mut pos = 12;

    // Encode QNAME: each label prefixed by length byte
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        if pos + 1 + label.len() >= 500 {
            return Err(DnsError::InvalidName);
        }
        buf[pos] = label.len() as u8;
        pos += 1;
        buf[pos..pos + label.len()].copy_from_slice(label.as_bytes());
        pos += label.len();
    }
    // Null terminator for QNAME
    buf[pos] = 0;
    pos += 1;

    // QTYPE = A (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;

    // QCLASS = IN (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;

    Ok(pos)
}

/// Parse a DNS response and extract the first A record.
fn parse_response(resp: &[u8]) -> Result<[u8; 4], DnsError> {
    if resp.len() < 12 {
        return Err(DnsError::Malformed);
    }

    // Check response flags
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    // QR bit must be 1 (response)
    if flags & 0x8000 == 0 {
        return Err(DnsError::Malformed);
    }
    // Check RCODE (bottom 4 bits) — 0 = no error
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(DnsError::NoAnswer);
    }

    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return Err(DnsError::NoAnswer);
    }

    // Skip question section
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > resp.len() {
            return Err(DnsError::Malformed);
        }
    }

    // Parse answer section — find first A record
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return Err(DnsError::Malformed);
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            return Err(DnsError::Malformed);
        }
        // A record: type=1, rdlength=4
        if rtype == 1 && rdlength == 4 {
            return Ok([resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]]);
        }
        pos += rdlength;
    }

    Err(DnsError::NoAnswer)
}

/// Skip a DNS name (handling compression pointers).
fn skip_name(resp: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    let mut jumps = 0;
    loop {
        if pos >= resp.len() {
            return Err(DnsError::Malformed);
        }
        let b = resp[pos];
        if b == 0 {
            // End of name
            return Ok(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes, name ends here
            return Ok(pos + 2);
        }
        // Label: skip length + label bytes
        let label_len = b as usize;
        pos += 1 + label_len;
        jumps += 1;
        if jumps > 128 {
            return Err(DnsError::Malformed);
        }
    }
}
