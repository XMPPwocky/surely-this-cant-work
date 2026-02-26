// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

pub const IPV4_HDR_SIZE: usize = 20;

pub struct IpHdr {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    #[allow(dead_code)] // protocol header field; kept for completeness
    pub total_len: u16,
}

pub fn parse_ipv4(packet: &[u8]) -> Option<(IpHdr, &[u8])> {
    if packet.len() < IPV4_HDR_SIZE {
        return None;
    }
    let ver_ihl = packet[0];
    let version = ver_ihl >> 4;
    let ihl = (ver_ihl & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let hdr_len = ihl * 4;
    if packet.len() < hdr_len {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    if (total_len as usize) > packet.len() || (total_len as usize) < hdr_len {
        return None;
    }
    let proto = packet[9];
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    dst.copy_from_slice(&packet[16..20]);
    let payload = &packet[hdr_len..total_len as usize];
    Some((IpHdr { src, dst, proto, total_len }, payload))
}

pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_ipv4(src: &[u8; 4], dst: &[u8; 4], proto: u8, payload: &[u8], buf: &mut [u8]) -> usize {
    let total_len = IPV4_HDR_SIZE + payload.len();
    if total_len > buf.len() || total_len > 0xFFFF {
        return 0;
    }
    // Version + IHL
    buf[0] = 0x45;
    // DSCP/ECN
    buf[1] = 0;
    // Total length
    let tl = (total_len as u16).to_be_bytes();
    buf[2] = tl[0];
    buf[3] = tl[1];
    // Identification
    buf[4] = 0;
    buf[5] = 0;
    // Flags (DF) + Fragment offset
    buf[6] = 0x40;
    buf[7] = 0x00;
    // TTL
    buf[8] = 64;
    // Protocol
    buf[9] = proto;
    // Checksum placeholder
    buf[10] = 0;
    buf[11] = 0;
    // Source IP
    buf[12..16].copy_from_slice(src);
    // Dest IP
    buf[16..20].copy_from_slice(dst);
    // Compute checksum
    let cksum = ip_checksum(&buf[..IPV4_HDR_SIZE]);
    let ck = cksum.to_be_bytes();
    buf[10] = ck[0];
    buf[11] = ck[1];
    // Payload
    buf[IPV4_HDR_SIZE..total_len].copy_from_slice(payload);
    total_len
}
