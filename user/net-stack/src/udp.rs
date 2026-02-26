// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

use crate::PROTO_UDP;

pub const UDP_HDR_SIZE: usize = 8;

pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    #[allow(dead_code)] // protocol header field; kept for completeness
    pub len: u16,
}

/// Verify the UDP checksum over the pseudo-header + UDP segment.
/// Returns true if the checksum is correct or zero (not computed, valid in IPv4).
pub fn udp_checksum_ok(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_segment: &[u8]) -> bool {
    let cksum_field = u16::from_be_bytes([udp_segment[6], udp_segment[7]]);
    if cksum_field == 0 {
        return true; // RFC 768: zero means no checksum computed
    }
    // Build pseudo-header and sum it together with the UDP segment.
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;
    // Pseudo-header: src IP (4), dst IP (4), zero (1), protocol (1), UDP length (2)
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += PROTO_UDP as u32; // 0x00 || protocol
    sum += udp_len as u32;
    // Sum UDP segment (header + data)
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum == 0xFFFF
}

pub fn parse_udp(packet: &[u8]) -> Option<(UdpHdr, &[u8])> {
    if packet.len() < UDP_HDR_SIZE {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
    let len = u16::from_be_bytes([packet[4], packet[5]]);
    if (len as usize) < UDP_HDR_SIZE || (len as usize) > packet.len() {
        return None;
    }
    let data = &packet[UDP_HDR_SIZE..len as usize];
    Some((UdpHdr { src_port, dst_port, len }, data))
}

pub fn build_udp(
    src_ip: &[u8; 4], dst_ip: &[u8; 4],
    src_port: u16, dst_port: u16,
    payload: &[u8], buf: &mut [u8],
) -> usize {
    let total_len = UDP_HDR_SIZE + payload.len();
    if total_len > buf.len() || total_len > 0xFFFF {
        return 0;
    }
    let sp = src_port.to_be_bytes();
    buf[0] = sp[0];
    buf[1] = sp[1];
    let dp = dst_port.to_be_bytes();
    buf[2] = dp[0];
    buf[3] = dp[1];
    let l = (total_len as u16).to_be_bytes();
    buf[4] = l[0];
    buf[5] = l[1];
    // Checksum field = 0 during computation
    buf[6] = 0;
    buf[7] = 0;
    buf[UDP_HDR_SIZE..total_len].copy_from_slice(payload);
    // Compute UDP checksum over pseudo-header + segment
    let udp_len = total_len as u16;
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += PROTO_UDP as u32;
    sum += udp_len as u32;
    let mut i = 0;
    while i + 1 < total_len {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < total_len {
        sum += (buf[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    // RFC 768: if computed checksum is 0, transmit as 0xFFFF
    let cksum = if cksum == 0 { 0xFFFF } else { cksum };
    let cb = cksum.to_be_bytes();
    buf[6] = cb[0];
    buf[7] = cb[1];
    total_len
}
