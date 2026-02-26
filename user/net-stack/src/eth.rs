// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

pub const ETH_HDR_SIZE: usize = 14;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;

pub struct EthHdr {
    #[allow(dead_code)] // protocol header field; useful for future broadcast/multicast checks
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

pub fn parse_eth(frame: &[u8]) -> Option<(EthHdr, &[u8])> {
    if frame.len() < ETH_HDR_SIZE {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some((EthHdr { dst, src, ethertype }, &frame[ETH_HDR_SIZE..]))
}

pub fn build_eth(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8], buf: &mut [u8]) -> usize {
    let total = ETH_HDR_SIZE + payload.len();
    if total > buf.len() {
        return 0;
    }
    buf[0..6].copy_from_slice(dst);
    buf[6..12].copy_from_slice(src);
    let et = ethertype.to_be_bytes();
    buf[12] = et[0];
    buf[13] = et[1];
    buf[ETH_HDR_SIZE..ETH_HDR_SIZE + payload.len()].copy_from_slice(payload);
    total
}
