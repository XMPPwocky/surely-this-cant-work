// ---------------------------------------------------------------------------
// ARP
// ---------------------------------------------------------------------------

use crate::eth::{build_eth, ETHERTYPE_ARP};
use crate::{ARP_ENTRY_TTL, ARP_HLEN, BROADCAST_MAC};

pub struct ArpEntry {
    ip: [u8; 4],
    mac: [u8; 6],
    valid: bool,
    timestamp: u64,
}

pub struct ArpTable {
    entries: [ArpEntry; 8],
}

impl ArpTable {
    pub fn new() -> Self {
        ArpTable {
            entries: [const {
                ArpEntry {
                    ip: [0; 4],
                    mac: [0; 6],
                    valid: false,
                    timestamp: 0,
                }
            }; 8],
        }
    }

    pub fn lookup(&self, ip: &[u8; 4], now: u64) -> Option<[u8; 6]> {
        for e in &self.entries {
            if e.valid && e.ip == *ip && now.wrapping_sub(e.timestamp) < ARP_ENTRY_TTL {
                return Some(e.mac);
            }
        }
        None
    }

    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6], now: u64) {
        // Update existing entry
        for e in &mut self.entries {
            if e.valid && e.ip == ip {
                e.mac = mac;
                e.timestamp = now;
                return;
            }
        }
        // Find empty slot
        for e in &mut self.entries {
            if !e.valid {
                e.ip = ip;
                e.mac = mac;
                e.valid = true;
                e.timestamp = now;
                return;
            }
        }
        // Evict oldest entry
        let mut oldest_idx = 0;
        let mut oldest_age = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            let age = now.wrapping_sub(e.timestamp);
            if age > oldest_age {
                oldest_age = age;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx].ip = ip;
        self.entries[oldest_idx].mac = mac;
        self.entries[oldest_idx].valid = true;
        self.entries[oldest_idx].timestamp = now;
    }

    /// Remove entries older than ARP_ENTRY_TTL.
    pub fn expire(&mut self, now: u64) {
        for e in &mut self.entries {
            if e.valid && now.wrapping_sub(e.timestamp) >= ARP_ENTRY_TTL {
                e.valid = false;
            }
        }
    }
}

/// Handle an incoming ARP packet: update ARP table, optionally build a reply frame.
/// Returns the total frame length (including Ethernet header) if a reply should be sent.
pub fn handle_arp(
    arp_table: &mut ArpTable,
    our_mac: &[u8; 6],
    our_ip: &[u8; 4],
    payload: &[u8],
    reply_buf: &mut [u8],
    now: u64,
) -> Option<usize> {
    if payload.len() < ARP_HLEN {
        return None;
    }
    // Validate hardware type (Ethernet) and protocol type (IPv4)
    let hw_type = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
    if hw_type != 0x0001 || proto_type != 0x0800 {
        return None;
    }
    let hw_len = payload[4];
    let proto_len = payload[5];
    if hw_len != 6 || proto_len != 4 {
        return None;
    }

    let operation = u16::from_be_bytes([payload[6], payload[7]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&payload[8..14]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&payload[14..18]);
    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&payload[24..28]);

    // Always learn the sender
    arp_table.insert(sender_ip, sender_mac, now);

    // If this is a request targeting our IP, send a reply
    if operation == 1 && target_ip == *our_ip {
        // Build ARP reply payload
        let mut arp_payload = [0u8; ARP_HLEN];
        // Hardware type: Ethernet
        arp_payload[0] = 0x00;
        arp_payload[1] = 0x01;
        // Protocol type: IPv4
        arp_payload[2] = 0x08;
        arp_payload[3] = 0x00;
        // Hardware addr len
        arp_payload[4] = 6;
        // Protocol addr len
        arp_payload[5] = 4;
        // Operation: reply
        arp_payload[6] = 0x00;
        arp_payload[7] = 0x02;
        // Sender MAC (ours)
        arp_payload[8..14].copy_from_slice(our_mac);
        // Sender IP (ours)
        arp_payload[14..18].copy_from_slice(our_ip);
        // Target MAC
        arp_payload[18..24].copy_from_slice(&sender_mac);
        // Target IP
        arp_payload[24..28].copy_from_slice(&sender_ip);

        let frame_len = build_eth(&sender_mac, our_mac, ETHERTYPE_ARP, &arp_payload, reply_buf);
        if frame_len > 0 {
            return Some(frame_len);
        }
    }

    None
}

pub fn send_arp_request(our_mac: &[u8; 6], our_ip: &[u8; 4], target_ip: &[u8; 4], buf: &mut [u8]) -> usize {
    let mut arp_payload = [0u8; ARP_HLEN];
    // Hardware type: Ethernet
    arp_payload[0] = 0x00;
    arp_payload[1] = 0x01;
    // Protocol type: IPv4
    arp_payload[2] = 0x08;
    arp_payload[3] = 0x00;
    // Hardware addr len
    arp_payload[4] = 6;
    // Protocol addr len
    arp_payload[5] = 4;
    // Operation: request
    arp_payload[6] = 0x00;
    arp_payload[7] = 0x01;
    // Sender MAC (ours)
    arp_payload[8..14].copy_from_slice(our_mac);
    // Sender IP (ours)
    arp_payload[14..18].copy_from_slice(our_ip);
    // Target MAC: zeroed (unknown)
    // arp_payload[18..24] already zero
    // Target IP
    arp_payload[24..28].copy_from_slice(target_ip);

    build_eth(&BROADCAST_MAC, our_mac, ETHERTYPE_ARP, &arp_payload, buf)
}
