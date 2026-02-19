// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

use std::net::UdpSocket;

fn main() {
    println!("UDP echo server starting...");

    let sock = match UdpSocket::bind("0.0.0.0:7777") {
        Ok(s) => s,
        Err(e) => {
            println!("Bind failed: {:?}", e);
            return;
        }
    };
    println!("UDP echo server listening on port 7777");

    let mut buf = [0u8; 1024];
    loop {
        let (len, peer) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                println!("recv_from error: {:?}", e);
                return;
            }
        };
        println!("Received {} bytes from {}", len, peer);

        if let Err(e) = sock.send_to(&buf[..len], peer) {
            println!("send_to error: {:?}", e);
        }
    }
}
