// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

use rvos::socket::{UdpSocket, SocketAddr};

fn main() {
    println!("UDP echo server starting...");

    let addr = SocketAddr::Inet4 { a: 0, b: 0, c: 0, d: 0, port: 7777 };
    let mut sock = match UdpSocket::bind(addr) {
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
        let SocketAddr::Inet4 { a, b, c, d, port } = peer;
        println!("Received {} bytes from {}.{}.{}.{}:{}", len, a, b, c, d, port);

        if let Err(e) = sock.send_to(&buf[..len], peer) {
            println!("send_to error: {:?}", e);
        }
    }
}
