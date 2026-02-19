// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

use rvos::socket::{TcpListener, TcpStream, SocketAddr, ShutdownHow};

fn handle_client(mut stream: TcpStream, peer: SocketAddr) {
    let SocketAddr::Inet4 { a, b, c, d, port } = peer;
    println!("Connection from {}.{}.{}.{}:{}", a, b, c, d, port);

    let mut buf = [0u8; 1024];
    loop {
        let n = match stream.recv(&mut buf) {
            Ok(0) => {
                println!("Client disconnected");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                println!("recv error: {:?}", e);
                break;
            }
        };
        println!("Received {} bytes", n);

        if let Err(e) = stream.send(&buf[..n]) {
            println!("send error: {:?}", e);
            break;
        }
    }

    let _ = stream.shutdown(ShutdownHow::Both {});
}

fn main() {
    println!("TCP echo server starting...");

    let addr = SocketAddr::Inet4 { a: 0, b: 0, c: 0, d: 0, port: 7778 };
    let mut listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            println!("Bind failed: {:?}", e);
            return;
        }
    };
    println!("TCP echo server listening on port 7778");

    loop {
        let (stream, peer) = match listener.accept() {
            Ok(r) => r,
            Err(e) => {
                println!("accept error: {:?}", e);
                continue;
            }
        };
        handle_client(stream, peer);
    }
}
