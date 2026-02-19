// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) {
    let peer = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            println!("peer_addr error: {:?}", e);
            return;
        }
    };
    println!("Connection from {}", peer);

    let mut buf = [0u8; 1024];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => {
                println!("Client disconnected");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                println!("read error: {:?}", e);
                break;
            }
        };
        println!("Received {} bytes", n);

        if let Err(e) = stream.write_all(&buf[..n]) {
            println!("write error: {:?}", e);
            break;
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
}

fn main() {
    println!("TCP echo server starting...");

    let listener = match TcpListener::bind("0.0.0.0:7778") {
        Ok(l) => l,
        Err(e) => {
            println!("Bind failed: {:?}", e);
            return;
        }
    };
    println!("TCP echo server listening on port 7778");

    loop {
        let (stream, _peer) = match listener.accept() {
            Ok(r) => r,
            Err(e) => {
                println!("accept error: {:?}", e);
                continue;
            }
        };
        handle_client(stream);
    }
}
