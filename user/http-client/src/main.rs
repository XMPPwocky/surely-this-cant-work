extern crate rvos_rt;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: http-get <url>");
        eprintln!("  e.g. http-get http://example.com/");
        process::exit(1);
    }

    let url = &args[1];

    let (host, port, path) = match parse_url(url) {
        Some(v) => v,
        None => {
            eprintln!("http-get: invalid URL: {}", url);
            process::exit(1);
        }
    };

    // Resolve hostname to IP
    let ip = match rvos::dns::resolve_default(&host) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("http-get: DNS resolve '{}': {:?}", host, e);
            process::exit(1);
        }
    };

    println!(
        "Connecting to {}:{} ({}.{}.{}.{})...",
        host, port, ip[0], ip[1], ip[2], ip[3]
    );

    // Connect via TCP
    let addr = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    let mut stream = match TcpStream::connect((&*addr, port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("http-get: connect: {:?}", e);
            process::exit(1);
        }
    };

    // Send HTTP/1.0 GET request
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    if let Err(e) = stream.write_all(request.as_bytes()) {
        eprintln!("http-get: write: {:?}", e);
        process::exit(1);
    }

    // Read and print response
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Print as UTF-8 (lossy for binary)
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
                print!("{}", s);
            }
            Err(e) => {
                eprintln!("\nhttp-get: read: {:?}", e);
                break;
            }
        }
    }
    println!();
}

/// Parse an HTTP URL into (host, port, path).
/// Only supports http:// (not https).
fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;

    // Split host+port from path
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    // Split host from port
    let (host, port) = match hostport.rfind(':') {
        Some(i) => {
            let port_str = &hostport[i + 1..];
            let port: u16 = port_str.parse().ok()?;
            (&hostport[..i], port)
        }
        None => (hostport, 80),
    };

    if host.is_empty() {
        return None;
    }

    Some((host.into(), port, path.into()))
}
