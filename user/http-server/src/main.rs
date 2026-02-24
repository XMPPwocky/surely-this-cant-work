extern crate rvos_rt;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

const DEFAULT_PORT: u16 = 80;
const WWW_ROOT: &str = "/persist/www";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = if args.len() > 1 {
        args[1].parse().unwrap_or_else(|_| {
            eprintln!("http-server: invalid port: {}", args[1]);
            std::process::exit(1);
        })
    } else {
        DEFAULT_PORT
    };

    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&*bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("http-server: bind {}: {:?}", bind_addr, e);
            return;
        }
    };
    println!("http-server: listening on port {} (root={})", port, WWW_ROOT);

    loop {
        let (stream, peer) = match listener.accept() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("http-server: accept: {:?}", e);
                continue;
            }
        };
        println!("http-server: connection from {}", peer);
        handle_client(stream);
    }
}

fn handle_client(mut stream: TcpStream) {
    // Read the request (up to 2KB should be enough for the request line + headers)
    let mut req_buf = [0u8; 2048];
    let mut total = 0;
    // Read until we see \r\n\r\n or fill the buffer
    loop {
        if total >= req_buf.len() {
            break;
        }
        match stream.read(&mut req_buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                // Check for end of headers
                if req_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if total == 0 {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    let req_str = core::str::from_utf8(&req_buf[..total]).unwrap_or("");

    // Parse request line: "METHOD /path HTTP/1.x"
    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, "Bad Request", b"Bad Request\n");
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    let method = parts[0];
    let path = parts[1];

    if method != "GET" {
        send_response(&mut stream, 400, "Bad Request", b"Only GET is supported\n");
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    println!("http-server: GET {}", path);

    // Sanitize path — prevent directory traversal
    let clean_path = sanitize_path(path);
    let file_path = format!("{}{}", WWW_ROOT, clean_path);

    // Check if it's a directory and serve index.html
    let file_path = match std::fs::metadata(&file_path) {
        Ok(m) if m.is_dir() => format!("{}/index.html", file_path),
        _ => file_path,
    };

    match std::fs::read(&file_path) {
        Ok(data) => {
            let content_type = guess_content_type(&file_path);
            send_file_response(&mut stream, &data, content_type);
        }
        Err(_) => {
            send_response(&mut stream, 404, "Not Found", b"404 Not Found\n");
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
}

/// Send an HTTP response with status and body.
fn send_response(stream: &mut TcpStream, status: u16, reason: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.0 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, reason, body.len()
    );
    write_all_retry(stream, header.as_bytes());
    write_all_retry(stream, body);
}

/// Send a file as an HTTP 200 response, chunked for large files.
fn send_file_response(stream: &mut TcpStream, data: &[u8], content_type: &str) {
    let header = format!(
        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
        data.len(), content_type
    );
    write_all_retry(stream, header.as_bytes());
    // Send body in chunks to avoid overwhelming the TCP send buffer
    for chunk in data.chunks(1000) {
        write_all_retry(stream, chunk);
    }
}

/// Write all bytes, retrying on WouldBlock/NoResources with yield.
fn write_all_retry(stream: &mut TcpStream, mut data: &[u8]) {
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => break,
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(_) => break,
        }
    }
}

/// Sanitize a URL path to prevent directory traversal.
fn sanitize_path(path: &str) -> String {
    // Decode trivial cases, remove query string and fragment
    let path = path.split('?').next().unwrap_or("/");
    let path = path.split('#').next().unwrap_or("/");

    // Build clean path by resolving . and ..
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => { segments.pop(); }
            s => segments.push(s),
        }
    }

    if segments.is_empty() {
        "/".into()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Guess Content-Type from file extension.
fn guess_content_type(path: &str) -> &'static str {
    if let Some(ext) = path.rsplit('.').next() {
        match ext {
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "js" => "application/javascript",
            "json" => "application/json",
            "txt" => "text/plain",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            _ => "application/octet-stream",
        }
    } else {
        "application/octet-stream"
    }
}
