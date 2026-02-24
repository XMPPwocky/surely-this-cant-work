extern crate rvos_rt;

use std::io::Write;
use std::process;

use rvos::raw;
use rvos::rvos_wire;
use rvos::Message;
use rvos_proto::fs::{FileOffset, FileRequest, FileResponse};
use rvos_proto::socket::*;

use termserv::{TermOutput, TermServer};

// ── Address parsing ─────────────────────────────────────────────

fn parse_addr(host: &str, port: u16) -> SocketAddr {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        eprintln!("nc: invalid address: {}", host);
        process::exit(1);
    }
    let mut o = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        o[i] = part.parse().unwrap_or_else(|_| {
            eprintln!("nc: invalid address: {}", host);
            process::exit(1);
        });
    }
    SocketAddr::Inet4 {
        a: o[0],
        b: o[1],
        c: o[2],
        d: o[3],
        port,
    }
}

// ── Socket helpers ──────────────────────────────────────────────

fn create_socket(sock_type: SocketType) -> usize {
    let svc = rvos::connect_to_service("net").unwrap_or_else(|e| {
        eprintln!("nc: connect to net: {:?}", e);
        process::exit(1);
    });
    let h = svc.into_raw_handle();
    let mut msg = Message::new();
    msg.len =
        rvos_wire::to_bytes(&SocketsRequest::Socket { sock_type }, &mut msg.data).unwrap();
    raw::sys_chan_send_blocking(h, &msg);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(h, &mut resp);
    let parsed = rvos_wire::from_bytes_with_caps::<SocketsResponse>(
        &resp.data[..resp.len],
        &resp.caps[..resp.cap_count],
    )
    .unwrap_or_else(|_| {
        eprintln!("nc: bad net response");
        process::exit(1);
    });
    raw::sys_chan_close(h);
    match parsed {
        SocketsResponse::Created { socket } => socket.raw(),
        SocketsResponse::Error { code } => {
            eprintln!("nc: socket: {:?}", code);
            process::exit(1);
        }
        _ => {
            eprintln!("nc: unexpected net response");
            process::exit(1);
        }
    }
}

/// Blocking RPC on a per-socket channel: send request, recv response.
/// Used during setup (before the relay loop) where only one request is
/// in flight at a time.
fn sock_rpc(h: usize, req: &SocketRequest<'_>) -> SocketResponse {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(req, &mut msg.data).unwrap();
    raw::sys_chan_send_blocking(h, &msg);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(h, &mut resp);
    rvos_wire::from_bytes_with_caps::<SocketResponse>(
        &resp.data[..resp.len],
        &resp.caps[..resp.cap_count],
    )
    .unwrap_or_else(|_| {
        eprintln!("nc: bad socket response");
        process::exit(1);
    })
}

fn expect_ok(h: usize, req: &SocketRequest<'_>, label: &str) {
    match sock_rpc(h, req) {
        SocketResponse::Ok {} => {}
        SocketResponse::Error { code } => {
            eprintln!("nc: {}: {:?}", label, code);
            raw::sys_chan_close(h);
            process::exit(1);
        }
        _ => {
            eprintln!("nc: {}: unexpected response", label);
            raw::sys_chan_close(h);
            process::exit(1);
        }
    }
}

// ── Stdin / stdout helpers ──────────────────────────────────────

/// Maximum bytes to request per stdin read.  Kept small enough that the
/// resulting SocketRequest::Send (3-byte header) or SendTo (10-byte header)
/// still fits in a single 1024-byte IPC message.
const READ_LEN: u32 = 1000;

fn send_stdin_read(h: usize) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &FileRequest::Read {
            offset: FileOffset::Stream {},
            len: READ_LEN,
        },
        &mut msg.data,
    )
    .unwrap();
    raw::sys_chan_send_blocking(h, &msg);
}

/// Non-blocking stdin recv.  Returns `Some(data)` when a complete read
/// has been received (empty vec = EOF / channel closed), or `None` if no
/// data is available yet.
fn try_recv_stdin(h: usize) -> Option<Vec<u8>> {
    let mut msg = Message::new();
    let ret = raw::sys_chan_recv(h, &mut msg);
    if ret == 2 {
        return Some(Vec::new()); // closed → EOF
    }
    if ret != 0 {
        return None; // no message yet
    }

    let Ok(FileResponse::Data { chunk }) =
        rvos_wire::from_bytes::<FileResponse<'_>>(&msg.data[..msg.len])
    else {
        return Some(Vec::new());
    };
    if chunk.is_empty() {
        return Some(Vec::new()); // sentinel with no data
    }

    let mut data = chunk.to_vec();

    // Drain remaining chunks until empty sentinel.  The TTY / fs server
    // sends all chunks in a burst so blocking recv completes near-instantly.
    loop {
        let mut r = Message::new();
        if raw::sys_chan_recv_blocking(h, &mut r) != 0 {
            break;
        }
        match rvos_wire::from_bytes::<FileResponse<'_>>(&r.data[..r.len]) {
            Ok(FileResponse::Data { chunk }) if !chunk.is_empty() => {
                data.extend_from_slice(chunk);
            }
            _ => break,
        }
    }

    Some(data)
}

fn write_stdout(data: &[u8]) {
    let _ = std::io::stdout().write_all(data);
    let _ = std::io::stdout().flush();
}

// ── TCP relay ───────────────────────────────────────────────────

fn relay_tcp(sock_h: usize, stdin_h: usize) {
    let mut stdin_pending = false;
    let mut recv_pending = false;
    let mut stdin_eof = false;

    loop {
        // Post new requests as needed.
        if !stdin_pending && !stdin_eof {
            send_stdin_read(stdin_h);
            stdin_pending = true;
        }
        if !recv_pending {
            let mut msg = Message::new();
            msg.len = rvos_wire::to_bytes(
                &SocketRequest::Recv { max_len: 1024 },
                &mut msg.data,
            )
            .unwrap();
            raw::sys_chan_send_blocking(sock_h, &msg);
            recv_pending = true;
        }

        // Poll and sleep until data arrives on either channel.
        if !stdin_eof {
            raw::sys_chan_poll_add(stdin_h);
        }
        raw::sys_chan_poll_add(sock_h);
        raw::sys_block();

        // ── stdin → socket ──────────────────────────────────────
        if stdin_pending {
            if let Some(data) = try_recv_stdin(stdin_h) {
                stdin_pending = false;
                if data.is_empty() {
                    // EOF – half-close the socket write direction.
                    stdin_eof = true;
                    let mut msg = Message::new();
                    msg.len = rvos_wire::to_bytes(
                        &SocketRequest::Shutdown {
                            how: ShutdownHow::Write {},
                        },
                        &mut msg.data,
                    )
                    .unwrap();
                    raw::sys_chan_send_blocking(sock_h, &msg);
                } else {
                    let mut msg = Message::new();
                    msg.len = rvos_wire::to_bytes(
                        &SocketRequest::Send { data: &data },
                        &mut msg.data,
                    )
                    .unwrap();
                    raw::sys_chan_send_blocking(sock_h, &msg);
                }
            }
        }

        // ── socket → stdout (drain all available messages) ──────
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(sock_h, &mut msg);
            if ret == 2 {
                return; // channel closed
            }
            if ret != 0 {
                break; // empty
            }
            if msg.len == 0 {
                break;
            }

            // Dispatch by wire tag byte:
            //   0, len==1 → SocketResponse::Ok  (shutdown ack)
            //   0, len >1 → SocketData::Data    (recv payload)
            //   1         → SocketResponse::Error
            //   4         → SocketResponse::Sent (send ack)
            match msg.data[0] {
                0 if msg.len == 1 => {} // Ok – shutdown ack
                0 => {
                    recv_pending = false;
                    if let Ok(SocketData::Data { data }) =
                        rvos_wire::from_bytes::<SocketData<'_>>(&msg.data[..msg.len])
                    {
                        if data.is_empty() {
                            return; // connection closed
                        }
                        write_stdout(data);
                    }
                }
                1 => return, // error
                4 => {}      // sent ack
                _ => {}
            }
        }
    }
}

// ── UDP relay ───────────────────────────────────────────────────

fn relay_udp(sock_h: usize, stdin_h: usize, peer: SocketAddr) {
    let mut stdin_pending = false;
    let mut recv_pending = false;
    let mut stdin_eof = false;

    loop {
        if !stdin_pending && !stdin_eof {
            send_stdin_read(stdin_h);
            stdin_pending = true;
        }
        if !recv_pending {
            let mut msg = Message::new();
            msg.len =
                rvos_wire::to_bytes(&SocketRequest::RecvFrom {}, &mut msg.data).unwrap();
            raw::sys_chan_send_blocking(sock_h, &msg);
            recv_pending = true;
        }

        if !stdin_eof {
            raw::sys_chan_poll_add(stdin_h);
        }
        raw::sys_chan_poll_add(sock_h);
        raw::sys_block();

        // ── stdin → socket ──────────────────────────────────────
        if stdin_pending {
            if let Some(data) = try_recv_stdin(stdin_h) {
                stdin_pending = false;
                if data.is_empty() {
                    stdin_eof = true;
                } else {
                    let mut msg = Message::new();
                    msg.len = rvos_wire::to_bytes(
                        &SocketRequest::SendTo {
                            addr: peer,
                            data: &data,
                        },
                        &mut msg.data,
                    )
                    .unwrap();
                    raw::sys_chan_send_blocking(sock_h, &msg);
                }
            }
        }

        // ── socket → stdout ─────────────────────────────────────
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(sock_h, &mut msg);
            if ret == 2 {
                return;
            }
            if ret != 0 {
                break;
            }
            if msg.len == 0 {
                break;
            }

            // Dispatch by wire tag:
            //   0, len==1  → SocketResponse::Ok
            //   1, len<=2  → SocketResponse::Error (tag + error code)
            //   1, len >2  → SocketData::Datagram  (tag + addr + data)
            //   4          → SocketResponse::Sent
            match msg.data[0] {
                0 if msg.len == 1 => {} // Ok
                1 if msg.len <= 2 => return, // Error
                1 => {
                    recv_pending = false;
                    if let Ok(SocketData::Datagram { data, .. }) =
                        rvos_wire::from_bytes::<SocketData<'_>>(&msg.data[..msg.len])
                    {
                        write_stdout(data);
                    }
                }
                4 => {} // sent ack
                _ => {}
            }
        }
    }
}

// ── Mode entry points ───────────────────────────────────────────

fn tcp_client(addr: SocketAddr, stdin_h: usize) {
    let h = create_socket(SocketType::Stream {});
    expect_ok(h, &SocketRequest::Connect { addr }, "connect");
    relay_tcp(h, stdin_h);
    raw::sys_chan_close(h);
}

fn tcp_server(port: u16, stdin_h: usize) {
    let h = create_socket(SocketType::Stream {});
    let addr = SocketAddr::Inet4 {
        a: 0,
        b: 0,
        c: 0,
        d: 0,
        port,
    };
    expect_ok(h, &SocketRequest::Bind { addr }, "bind");
    expect_ok(
        h,
        &SocketRequest::Listen { backlog: 1 },
        "listen",
    );
    eprintln!("Listening on port {}", port);

    match sock_rpc(h, &SocketRequest::Accept {}) {
        SocketResponse::Accepted { peer_addr, socket } => {
            let ch = socket.raw();
            let SocketAddr::Inet4 { a, b, c, d, port: p } = peer_addr;
            eprintln!("Connection from {}.{}.{}.{}:{}", a, b, c, d, p);
            raw::sys_chan_close(h);
            relay_tcp(ch, stdin_h);
            raw::sys_chan_close(ch);
        }
        SocketResponse::Error { code } => {
            eprintln!("nc: accept: {:?}", code);
            raw::sys_chan_close(h);
            process::exit(1);
        }
        _ => {
            eprintln!("nc: accept: unexpected response");
            raw::sys_chan_close(h);
            process::exit(1);
        }
    }
}

fn udp_client(addr: SocketAddr, stdin_h: usize) {
    let h = create_socket(SocketType::Dgram {});
    relay_udp(h, stdin_h, addr);
    raw::sys_chan_close(h);
}

fn udp_server(port: u16, stdin_h: usize) {
    let h = create_socket(SocketType::Dgram {});
    let addr = SocketAddr::Inet4 {
        a: 0,
        b: 0,
        c: 0,
        d: 0,
        port,
    };
    expect_ok(h, &SocketRequest::Bind { addr }, "bind");
    eprintln!("Listening on UDP port {}", port);

    // Blocking RecvFrom for the first datagram to learn peer address.
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&SocketRequest::RecvFrom {}, &mut msg.data).unwrap();
    raw::sys_chan_send_blocking(h, &msg);
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(h, &mut resp);

    let Ok(SocketData::Datagram { addr: peer, data }) =
        rvos_wire::from_bytes::<SocketData<'_>>(&resp.data[..resp.len])
    else {
        eprintln!("nc: recvfrom failed");
        raw::sys_chan_close(h);
        process::exit(1);
    };

    let SocketAddr::Inet4 { a, b, c, d, port: p } = peer;
    eprintln!("Datagram from {}.{}.{}.{}:{}", a, b, c, d, p);
    write_stdout(data);

    relay_udp(h, stdin_h, peer);
    raw::sys_chan_close(h);
}

// ── Exec mode (nc -e) ──────────────────────────────────────────

/// TermOutput backend: sends child's stdout data over the TCP socket.
struct NetOutput {
    sock_h: usize,
}

impl TermOutput for NetOutput {
    fn write_output(&mut self, data: &[u8]) {
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(
            &SocketRequest::Send { data },
            &mut msg.data,
        )
        .unwrap();
        raw::sys_chan_send_blocking(self.sock_h, &msg);
    }

    // No echo — the remote terminal handles that.
    fn echo_char(&mut self, _ch: u8) {}
    fn echo_backspace(&mut self) {}
    fn echo_newline(&mut self) {}
}

/// Run exec mode: spawn the command with stdio wired through a TermServer,
/// relay between the TermServer and the TCP socket.
fn exec_relay(sock_h: usize, exec_cmd: &str) {
    // Create channel pairs for child's stdin and stdout
    let (stdin_our, stdin_child) = raw::sys_chan_create();
    let (stdout_our, stdout_child) = raw::sys_chan_create();

    // Extract argv[0] from the command path
    let argv0 = match exec_cmd.rfind('/') {
        Some(pos) => &exec_cmd[pos + 1..],
        None => exec_cmd,
    };

    // Spawn the child with overridden stdio
    let proc_chan = match rvos::spawn_process_with_overrides(
        exec_cmd,
        argv0.as_bytes(),
        &[
            rvos::NsOverride::Redirect("stdin", stdin_child),
            rvos::NsOverride::Redirect("stdout", stdout_child),
        ],
    ) {
        Ok(ch) => ch.into_raw_handle(),
        Err(e) => {
            eprintln!("nc: exec {}: {:?}", exec_cmd, e);
            raw::sys_chan_close(stdin_our);
            raw::sys_chan_close(stdout_our);
            raw::sys_chan_close(stdin_child);
            raw::sys_chan_close(stdout_child);
            return;
        }
    };
    raw::sys_chan_close(stdin_child);
    raw::sys_chan_close(stdout_child);

    // Read child PID from process handle channel
    let mut msg = Message::new();
    raw::sys_chan_recv_blocking(proc_chan, &mut msg);
    let child_pid = if let Ok(started) =
        rvos_wire::from_bytes::<rvos_proto::process::ProcessStarted>(&msg.data[..msg.len])
    {
        started.pid
    } else {
        0
    };

    // Set up TermServer with the child as a client
    let mut term = TermServer::new();
    term.add_client(stdin_our, stdout_our);
    let mut net_out = NetOutput { sock_h };

    // Post initial Recv request on the socket
    let mut recv_pending = false;

    loop {
        if !recv_pending {
            let mut m = Message::new();
            m.len = rvos_wire::to_bytes(
                &SocketRequest::Recv { max_len: 1024 },
                &mut m.data,
            )
            .unwrap();
            raw::sys_chan_send_blocking(sock_h, &m);
            recv_pending = true;
        }

        // Poll all channels and block
        raw::sys_chan_poll_add(sock_h);
        term.poll_add_all();
        raw::sys_block();

        // Drain socket messages → feed into TermServer
        let mut socket_closed = false;
        loop {
            let mut m = Message::new();
            let ret = raw::sys_chan_recv(sock_h, &mut m);
            if ret == 2 {
                socket_closed = true;
                break;
            }
            if ret != 0 || m.len == 0 {
                break;
            }
            match m.data[0] {
                0 if m.len == 1 => {} // Ok (shutdown ack)
                0 => {
                    // SocketData::Data — network data arrived
                    recv_pending = false;
                    if let Ok(SocketData::Data { data }) =
                        rvos_wire::from_bytes::<SocketData<'_>>(&m.data[..m.len])
                    {
                        if data.is_empty() {
                            socket_closed = true;
                            break;
                        }
                        for &b in data {
                            term.feed_input(b, &mut net_out);
                        }
                    }
                }
                1 => {
                    socket_closed = true;
                    break;
                }
                4 => {} // Sent ack
                _ => {}
            }
        }

        if socket_closed {
            // Remote closed — kill the child and exit
            if child_pid != 0 {
                raw::sys_kill(child_pid as usize, -1);
            }
            break;
        }

        // Poll TermServer: stdin requests + stdout writes → socket
        term.poll_stdin();
        term.poll_stdout(&mut net_out);

        if !term.has_active_clients() {
            // Child exited — shut down socket write side and exit
            let mut m = Message::new();
            m.len = rvos_wire::to_bytes(
                &SocketRequest::Shutdown {
                    how: ShutdownHow::Write {},
                },
                &mut m.data,
            )
            .unwrap();
            raw::sys_chan_send_blocking(sock_h, &m);
            break;
        }
    }

    raw::sys_chan_close(proc_chan);
}

fn exec_tcp_client(addr: SocketAddr, exec_cmd: &str) {
    let h = create_socket(SocketType::Stream {});
    expect_ok(h, &SocketRequest::Connect { addr }, "connect");
    exec_relay(h, exec_cmd);
    raw::sys_chan_close(h);
}

fn exec_tcp_server(port: u16, exec_cmd: &str) {
    let h = create_socket(SocketType::Stream {});
    let addr = SocketAddr::Inet4 {
        a: 0,
        b: 0,
        c: 0,
        d: 0,
        port,
    };
    expect_ok(h, &SocketRequest::Bind { addr }, "bind");
    expect_ok(
        h,
        &SocketRequest::Listen { backlog: 1 },
        "listen",
    );
    eprintln!("Listening on port {}", port);

    match sock_rpc(h, &SocketRequest::Accept {}) {
        SocketResponse::Accepted { peer_addr, socket } => {
            let ch = socket.raw();
            let SocketAddr::Inet4 { a, b, c, d, port: p } = peer_addr;
            eprintln!("Connection from {}.{}.{}.{}:{}", a, b, c, d, p);
            raw::sys_chan_close(h);
            exec_relay(ch, exec_cmd);
            raw::sys_chan_close(ch);
        }
        SocketResponse::Error { code } => {
            eprintln!("nc: accept: {:?}", code);
            raw::sys_chan_close(h);
            process::exit(1);
        }
        _ => {
            eprintln!("nc: accept: unexpected response");
            raw::sys_chan_close(h);
            process::exit(1);
        }
    }
}

// ── main ────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut listen = false;
    let mut udp = false;
    let mut exec_cmd: Option<String> = None;
    let mut positional = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-l" => listen = true,
            "-u" => udp = true,
            "-lu" | "-ul" => {
                listen = true;
                udp = true;
            }
            "-e" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("nc: -e requires a command argument");
                    process::exit(1);
                }
                exec_cmd = Some(args[i].clone());
            }
            s if s.starts_with('-') => {
                eprintln!("nc: unknown option: {}", s);
                eprintln!("usage: nc [-l] [-u] [-e cmd] <host> <port>");
                process::exit(1);
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    if exec_cmd.is_some() && udp {
        eprintln!("nc: -e is not supported with -u (UDP)");
        process::exit(1);
    }

    if listen {
        if positional.len() != 1 {
            eprintln!("usage: nc -l [-u] [-e cmd] <port>");
            process::exit(1);
        }
        let port: u16 = positional[0].parse().unwrap_or_else(|_| {
            eprintln!("nc: invalid port: {}", positional[0]);
            process::exit(1);
        });
        if let Some(ref cmd) = exec_cmd {
            exec_tcp_server(port, cmd);
        } else if udp {
            let stdin_h = std::os::rvos::stdin_handle();
            udp_server(port, stdin_h);
        } else {
            let stdin_h = std::os::rvos::stdin_handle();
            tcp_server(port, stdin_h);
        }
    } else {
        if positional.len() != 2 {
            eprintln!("usage: nc [-u] [-e cmd] <host> <port>");
            process::exit(1);
        }
        let port: u16 = positional[1].parse().unwrap_or_else(|_| {
            eprintln!("nc: invalid port: {}", positional[1]);
            process::exit(1);
        });
        let addr = parse_addr(&positional[0], port);
        if let Some(ref cmd) = exec_cmd {
            exec_tcp_client(addr, cmd);
        } else if udp {
            let stdin_h = std::os::rvos::stdin_handle();
            udp_client(addr, stdin_h);
        } else {
            let stdin_h = std::os::rvos::stdin_handle();
            tcp_client(addr, stdin_h);
        }
    }
}
