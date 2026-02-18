// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

use rvos::channel::Channel;
use rvos_proto::net::{NetRequest, NetRequestMsg, NetResponse, NetResponseMsg};

fn main() {
    println!("UDP echo server starting...");

    // Connect to "net" service via boot channel (handle 0)
    let net_ch = match rvos::service::connect_to_service("net") {
        Ok(ch) => ch,
        Err(e) => {
            println!("Failed to connect to net service: {:?}", e);
            return;
        }
    };

    let mut ch: Channel<NetRequestMsg, NetResponseMsg> =
        Channel::from_raw_handle(net_ch.into_raw_handle());

    // Bind to port 7777
    ch.send(&NetRequest::Bind { port: 7777 }).unwrap();

    // Wait for Bind response
    let resp = ch.recv_blocking();
    match resp {
        Ok(NetResponse::Ok {}) => {
            println!("UDP echo server listening on port 7777");
        }
        Ok(NetResponse::Error { message }) => {
            println!("Bind failed: {}", message);
            return;
        }
        _ => {
            println!("Unexpected bind response");
            return;
        }
    }

    // Echo loop
    loop {
        // Send RecvFrom request
        ch.send(&NetRequest::RecvFrom {}).unwrap();

        // Wait for datagram
        let resp = ch.recv_blocking();
        match resp {
            Ok(NetResponse::Datagram {
                src_ip0, src_ip1, src_ip2, src_ip3,
                src_port, data,
            }) => {
                println!(
                    "Received {} bytes from {}.{}.{}.{}:{}",
                    data.len(), src_ip0, src_ip1, src_ip2, src_ip3, src_port
                );

                // Copy data to stack buffer before sending (borrow release)
                let mut buf = [0u8; 1024];
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);

                // Echo back
                ch.send(&NetRequest::SendTo {
                    dst_ip0: src_ip0,
                    dst_ip1: src_ip1,
                    dst_ip2: src_ip2,
                    dst_ip3: src_ip3,
                    dst_port: src_port,
                    data: &buf[..len],
                }).unwrap();

                // Wait for send confirmation
                let send_resp = ch.recv_blocking();
                match send_resp {
                    Ok(NetResponse::SendOk {}) => {}
                    Ok(NetResponse::Error { message }) => {
                        println!("Send failed: {}", message);
                    }
                    _ => {}
                }
            }
            Ok(NetResponse::Error { message }) => {
                println!("RecvFrom error: {}", message);
            }
            _ => {
                println!("Unexpected response, exiting");
                return;
            }
        }
    }
}
