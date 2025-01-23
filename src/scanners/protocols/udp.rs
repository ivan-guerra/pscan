//! UDP port scanning implementation.
//!
//! This module provides UDP port scanning functionality through the `UdpScanner` type,
//! which implements the `Scan` trait. UDP scanning is performed by sending empty
//! datagrams to target ports and analyzing responses.
//!
//! # Limitations
//!
//! UDP scanning is less reliable than TCP scanning because:
//! - Many UDP services don't respond to empty datagrams
//! - Responses may be rate-limited by firewalls
//! - Root/Administrator privileges may be required
//!
//! # Example
//!
//! ```no_run
//! use pscan::scanners::{PortRange, UdpScanner, Scan};
//! use std::net::IpAddr;
//!
//! let scanner = UdpScanner;
//! let addr: IpAddr = "127.0.0.1".parse().unwrap();
//! let range = PortRange::new(1, 1024);
//! let results = scanner.scan(&addr, &range, 1000);
//! ```
use crate::{
    results::{PortState, ScanResult},
    scanners::{PortRange, Scan, ScanProtocol, ScanResults},
};
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::{io, net::IpAddr};

pub struct UdpScanner;

impl Scan for UdpScanner {
    /// Performs a UDP port scan on the specified IP address within the given port range.
    ///
    /// The scan is performed using multiple threads (up to 16) to improve performance.
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
        timeout_ms: u64,
    ) -> ScanResults {
        let ports: Vec<u16> = (port_range.start..=port_range.end).collect();
        let n_threads = num_cpus::get().min(16);
        let chunk_size = ports.len().div_ceil(n_threads);
        let target = Arc::new(*addr);
        let results = Arc::new(Mutex::new(ScanResults::new()));

        let handles: Vec<_> = ports
            .chunks(chunk_size)
            .enumerate()
            .map(|(i, chunk)| {
                let addr = Arc::clone(&target);
                let results = Arc::clone(&results);
                let ports = chunk.to_vec();

                thread::Builder::new()
                    .name(format!("udp-scanner-{}", i))
                    .spawn(move || {
                        let socket = match addr.as_ref() {
                            IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0"),
                            IpAddr::V6(_) => UdpSocket::bind("[::]:0"),
                        };
                        let socket = match socket {
                            Ok(s) => {
                                if let Err(e) =
                                    s.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
                                {
                                    eprintln!("Failed to set socket read timeout: {}", e);
                                    return;
                                }
                                s
                            }
                            Err(e) => {
                                eprintln!("Failed to bind UDP socket: {}", e);
                                return;
                            }
                        };

                        for port in ports {
                            let target = format!("{}:{}", addr, port);
                            if let Some(state) = check_udp_port(&socket, &target) {
                                let mut results = results.lock().unwrap();
                                results.push(ScanResult::new(ScanProtocol::Udp, port, state));
                            }
                        }
                    })
                    .expect("Failed to spawn thread")
            })
            .collect();

        for handle in handles {
            if let Err(e) = handle.join() {
                eprintln!("Thread panicked: {:?}", e);
            }
        }

        let mut results = Arc::try_unwrap(results)
            .expect("Failed to unwrap Arc")
            .into_inner()
            .expect("Failed to acquire mutex lock");
        results.sort_by(|a, b| a.port.cmp(&b.port));

        results
    }
}

/// Checks the state of a UDP port by sending an empty datagram and analyzing the response.
fn check_udp_port(socket: &UdpSocket, addr: &str) -> Option<PortState> {
    let target_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                eprintln!("Error: No valid socket address found for {}", addr);
                return None;
            }
        },
        Err(e) => {
            eprintln!("Error resolving address {}: {}", addr, e);
            return None;
        }
    };

    if let Err(e) = socket.send_to(&[], target_addr) {
        eprintln!("Error sending UDP packet to {}: {}", addr, e);
        return None;
    }

    let mut buffer = [0u8; 512];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((_, src_addr)) => {
                // If we receive any data, consider the port Open
                if src_addr.to_string() == addr {
                    return Some(PortState::Open);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Timeout reached, port is considered Filtered
                return Some(PortState::Filtered);
            }
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset => {
                // ICMP Destination Unreachable received
                return Some(PortState::Closed);
            }
            Err(_) => return None, // Handle other unexpected errors
        }
    }
}
