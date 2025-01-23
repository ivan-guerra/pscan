//! TCP port scanning implementation.
//!
//! This module provides TCP port scanning functionality through the `TcpScanner` type,
//! which implements the `Scan` trait. It performs TCP connect scans by attempting to
//! establish full TCP connections to target ports.
//!
//! # Example
//!
//! ```no_run
//! use pscan::scanners::{PortRange, TcpScanner, Scan};
//! use std::net::IpAddr;
//!
//! let scanner = TcpScanner;
//! let addr: IpAddr = "127.0.0.1".parse().unwrap();
//! let range = PortRange::new(1, 1024);
//! let results = scanner.scan(&addr, &range, 1000);
//! ```
//!
//! # Note
//!
//! TCP connect scans are reliable but potentially slower than other scanning
//! methods due to the full connection establishment process.
use crate::results::{PortState, ScanResult};
use crate::scanners::{PortRange, Scan, ScanProtocol, ScanResults};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct TcpScanner;

impl Scan for TcpScanner {
    /// Performs a TCP port scan on the specified IP address within the given port range.
    ///
    /// The scan is performed using multiple threads (up to 16).
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
        timeout_ms: u64,
    ) -> ScanResults {
        let ports: Vec<u16> = (port_range.start..=port_range.end).collect();
        let n_threads = num_cpus::get().min(16);
        let chunk_size = ports.len().div_ceil(n_threads);
        let addr = Arc::new(*addr);
        let results = Arc::new(Mutex::new(ScanResults::new()));

        let handles: Vec<_> = ports
            .chunks(chunk_size)
            .enumerate()
            .map(|(i, chunk)| {
                let addr = Arc::clone(&addr);
                let results = Arc::clone(&results);
                let ports = chunk.to_vec();

                thread::Builder::new()
                    .name(format!("tcp-scanner-{}", i))
                    .spawn(move || {
                        for port in ports {
                            let target = format!("{}:{}", addr, port);
                            if let Some(state) = check_tcp_connection(&target, timeout_ms) {
                                let mut results = results.lock().unwrap();
                                results.push(ScanResult::new(ScanProtocol::Tcp, port, state));
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

/// Attempts to establish a TCP connection to the specified address and determines the port state.
fn check_tcp_connection<A: ToSocketAddrs>(addr: A, timeout_ms: u64) -> Option<PortState> {
    let target = addr
        .to_socket_addrs()
        .expect("Error getting socket addrs")
        .next()
        .unwrap();

    match TcpStream::connect_timeout(&target, Duration::from_millis(timeout_ms)) {
        Ok(_) => Some(PortState::Open),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(PortState::Closed),
        Err(_) => Some(PortState::Filtered),
    }
}
