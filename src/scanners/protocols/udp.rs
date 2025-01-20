use crate::{
    results::{PortState, ScanResult},
    scanners::{PortRange, Scan, ScanProtocol, ScanResults},
};
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct UdpScanner;

impl Scan for UdpScanner {
    /// Performs a UDP port scan on the specified IP address within the given port range.
    ///
    /// The scan is performed using multiple threads (up to 16) to improve performance.
    fn scan(&self, addr: &std::net::IpAddr, port_range: &PortRange) -> ScanResults {
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
                        let socket = match UdpSocket::bind("0.0.0.0:0") {
                            Ok(s) => {
                                if let Err(e) = s.set_read_timeout(Some(Duration::from_millis(25)))
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

        Arc::try_unwrap(results)
            .expect("Failed to unwrap Arc")
            .into_inner()
            .expect("Failed to acquire mutex lock")
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

    let mut buf = [0; 1024];
    match socket.recv_from(&mut buf) {
        Ok(_) => Some(PortState::Open),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Some(PortState::Closed),
        Err(e) => {
            eprintln!("Error receiving UDP response from {}: {}", addr, e);
            None
        }
    }
}
