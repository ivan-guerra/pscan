//! Utility functions for network operations and address handling.
//!
//! This module provides helper functions for common network-related tasks such as:
//! - ICMP ping operations
//! - DNS resolution
//! - Network address handling
//!
//! # Examples
//!
//! Pinging a host:
//! ```no_run
//! use std::net::IpAddr;
//! use pscan::utils::ping_host;
//!
//! let addr: IpAddr = "1.1.1.1".parse().unwrap();
//! let result = ping_host(&addr);
//! ```
//!
//! Resolving a hostname:
//! ```no_run
//! use pscan::utils::resolve_hostname_to_ip;
//!
//! if let Some(ip) = resolve_hostname_to_ip("example.com") {
//!     println!("Resolved IP: {}", ip);
//! }
//! ```
use ping_rs::PingApiOutput;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// Sends an ICMP echo request (ping) to the specified IP address.
pub fn ping_host(addr: &IpAddr) -> PingApiOutput {
    let data = [0; 4];
    let timeout = Duration::from_secs(1);
    let options = ping_rs::PingOptions {
        ttl: 128,
        dont_fragment: true,
    };
    ping_rs::send_ping(addr, timeout, &data, Some(&options))
}

/// Resolves a hostname to its corresponding IP address.
pub fn resolve_hostname_to_ip(hostname: &str) -> Option<IpAddr> {
    let addr = format!("{}:0", hostname);
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut iter| iter.next()) // Take the first resolved address
        .map(|socket_addr| socket_addr.ip())
}
