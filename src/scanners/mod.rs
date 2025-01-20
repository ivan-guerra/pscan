//! Core scanning functionality and types for port scanning operations.
//!
//! This module provides:
//! - Port range definitions and parsing (`PortRange`)
//! - Protocol specifications (`ScanProtocol`)
//! - Core scanning trait (`Scan`)
//! - Protocol-specific scanner implementations (TCP and UDP)
//!
//! The module is organized with protocol-specific implementations in
//! the `protocols` submodule, while keeping common types and traits
//! in the root module scope.
//!
//! # Example
//! ```no_run
//! use pscan::scanners::{PortRange, TcpScanner, Scan};
//!
//! let scanner = TcpScanner::new();
//! let range = PortRange { start: 1, end: 1024 };
//! let addr = "127.0.0.1".parse().unwrap();
//! let results = scanner.scan(&addr, &range);
//! ```
use crate::results::ScanResults;
use clap::ValueEnum;
use std::fmt::Display;
use std::str::FromStr;

pub mod protocols;
pub use protocols::TcpScanner;
pub use protocols::UdpScanner;

/// Represents a range of ports to be scanned.
#[derive(Debug, Clone)]
pub struct PortRange {
    /// The first port number in the range (inclusive)
    pub start: u16,
    /// The last port number in the range (inclusive)
    pub end: u16,
}

impl Default for PortRange {
    fn default() -> Self {
        PortRange {
            start: 1,
            end: 65535,
        }
    }
}

impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("Invalid port range".to_string());
        }

        let start = parts[0].parse().map_err(|_| "Invalid start port number")?;
        let end = parts[1].parse().map_err(|_| "Invalid end port number")?;
        if start > end {
            return Err("Start port must be less than or equal to end port".to_string());
        }

        Ok(PortRange { start, end })
    }
}

/// Specifies the protocol to be used for port scanning.
#[derive(Debug, Clone, ValueEnum)]
pub enum ScanProtocol {
    /// TCP (Transmission Control Protocol) scanning mode
    Tcp,
    /// UDP (User Datagram Protocol) scanning mode
    Udp,
}

impl Display for ScanProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let protocol = match self {
            ScanProtocol::Tcp => "tcp",
            ScanProtocol::Udp => "udp",
        };

        write!(f, "{}", protocol)
    }
}

/// A trait defining the interface for port scanning implementations.
///
/// This trait must be implemented by any scanner that performs port scanning operations,
/// regardless of the protocol or method used.
pub trait Scan {
    fn scan(&self, addr: &std::net::IpAddr, port_range: &PortRange) -> ScanResults;
}
