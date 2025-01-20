use crate::results::ScanResults;
use clap::ValueEnum;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
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

#[derive(Debug, Clone, ValueEnum)]
pub enum ScanStrategy {
    TcpHalfOpen,
    TcpConnect,
    Udp,
}

pub trait Strategy {
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
    ) -> Result<ScanResults, Box<dyn std::error::Error>>;
}

pub struct TcpHalfOpenScan;

impl Strategy for TcpHalfOpenScan {
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
    ) -> Result<ScanResults, Box<dyn std::error::Error>> {
        println!("TCP half-open scan on {} on ports {}", addr, port_range);
        Ok(ScanResults::default())
    }
}

pub struct TcpConnectScan;

impl Strategy for TcpConnectScan {
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
    ) -> Result<ScanResults, Box<dyn std::error::Error>> {
        println!("TCP connect scan on {} on ports {}", addr, port_range);
        Ok(ScanResults::default())
    }
}

pub struct UdpScan;

impl Strategy for UdpScan {
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
    ) -> Result<ScanResults, Box<dyn std::error::Error>> {
        println!("UDP scan on {} on ports {}", addr, port_range);
        Ok(ScanResults::default())
    }
}
