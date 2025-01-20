use crate::scanners::{PortRange, ScanResults, Strategy};

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
