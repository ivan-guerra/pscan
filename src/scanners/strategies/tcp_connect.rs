use crate::scanners::{PortRange, ScanResults, Strategy};

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
