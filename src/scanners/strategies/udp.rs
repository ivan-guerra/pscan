use crate::scanners::{PortRange, ScanResults, Strategy};

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
