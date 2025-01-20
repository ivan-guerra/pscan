use crate::results::{PortState, ScanProtocol, ScanResult};
use crate::scanners::{PortRange, ScanResults, Strategy};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct TcpConnectScan;

impl Strategy for TcpConnectScan {
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
    ) -> Result<ScanResults, Box<dyn std::error::Error>> {
        let mut results =
            ScanResults::with_capacity((port_range.end - port_range.start + 1) as usize);

        for port in port_range.start..=port_range.end {
            let target = format!("{}:{}", addr, port);
            match check_tcp_connection(target) {
                Ok(state) => {
                    results.push(ScanResult::new(ScanProtocol::Tcp, port, state));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(results)
    }
}

fn check_tcp_connection<A: ToSocketAddrs>(
    addr: A,
) -> Result<PortState, Box<dyn std::error::Error>> {
    let target = addr
        .to_socket_addrs()?
        .next()
        .ok_or("Invalid socket address")?;

    let timeout = Duration::from_millis(250);
    match TcpStream::connect_timeout(&target, timeout) {
        Ok(_) => Ok(PortState::Open),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(PortState::Closed),
        Err(_) => Ok(PortState::Filtered),
    }
}
