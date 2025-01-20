use crate::{
    results::{PortState, ScanProtocol, ScanResult},
    scanners::{PortRange, ScanResults, Strategy},
};
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
use std::time::Duration;

pub struct UdpScan;

impl Strategy for UdpScan {
    fn scan(
        &self,
        addr: &std::net::IpAddr,
        port_range: &PortRange,
    ) -> Result<ScanResults, Box<dyn std::error::Error>> {
        let mut results =
            ScanResults::with_capacity((port_range.end - port_range.start + 1) as usize);

        for port in port_range.start..=port_range.end {
            let target = format!("{}:{}", addr, port);
            match check_udp_connection(target) {
                Ok(state) => {
                    results.push(ScanResult::new(ScanProtocol::Udp, port, state));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(results)
    }
}

pub fn check_udp_connection<A: ToSocketAddrs>(
    addr: A,
) -> Result<PortState, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(25)))?;

    let target_addr = addr.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "Could not resolve target address",
        )
    })?;

    socket.send_to(&[], target_addr)?;

    let mut buf = vec![0; 1024];
    match socket.recv_from(&mut buf) {
        Ok(_) => Ok(PortState::Open),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(PortState::Closed),
        Err(e) => Err(Box::new(e)),
    }
}
