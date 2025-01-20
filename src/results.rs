use std::fmt::Display;

pub enum ScanProtocol {
    Tcp,
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

#[derive(PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        };

        write!(f, "{}", state)
    }
}

pub struct ScanResult {
    pub protocol: ScanProtocol,
    pub port: u16,
    pub state: PortState,
}

impl ScanResult {
    pub fn new(protocol: ScanProtocol, port: u16, state: PortState) -> Self {
        ScanResult {
            protocol,
            port,
            state,
        }
    }
}

impl Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:12} {:12}",
            format!("{}/{}", self.port, self.protocol),
            self.state
        )
    }
}

pub type ScanResults = Vec<ScanResult>;
