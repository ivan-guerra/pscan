use clap::ValueEnum;
use std::fmt::Display;

use crate::scanners::ScanProtocol;

#[derive(Debug, PartialEq, Clone, ValueEnum)]
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

pub type ScanResults = Vec<ScanResult>;
