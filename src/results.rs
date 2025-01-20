use crate::scanners::ScanProtocol;
use crate::Args;
use clap::ValueEnum;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fmt::Display;

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

#[derive(Debug)]
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

static TCP_SERVICES: Lazy<HashMap<u16, &str>> = Lazy::new(|| {
    let tcp_services = include_str!("../services/iana_tcp_services.csv");
    let map = tcp_services
        .lines()
        .skip(1)
        .fold(HashMap::new(), |mut acc, line| {
            let mut parts = line.split(',');
            let service = parts.next().unwrap();
            let port = parts.next().unwrap().parse::<u16>().unwrap();
            acc.insert(port, service);
            acc
        });
    map
});

static UDP_SERVICES: Lazy<HashMap<u16, &str>> = Lazy::new(|| {
    let tcp_services = include_str!("../services/iana_udp_services.csv");
    let map = tcp_services
        .lines()
        .skip(1)
        .fold(HashMap::new(), |mut acc, line| {
            let mut parts = line.split(',');
            let service = parts.next().unwrap();
            let port = parts.next().unwrap().parse::<u16>().unwrap();
            acc.insert(port, service);
            acc
        });
    map
});

pub fn print_results(args: &Args, results: ScanResults, duration: std::time::Duration) {
    println!("pscan report for {}:{}", args.addr, args.port_range);

    for state in &args.ignored_state {
        let ignored_cnt = results.iter().filter(|r| r.state == *state).count();
        if ignored_cnt > 0 {
            println!("Not shown: {} {} ports", ignored_cnt, state);
        }
    }

    let results = results
        .into_iter()
        .filter(|r| !args.ignored_state.contains(&r.state))
        .collect::<Vec<_>>();

    println!("{:<10} {:<10} {:<10}", "PORT", "STATE", "SERVICE");
    for result in results {
        let service = match result.protocol {
            ScanProtocol::Tcp => TCP_SERVICES.get(&result.port),
            ScanProtocol::Udp => UDP_SERVICES.get(&result.port),
        }
        .unwrap_or(&"unknown");

        println!(
            "{:<10} {:<10} {:<10}",
            format!("{}/{}", result.port, result.protocol),
            format!("{}", result.state),
            service
        );
    }

    println!(
        "\npscan done: scanned in {:.2} seconds",
        duration.as_secs_f64()
    );
}
