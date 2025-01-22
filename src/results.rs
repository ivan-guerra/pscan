//! Module for handling and displaying port scanning results.
//!
//! This module provides types and functions for:
//! - Representing port states (`PortState`)
//! - Storing individual scan results (`ScanResult`)
//! - Managing collections of scan results (`ScanResults`)
//! - Mapping port numbers to service names using IANA registries
//! - Formatting and displaying scan results
use crate::scanners::{Address, ScanProtocol};
use crate::utils;
use crate::Args;
use clap::ValueEnum;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fmt::Display;

/// Represents the state of a port after scanning.
#[derive(Debug, PartialEq, Clone, ValueEnum)]
pub enum PortState {
    /// Port is open and accepting connections
    Open,
    /// Port is closed and not accepting connections
    Closed,
    /// Port's state could not be determined (possibly due to firewall)
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

/// Represents the result of a single port scan operation.
#[derive(Debug)]
pub struct ScanResult {
    /// The protocol used for scanning (TCP or UDP)
    pub protocol: ScanProtocol,
    /// The port number that was scanned
    pub port: u16,
    /// The state of the port after scanning (Open, Closed, or Filtered)
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

/// A collection of scan results representing the outcome of port scanning operations.
pub type ScanResults = Vec<ScanResult>;

/// Static mapping of TCP port numbers to their corresponding IANA registered service names.
/// This mapping is lazily initialized from the embedded CSV file containing IANA TCP service definitions.
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

/// Static mapping of UDP port numbers to their corresponding IANA registered service names.
/// This mapping is lazily initialized from the embedded CSV file containing IANA UDP service definitions.
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

/// Prints the formatted results of a port scanning operation.
///
/// # Output Format
///
/// The output includes:
/// 1. A header showing the target address and port range
/// 2. Summary of ignored ports by state (if any)
/// 3. Table of discovered ports with their states and services
/// 4. Footer showing total scan duration
pub fn print_results(args: &Args, results: ScanResults, duration: std::time::Duration) {
    match args.addr {
        Address::Ip(ip) => {
            println!("pscan report for {}:{}", ip, args.port_range);
        }
        Address::Hostname(ref hostname) => match utils::resolve_hostname_to_ip(hostname) {
            Some(ip) => {
                println!("pscan report for {} ({}):{}", hostname, ip, args.port_range);
            }
            None => {
                println!(
                    "pscan report for {} (unknown):{}",
                    hostname, args.port_range
                );
            }
        },
    }

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
