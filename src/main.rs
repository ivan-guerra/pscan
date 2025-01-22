//! A fast, multi-threaded port scanner implementation in Rust.
//!
//! This program provides command-line functionality to scan TCP and UDP
//! ports on specified IP addresses. It features:
//!
//! - Multi-threaded scanning for improved performance
//! - Support for both TCP and UDP protocols
//! - Customizable port ranges
//! - Service name resolution using IANA registries
//! - Filterable output based on port states
use clap::Parser;
use ping_rs::PingApiOutput;
use scanners::{PortRange, Scan, ScanProtocol, TcpScanner, UdpScanner};
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

mod results;
mod scanners;

#[derive(Debug, Clone)]
enum Address {
    Ip(IpAddr),
    Hostname(String),
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Address::Ip(ip) => write!(f, "{}", ip),
            Address::Hostname(hostname) => write!(f, "{}", hostname),
        }
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = input.parse::<IpAddr>() {
            Ok(Address::Ip(ip))
        } else {
            Ok(Address::Hostname(input.to_string()))
        }
    }
}

fn parse_addr(input: &str) -> Result<Address, String> {
    input.parse::<Address>()
}

#[doc(hidden)]
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(value_parser = parse_addr, help = "Target IP address")]
    addr: Address,

    #[arg(
        short,
        long,
        value_enum,
        default_value_t = ScanProtocol::Tcp,
        help = "Scan protocol"
    )]
    scan_protocol: ScanProtocol,

    #[arg(short, long, default_value_t, help = "Port range to scan")]
    port_range: PortRange,

    #[arg(short, long, help = "Port states ignored in the scan output")]
    ignored_state: Vec<results::PortState>,
}

fn ping_host(addr: &IpAddr) -> PingApiOutput {
    let data = [0; 4];
    let timeout = Duration::from_secs(1);
    let options = ping_rs::PingOptions {
        ttl: 128,
        dont_fragment: true,
    };
    ping_rs::send_ping(addr, timeout, &data, Some(&options))
}

fn resolve_url_to_ip(hostname: &str) -> Option<IpAddr> {
    let addr = format!("{}:0", hostname);
    addr.to_socket_addrs()
        .ok() // Attempt to resolve
        .and_then(|mut iter| iter.next()) // Take the first resolved address
        .map(|socket_addr| socket_addr.ip()) // Extract the IpAddr
}

#[doc(hidden)]
fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let addr = match args.addr {
        Address::Ip(ip) => ip,
        Address::Hostname(ref hostname) => {
            resolve_url_to_ip(hostname).ok_or(format!("Could not resolve hostname {}", hostname))?
        }
    };

    let result = ping_host(&addr);
    match result {
        Ok(reply) => println!("Host is up ({}ms latency).", reply.rtt),
        Err(e) => return Err(format!("Host is unreachable, {:?}", e).into()),
    }

    let get_scanner = |protocol: &ScanProtocol| -> Box<dyn Scan> {
        match protocol {
            ScanProtocol::Tcp => Box::new(TcpScanner),
            ScanProtocol::Udp => Box::new(UdpScanner),
        }
    };
    let scanner = get_scanner(&args.scan_protocol);
    let start_time = std::time::Instant::now();
    let results = scanner.scan(&addr, &args.port_range);
    let duration = start_time.elapsed();

    results::print_results(&args, results, duration);

    Ok(())
}

#[doc(hidden)]
fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
