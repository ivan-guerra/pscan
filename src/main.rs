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
use std::net::IpAddr;
use std::time::Duration;

mod results;
mod scanners;

#[doc(hidden)]
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(help = "Target IP address")]
    addr: std::net::IpAddr,

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

#[doc(hidden)]
fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let result = ping_host(&args.addr);
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
    let results = scanner.scan(&args.addr, &args.port_range);
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
