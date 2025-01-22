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
use scanners::{parse_addr, Address, PortRange, Scan, ScanProtocol, TcpScanner, UdpScanner};

mod results;
mod scanners;
mod utils;

#[doc(hidden)]
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        value_parser = parse_addr, 
        help = "Target IP address or hostname"
    )]
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

#[doc(hidden)]
fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let addr = match args.addr {
        Address::Ip(ip) => ip,
        Address::Hostname(ref hostname) => utils::resolve_hostname_to_ip(hostname)
            .ok_or(format!("Could not resolve hostname {}", hostname))?,
    };

    match utils::ping_host(&addr) { 
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
