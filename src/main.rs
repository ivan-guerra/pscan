use clap::Parser;
use scanners::{PortRange, Scan, ScanProtocol, TcpScanner, UdpScanner};

mod results;
mod scanners;

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
        help = "Scan strategy"
    )]
    strategy: ScanProtocol,

    #[arg(short, long, default_value_t, help = "Port range to scan")]
    port_range: PortRange,

    #[arg(short, long, help = "Port states ignored in the scan output")]
    ignored_state: Vec<results::PortState>,
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let get_scanner = |strategy: &ScanProtocol| -> Box<dyn Scan> {
        match strategy {
            ScanProtocol::Tcp => Box::new(TcpScanner),
            ScanProtocol::Udp => Box::new(UdpScanner),
        }
    };

    let scanner = get_scanner(&args.strategy);
    let start_time = std::time::Instant::now();
    let results = scanner.scan(&args.addr, &args.port_range)?;
    let duration = start_time.elapsed();

    results::print_results(&args, results, duration);

    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
