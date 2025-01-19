use clap::Parser;
use strategy::{
    PingScan, PortRange, ScanStrategy, Strategy, TcpConnectScan, TcpHalfOpenScan, UdpScan,
};

mod strategy;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(help = "Target IP address")]
    addr: std::net::IpAddr,

    #[arg(
        short,
        long,
        value_enum,
        default_value_t = ScanStrategy::Ping,
        help = "Scan strategy"
    )]
    strategy: ScanStrategy,

    #[arg(short, long, default_value_t, help = "Port range to scan")]
    port_range: PortRange,
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let get_strategy = |strategy: ScanStrategy| -> Box<dyn Strategy> {
        match strategy {
            ScanStrategy::Ping => Box::new(PingScan),
            ScanStrategy::TcpHalfOpen => Box::new(TcpHalfOpenScan),
            ScanStrategy::TcpConnect => Box::new(TcpConnectScan),
            ScanStrategy::Udp => Box::new(UdpScan),
        }
    };

    let strategy = get_strategy(args.strategy);
    strategy.scan(args.addr, args.port_range);

    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
