use clap::Parser;
use strategy::{PortRange, ScanStrategy, Strategy, TcpConnectScan, TcpHalfOpenScan, UdpScan};

mod results;
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
        default_value_t = ScanStrategy::TcpHalfOpen,
        help = "Scan strategy"
    )]
    strategy: ScanStrategy,

    #[arg(short, long, default_value_t, help = "Port range to scan")]
    port_range: PortRange,
}

fn print_results(
    ip: std::net::IpAddr,
    ports: PortRange,
    results: results::ScanResults,
    duration: std::time::Duration,
) {
    println!("pscan report for {}:{}", ip, ports);

    let num_filtered = results
        .iter()
        .filter(|r| r.state == results::PortState::Filtered)
        .count();
    println!("Not shown: {} filtered ports", num_filtered);

    println!("{:8} {:10}", "PORT", "STATE");
    for result in results {
        println!("{}", result);
    }

    println!(
        "\npscan done: scanned in {:.2} seconds",
        duration.as_secs_f64()
    );
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let get_strategy = |strategy: ScanStrategy| -> Box<dyn Strategy> {
        match strategy {
            ScanStrategy::TcpHalfOpen => Box::new(TcpHalfOpenScan),
            ScanStrategy::TcpConnect => Box::new(TcpConnectScan),
            ScanStrategy::Udp => Box::new(UdpScan),
        }
    };

    let strategy = get_strategy(args.strategy);
    let start_time = std::time::Instant::now();
    let result = strategy.scan(&args.addr, &args.port_range)?;
    let duration = start_time.elapsed();

    print_results(args.addr, args.port_range, result, duration);

    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
