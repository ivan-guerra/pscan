use clap::Parser;
use once_cell::sync::Lazy;
use scanners::{
    strategies::{TcpConnectScan, TcpHalfOpenScan, UdpScan},
    PortRange, ScanStrategy, Strategy,
};
use std::collections::HashMap;

mod results;
mod scanners;

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

    println!("{:<10} {:<10} {:<10}", "PORT", "STATE", "SERVICE");
    for result in results {
        let service = match result.protocol {
            results::ScanProtocol::Tcp => TCP_SERVICES.get(&result.port),
            results::ScanProtocol::Udp => UDP_SERVICES.get(&result.port),
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
