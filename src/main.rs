use clap::{Parser, Subcommand};
use std::time::Duration;

mod dns;
mod http;
mod lib;
mod output;
mod ping;
mod scan;
mod trace;

use output::OutputFormat;

#[derive(Parser)]
#[clap(
    name = "netprobe",
    version,
    about = "Fast network diagnostics toolkit",
    long_about = "netprobe - A comprehensive network diagnostics toolkit written in Rust.\n\
                   Combines ping, port scanning, DNS lookup, traceroute, and HTTP benchmarking\n\
                   into a single, fast binary."
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// Output format: text or json
    #[clap(long, default_value = "text", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Send ICMP echo requests to a host
    Ping {
        /// Target hostname or IP address
        host: String,

        /// Number of packets to send (0 = infinite)
        #[clap(short, long, default_value = "4")]
        count: u32,

        /// Timeout in milliseconds for each packet
        #[clap(short, long, default_value = "1000")]
        timeout: u64,

        /// Interval between packets in milliseconds
        #[clap(short, long, default_value = "1000")]
        interval: u64,

        /// Packet payload size in bytes
        #[clap(short, long, default_value = "64")]
        size: usize,
    },

    /// Scan TCP ports on a target host
    Scan {
        /// Target hostname or IP address
        host: String,

        /// Port range to scan (e.g., "1-1024" or "80,443,8080")
        #[clap(short, long, default_value = "1-1024")]
        ports: String,

        /// Connection timeout in milliseconds
        #[clap(short, long, default_value = "500")]
        timeout: u64,

        /// Number of concurrent connections
        #[clap(short = 'j', long, default_value = "200")]
        concurrency: usize,

        /// Attempt service/banner detection on open ports
        #[clap(long)]
        service_detection: bool,
    },

    /// Perform DNS lookups
    Dns {
        /// Domain name to resolve
        domain: String,

        /// Record type: A, AAAA, MX, CNAME, TXT, NS, SOA
        #[clap(short = 't', long, default_value = "A")]
        record_type: String,

        /// DNS server to query (default: system resolver)
        #[clap(short, long)]
        server: Option<String>,

        /// Query timeout in milliseconds
        #[clap(long, default_value = "5000")]
        timeout: u64,
    },

    /// Trace the route to a host
    Trace {
        /// Target hostname or IP address
        host: String,

        /// Maximum number of hops
        #[clap(short, long, default_value = "30")]
        max_hops: u8,

        /// Timeout per hop in milliseconds
        #[clap(short, long, default_value = "2000")]
        timeout: u64,

        /// Number of probes per hop
        #[clap(short = 'q', long, default_value = "3")]
        queries: u8,
    },

    /// Benchmark HTTP endpoints
    Http {
        /// Target URL
        url: String,

        /// Number of total requests
        #[clap(short = 'n', long, default_value = "100")]
        requests: u32,

        /// Number of concurrent workers
        #[clap(short, long, default_value = "10")]
        concurrency: u32,

        /// HTTP method (GET, POST, PUT, DELETE, HEAD)
        #[clap(short, long, default_value = "GET")]
        method: String,

        /// Request timeout in milliseconds
        #[clap(short, long, default_value = "30000")]
        timeout: u64,

        /// Custom headers (can be repeated: -H "Key: Value")
        #[clap(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Request body (for POST/PUT)
        #[clap(short, long)]
        body: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let format = match cli.format.as_str() {
        "json" => OutputFormat::Json,
        _ => OutputFormat::Text,
    };

    match cli.command {
        Commands::Ping {
            host,
            count,
            timeout,
            interval,
            size,
        } => {
            ping::run(
                &host,
                count,
                Duration::from_millis(timeout),
                Duration::from_millis(interval),
                size,
                format,
            )
            .await?;
        }
        Commands::Scan {
            host,
            ports,
            timeout,
            concurrency,
            service_detection,
        } => {
            scan::run(
                &host,
                &ports,
                Duration::from_millis(timeout),
                concurrency,
                service_detection,
                format,
            )
            .await?;
        }
        Commands::Dns {
            domain,
            record_type,
            server,
            timeout,
        } => {
            dns::run(
                &domain,
                &record_type,
                server.as_deref(),
                Duration::from_millis(timeout),
                format,
            )
            .await?;
        }
        Commands::Trace {
            host,
            max_hops,
            timeout,
            queries,
        } => {
            trace::run(
                &host,
                max_hops,
                Duration::from_millis(timeout),
                queries,
                format,
            )
            .await?;
        }
        Commands::Http {
            url,
            requests,
            concurrency,
            method,
            timeout,
            headers,
            body,
        } => {
            http::run(
                &url,
                requests,
                concurrency,
                &method,
                Duration::from_millis(timeout),
                &headers,
                body.as_deref(),
                format,
            )
            .await?;
        }
    }

    Ok(())
}
