use crate::lib::{parse_ports, resolve_host, service_name, NetprobeError};
use crate::output::{self, OutputFormat};
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Serialize)]
struct ScanResult {
    host: String,
    ip: String,
    ports_scanned: usize,
    open_ports: Vec<PortInfo>,
    closed_ports: usize,
    filtered_ports: usize,
    scan_duration_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
struct PortInfo {
    port: u16,
    state: String,
    service: Option<String>,
    banner: Option<String>,
    response_ms: f64,
}

pub async fn run(
    host: &str,
    port_spec: &str,
    connect_timeout: Duration,
    concurrency: usize,
    service_detection: bool,
    format: OutputFormat,
) -> Result<()> {
    let ip = resolve_host(host)?;
    let ports = parse_ports(port_spec)?;
    let total_ports = ports.len();

    if format == OutputFormat::Text {
        println!(
            "{} Scanning {} ({}) - {} ports with {} concurrent connections",
            "SCAN".green().bold(),
            host.bold(),
            ip.to_string().cyan(),
            total_ports.to_string().yellow(),
            concurrency.to_string().yellow()
        );
        println!();
    }

    let scan_start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for port in ports {
        let sem = semaphore.clone();
        let detect = service_detection;
        let ct = connect_timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_port(ip, port, ct, detect).await
        }));
    }

    let mut open_ports: Vec<PortInfo> = Vec::new();
    let mut closed = 0usize;
    let mut filtered = 0usize;

    for handle in handles {
        match handle.await? {
            Some(info) => match info.state.as_str() {
                "open" => open_ports.push(info),
                "filtered" => filtered += 1,
                _ => closed += 1,
            },
            None => closed += 1,
        }
    }

    open_ports.sort_by_key(|p| p.port);
    let scan_duration = scan_start.elapsed();

    if format == OutputFormat::Text {
        if open_ports.is_empty() {
            println!("{}", "No open ports found.".yellow());
        } else {
            println!(
                "{:<8} {:<12} {:<20} {}",
                "PORT".bold(),
                "STATE".bold(),
                "SERVICE".bold(),
                "BANNER".bold()
            );
            println!("{}", "-".repeat(70));

            for port_info in &open_ports {
                let service = port_info.service.as_deref().unwrap_or("unknown");
                let banner = port_info
                    .banner
                    .as_deref()
                    .map(|b| truncate_str(b, 40))
                    .unwrap_or_default();

                println!(
                    "{:<8} {:<12} {:<20} {}",
                    format!("{}/tcp", port_info.port).cyan(),
                    "open".green(),
                    service.white(),
                    banner.dimmed()
                );
            }
        }

        println!();
        println!(
            "Scan complete: {} ports scanned in {:.2}s",
            total_ports.to_string().yellow(),
            scan_duration.as_secs_f64()
        );
        println!(
            "{} open, {} closed, {} filtered",
            open_ports.len().to_string().green(),
            closed.to_string().white(),
            filtered.to_string().yellow()
        );
    } else {
        let result = ScanResult {
            host: host.to_string(),
            ip: ip.to_string(),
            ports_scanned: total_ports,
            open_ports,
            closed_ports: closed,
            filtered_ports: filtered,
            scan_duration_ms: scan_duration.as_secs_f64() * 1000.0,
        };
        output::print_json(&result)?;
    }

    Ok(())
}

async fn scan_port(ip: IpAddr, port: u16, connect_timeout: Duration, detect: bool) -> Option<PortInfo> {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();

    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let response_ms = start.elapsed().as_secs_f64() * 1000.0;
            let svc = service_name(port).map(String::from);

            let banner = if detect {
                grab_banner(stream, connect_timeout).await
            } else {
                None
            };

            Some(PortInfo {
                port,
                state: "open".to_string(),
                service: svc,
                banner,
                response_ms,
            })
        }
        Ok(Err(e)) => {
            let kind = e.kind();
            if kind == std::io::ErrorKind::ConnectionRefused {
                None // closed
            } else {
                Some(PortInfo {
                    port,
                    state: "filtered".to_string(),
                    service: None,
                    banner: None,
                    response_ms: start.elapsed().as_secs_f64() * 1000.0,
                })
            }
        }
        Err(_) => {
            // Timeout - likely filtered
            Some(PortInfo {
                port,
                state: "filtered".to_string(),
                service: None,
                banner: None,
                response_ms: connect_timeout.as_secs_f64() * 1000.0,
            })
        }
    }
}

async fn grab_banner(mut stream: TcpStream, read_timeout: Duration) -> Option<String> {
    // Some services send a banner immediately, others need a nudge
    let mut buf = vec![0u8; 1024];

    // Try reading first (many services send banner on connect)
    match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            return Some(sanitize_banner(&buf[..n]));
        }
        _ => {}
    }

    // Send a simple probe
    let probe = b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n";
    if stream.write_all(probe).await.is_ok() {
        match timeout(
            Duration::from_millis(read_timeout.as_millis() as u64),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                return Some(sanitize_banner(&buf[..n]));
            }
            _ => {}
        }
    }

    None
}

fn sanitize_banner(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    // Take first line, trim, and remove non-printable chars
    s.lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>()
        .trim()
        .to_string()
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
// connection pool optimization
