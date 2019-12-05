use crate::lib::{format_duration, resolve_host, NetprobeError};
use crate::output::{self, OutputFormat};
use anyhow::Result;
use colored::*;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{checksum, IcmpCode, IcmpTypes};
use pnet::packet::Packet;
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
struct TraceResult {
    host: String,
    ip: String,
    hops: Vec<HopInfo>,
    reached: bool,
    total_hops: u8,
}

#[derive(Debug, Serialize)]
struct HopInfo {
    hop: u8,
    ip: Option<String>,
    hostname: Option<String>,
    probes: Vec<ProbeResult>,
}

#[derive(Debug, Serialize)]
struct ProbeResult {
    rtt_ms: Option<f64>,
    timed_out: bool,
}

pub async fn run(
    host: &str,
    max_hops: u8,
    timeout: Duration,
    queries: u8,
    format: OutputFormat,
) -> Result<()> {
    let dest_ip = resolve_host(host)?;

    if format == OutputFormat::Text {
        println!(
            "{} to {} ({}), {} hops max",
            "TRACEROUTE".green().bold(),
            host.bold(),
            dest_ip.to_string().cyan(),
            max_hops.to_string().yellow()
        );
        println!();
    }

    let mut hops = Vec::new();
    let mut reached = false;

    for ttl in 1..=max_hops {
        let mut probes = Vec::new();
        let mut hop_ip: Option<IpAddr> = None;

        for _ in 0..queries {
            match send_probe(dest_ip, ttl, timeout).await {
                Ok((responder_ip, rtt)) => {
                    if hop_ip.is_none() {
                        hop_ip = Some(responder_ip);
                    }
                    probes.push(ProbeResult {
                        rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
                        timed_out: false,
                    });
                    if responder_ip == dest_ip {
                        reached = true;
                    }
                }
                Err(_) => {
                    probes.push(ProbeResult {
                        rtt_ms: None,
                        timed_out: true,
                    });
                }
            }
        }

        // Reverse DNS for the hop IP
        let hostname = if let Some(ip) = hop_ip {
            reverse_lookup(ip).await
        } else {
            None
        };

        if format == OutputFormat::Text {
            print_hop(ttl, hop_ip, hostname.as_deref(), &probes);
        }

        hops.push(HopInfo {
            hop: ttl,
            ip: hop_ip.map(|ip| ip.to_string()),
            hostname,
            probes,
        });

        if reached {
            break;
        }
    }

    if format == OutputFormat::Text {
        println!();
        if reached {
            println!(
                "Destination {} reached in {} hops",
                dest_ip.to_string().green(),
                hops.len().to_string().yellow()
            );
        } else {
            println!(
                "{}",
                "Destination not reached within hop limit.".red()
            );
        }
    } else {
        let result = TraceResult {
            host: host.to_string(),
            ip: dest_ip.to_string(),
            hops,
            reached,
            total_hops: if reached {
                0 // will be computed from hops.len()
            } else {
                max_hops
            },
        };
        output::print_json(&result)?;
    }

    Ok(())
}

fn print_hop(ttl: u8, ip: Option<IpAddr>, hostname: Option<&str>, probes: &[ProbeResult]) {
    let hop_label = format!("{:>3}", ttl);

    let addr_str = match (ip, hostname) {
        (Some(ip), Some(name)) => format!("{} ({})", name.white(), ip.to_string().cyan()),
        (Some(ip), None) => ip.to_string().cyan().to_string(),
        (None, _) => "*".dimmed().to_string(),
    };

    let probe_strs: Vec<String> = probes
        .iter()
        .map(|p| match p.rtt_ms {
            Some(ms) => {
                let color = if ms < 10.0 {
                    format!("{:.2}ms", ms).green().to_string()
                } else if ms < 100.0 {
                    format!("{:.2}ms", ms).yellow().to_string()
                } else {
                    format!("{:.2}ms", ms).red().to_string()
                };
                color
            }
            None => "*".dimmed().to_string(),
        })
        .collect();

    println!(
        "{}  {}  {}",
        hop_label.bold(),
        addr_str,
        probe_strs.join("  ")
    );
}

async fn send_probe(dest_ip: IpAddr, ttl: u8, timeout: Duration) -> Result<(IpAddr, Duration)> {
    let domain = match dest_ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::RAW, Some(Protocol::ICMPV4))
        .or_else(|_| Socket::new(domain, Type::DGRAM, Some(Protocol::ICMPV4)))
        .map_err(|e| {
            NetprobeError::PermissionDenied(format!(
                "Failed to create socket (try running with sudo): {}",
                e
            ))
        })?;

    socket
        .set_ttl(ttl as u32)
        .map_err(|e| NetprobeError::SocketError(e.to_string()))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| NetprobeError::SocketError(e.to_string()))?;

    let dest = SocketAddr::new(dest_ip, 0);
    let id = (std::process::id() & 0xFFFF) as u16;
    let seq = ttl as u16;

    // Build ICMP packet
    let mut buf = vec![0u8; 64];
    {
        let mut packet = MutableEchoRequestPacket::new(&mut buf)
            .ok_or_else(|| NetprobeError::SocketError("Failed to create ICMP packet".into()))?;
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_icmp_code(IcmpCode::new(0));
        packet.set_identifier(id);
        packet.set_sequence_number(seq);
        let cksum = checksum(&packet.to_immutable());
        packet.set_checksum(cksum);
    }

    let start = Instant::now();
    socket
        .send_to(&buf, &dest.into())
        .map_err(|e| NetprobeError::SocketError(e.to_string()))?;

    let mut recv_buf = vec![0u8; 1024];
    match socket.recv_from(&mut recv_buf) {
        Ok((_, addr)) => {
            let rtt = start.elapsed();
            let responder: IpAddr = addr.as_socket().map(|s| s.ip()).unwrap_or(dest_ip);
            Ok((responder, rtt))
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                Err(NetprobeError::Timeout(timeout).into())
            } else {
                Err(NetprobeError::SocketError(e.to_string()).into())
            }
        }
    }
}

async fn reverse_lookup(ip: IpAddr) -> Option<String> {
    use trust_dns_resolver::TokioAsyncResolver;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(1000);
    opts.attempts = 1;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts).ok()?;

    match resolver.reverse_lookup(ip).await {
        Ok(lookup) => lookup.iter().next().map(|name| {
            let s = name.to_string();
            // Remove trailing dot
            s.trim_end_matches('.').to_string()
        }),
        Err(_) => None,
    }
}
