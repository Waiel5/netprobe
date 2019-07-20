use crate::lib::{resolve_host, LatencyStats, NetprobeError};
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
struct PingResult {
    host: String,
    ip: String,
    packets_sent: u32,
    packets_received: u32,
    packet_loss_pct: f64,
    stats: Option<LatencyStats>,
    replies: Vec<PingReply>,
}

#[derive(Debug, Serialize)]
struct PingReply {
    seq: u16,
    ttl: u8,
    time_ms: f64,
    size: usize,
}

pub async fn run(
    host: &str,
    count: u32,
    timeout: Duration,
    interval: Duration,
    size: usize,
    format: OutputFormat,
) -> Result<()> {
    let ip = resolve_host(host)?;

    if format == OutputFormat::Text {
        println!(
            "{} {} ({}) with {} bytes of data",
            "PING".green().bold(),
            host.bold(),
            ip.to_string().cyan(),
            size.to_string().yellow()
        );
        println!();
    }

    let mut replies = Vec::new();
    let mut durations = Vec::new();
    let mut packets_sent: u32 = 0;
    let mut packets_received: u32 = 0;
    let seq_limit = if count == 0 { u32::MAX } else { count };

    for seq in 0..seq_limit {
        packets_sent += 1;

        match send_ping(ip, seq as u16, timeout, size).await {
            Ok((ttl, rtt)) => {
                packets_received += 1;
                let time_ms = rtt.as_secs_f64() * 1000.0;
                durations.push(rtt);

                if format == OutputFormat::Text {
                    println!(
                        "{} bytes from {}: icmp_seq={} ttl={} time={:.2}ms",
                        size.to_string().white(),
                        ip.to_string().cyan(),
                        (seq + 1).to_string().yellow(),
                        ttl.to_string().green(),
                        time_ms
                    );
                }

                replies.push(PingReply {
                    seq: seq as u16 + 1,
                    ttl,
                    time_ms,
                    size,
                });
            }
            Err(e) => {
                if format == OutputFormat::Text {
                    let msg = match e.downcast_ref::<NetprobeError>() {
                        Some(NetprobeError::Timeout(_)) => {
                            format!("Request timeout for icmp_seq {}", seq + 1)
                        }
                        _ => format!("Error: {}", e),
                    };
                    println!("{}", msg.red());
                }
            }
        }

        if seq + 1 < seq_limit {
            tokio::time::sleep(interval).await;
        }
    }

    let loss_pct = if packets_sent > 0 {
        ((packets_sent - packets_received) as f64 / packets_sent as f64) * 100.0
    } else {
        0.0
    };

    let stats = LatencyStats::from_durations(&durations);

    if format == OutputFormat::Text {
        println!();
        println!("--- {} ping statistics ---", host.bold());
        println!(
            "{} packets transmitted, {} received, {:.1}% packet loss",
            packets_sent.to_string().yellow(),
            packets_received.to_string().green(),
            loss_pct
        );

        if let Some(ref stats) = stats {
            println!(
                "rtt min/avg/max/stddev = {:.3}/{:.3}/{:.3}/{:.3} ms",
                stats.min_ms, stats.avg_ms, stats.max_ms, stats.stddev_ms
            );
            println!(
                "jitter: {:.3}ms  median: {:.3}ms  p95: {:.3}ms  p99: {:.3}ms",
                stats.jitter_ms, stats.median_ms, stats.p95_ms, stats.p99_ms
            );
        }
    } else {
        let result = PingResult {
            host: host.to_string(),
            ip: ip.to_string(),
            packets_sent,
            packets_received,
            packet_loss_pct: loss_pct,
            stats,
            replies,
        };
        output::print_json(&result)?;
    }

    Ok(())
}

async fn send_ping(ip: IpAddr, seq: u16, timeout: Duration, _size: usize) -> Result<(u8, Duration)> {
    let domain = match ip {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::RAW, Some(Protocol::ICMPV4))
        .or_else(|_| Socket::new(domain, Type::DGRAM, Some(Protocol::ICMPV4)))
        .map_err(|e| {
            NetprobeError::PermissionDenied(format!(
                "Failed to create raw socket (try running with sudo): {}",
                e
            ))
        })?;

    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| NetprobeError::SocketError(e.to_string()))?;

    let dest = SocketAddr::new(ip, 0);

    // Build ICMP echo request packet
    let mut buf = vec![0u8; 64];
    {
        let mut packet = MutableEchoRequestPacket::new(&mut buf)
            .ok_or_else(|| NetprobeError::SocketError("Failed to create ICMP packet".into()))?;
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_icmp_code(IcmpCode::new(0));
        packet.set_identifier(std::process::id() as u16);
        packet.set_sequence_number(seq);
        let cksum = checksum(&packet.to_immutable());
        packet.set_checksum(cksum);
    }

    let start = Instant::now();
    socket
        .send_to(&buf, &dest.into())
        .map_err(|e| NetprobeError::SocketError(e.to_string()))?;

    let mut recv_buf = vec![0u8; 1024];
    match socket.recv(&mut recv_buf) {
        Ok(_) => {
            let rtt = start.elapsed();
            // Extract TTL from IP header (byte 8 in IPv4)
            let ttl = if recv_buf.len() > 8 { recv_buf[8] } else { 0 };
            Ok((ttl, rtt))
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut
            {
                Err(NetprobeError::Timeout(timeout).into())
            } else {
                Err(NetprobeError::SocketError(e.to_string()).into())
            }
        }
    }
}
