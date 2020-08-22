use serde::Serialize;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetprobeError {
    #[error("DNS resolution failed for host '{0}'")]
    DnsResolutionFailed(String),

    #[error("Connection timed out after {0:?}")]
    Timeout(Duration),

    #[error("Socket error: {0}")]
    SocketError(String),

    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),

    #[error("Invalid record type: {0}")]
    InvalidRecordType(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Resolve a hostname to its first IP address.
pub fn resolve_host(host: &str) -> Result<IpAddr, NetprobeError> {
    // Try parsing as an IP address first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Resolve hostname
    let addr = format!("{}:0", host);
    addr.to_socket_addrs()
        .map_err(|_| NetprobeError::DnsResolutionFailed(host.to_string()))?
        .next()
        .map(|socket_addr| socket_addr.ip())
        .ok_or_else(|| NetprobeError::DnsResolutionFailed(host.to_string()))
}

/// Parse a port range specification into a vector of ports.
///
/// Supported formats:
/// - Single port: "80"
/// - Range: "1-1024"
/// - Comma-separated: "80,443,8080"
/// - Mixed: "22,80,443,8000-8100"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, NetprobeError> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(NetprobeError::InvalidPortRange(part.to_string()));
            }
            let start: u16 = bounds[0]
                .trim()
                .parse()
                .map_err(|_| NetprobeError::InvalidPortRange(part.to_string()))?;
            let end: u16 = bounds[1]
                .trim()
                .parse()
                .map_err(|_| NetprobeError::InvalidPortRange(part.to_string()))?;
            if start > end {
                return Err(NetprobeError::InvalidPortRange(format!(
                    "start ({}) > end ({})",
                    start, end
                )));
            }
            for port in start..=end {
                ports.push(port);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| NetprobeError::InvalidPortRange(part.to_string()))?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err(NetprobeError::InvalidPortRange(spec.to_string()));
    }

    Ok(ports)
}

/// Statistics computed from a sequence of latency samples.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub stddev_ms: f64,
    pub jitter_ms: f64,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub samples: usize,
}

impl LatencyStats {
    /// Compute statistics from a vector of latency durations.
    pub fn from_durations(durations: &[Duration]) -> Option<Self> {
        if durations.is_empty() {
            return None;
        }

        let mut ms_values: Vec<f64> = durations.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        ms_values.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let n = ms_values.len();
        let min_ms = ms_values[0];
        let max_ms = ms_values[n - 1];
        let sum: f64 = ms_values.iter().sum();
        let avg_ms = sum / n as f64;

        let variance = ms_values.iter().map(|v| (v - avg_ms).powi(2)).sum::<f64>() / n as f64;
        let stddev_ms = variance.sqrt();

        // Jitter = mean of absolute differences between consecutive samples
        let jitter_ms = if n > 1 {
            let jitter_sum: f64 = ms_values
                .windows(2)
                .map(|w| (w[1] - w[0]).abs())
                .sum();
            jitter_sum / (n - 1) as f64
        } else {
            0.0
        };

        let median_ms = if n % 2 == 0 {
            (ms_values[n / 2 - 1] + ms_values[n / 2]) / 2.0
        } else {
            ms_values[n / 2]
        };

        let p95_ms = percentile(&ms_values, 95.0);
        let p99_ms = percentile(&ms_values, 99.0);

        Some(LatencyStats {
            min_ms,
            max_ms,
            avg_ms,
            stddev_ms,
            jitter_ms,
            median_ms,
            p95_ms,
            p99_ms,
            samples: n,
        })
    }
}

/// Compute the k-th percentile from a sorted slice.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (pct / 100.0) * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;
    sorted[lower] * (1.0 - frac) + sorted[upper] * frac
}

/// Format a duration as a human-readable string.
pub fn format_duration(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{:.1}us", ms * 1000.0)
    } else if ms < 1000.0 {
        format!("{:.2}ms", ms)
    } else {
        format!("{:.2}s", ms / 1000.0)
    }
}

/// Well-known port to service name mapping for common services.
pub fn service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 => Some("dhcp-server"),
        68 => Some("dhcp-client"),
        80 => Some("http"),
        110 => Some("pop3"),
        119 => Some("nntp"),
        123 => Some("ntp"),
        135 => Some("msrpc"),
        139 => Some("netbios"),
        143 => Some("imap"),
        161 => Some("snmp"),
        194 => Some("irc"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        514 => Some("syslog"),
        587 => Some("submission"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        9200 => Some("elasticsearch"),
        9300 => Some("elasticsearch-transport"),
        11211 => Some("memcached"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_port_range() {
        let ports = parse_ports("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_port_list() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_mixed_ports() {
        let ports = parse_ports("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_parse_invalid_port() {
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn test_parse_reversed_range() {
        assert!(parse_ports("100-50").is_err());
    }

    #[test]
    fn test_latency_stats() {
        let durations: Vec<Duration> = vec![10, 20, 30, 40, 50]
            .into_iter()
            .map(Duration::from_millis)
            .collect();
        let stats = LatencyStats::from_durations(&durations).unwrap();
        assert!((stats.min_ms - 10.0).abs() < 0.1);
        assert!((stats.max_ms - 50.0).abs() < 0.1);
        assert!((stats.avg_ms - 30.0).abs() < 0.1);
        assert!((stats.median_ms - 30.0).abs() < 0.1);
    }

    #[test]
    fn test_latency_stats_empty() {
        assert!(LatencyStats::from_durations(&[]).is_none());
    }

    #[test]
    fn test_format_duration() {
        assert!(format_duration(Duration::from_micros(500)).contains("us"));
        assert!(format_duration(Duration::from_millis(50)).contains("ms"));
        assert!(format_duration(Duration::from_secs(2)).contains("s"));
    }

    #[test]
    fn test_service_name() {
        assert_eq!(service_name(80), Some("http"));
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(12345), None);
    }

    #[test]
    fn test_resolve_ip_address() {
        let ip = resolve_host("127.0.0.1").unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }
}
// refactored error types
