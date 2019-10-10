use crate::lib::NetprobeError;
use crate::output::{self, OutputFormat};
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use trust_dns_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, Serialize)]
struct DnsResult {
    domain: String,
    record_type: String,
    server: String,
    query_time_ms: f64,
    records: Vec<DnsRecord>,
}

#[derive(Debug, Serialize)]
struct DnsRecord {
    name: String,
    record_type: String,
    ttl: u32,
    value: String,
}

pub async fn run(
    domain: &str,
    record_type_str: &str,
    server: Option<&str>,
    timeout: Duration,
    format: OutputFormat,
) -> Result<()> {
    let record_type = parse_record_type(record_type_str)?;

    // Build resolver configuration
    let (resolver_config, server_name) = if let Some(srv) = server {
        let ip = IpAddr::from_str(srv)
            .map_err(|_| NetprobeError::ParseError(format!("Invalid DNS server: {}", srv)))?;
        let ns = NameServerConfig {
            socket_addr: SocketAddr::new(ip, 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            bind_addr: None,
        };
        let mut config = ResolverConfig::new();
        config.add_name_server(ns);
        (config, srv.to_string())
    } else {
        (
            ResolverConfig::default(),
            "system default".to_string(),
        )
    };

    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 3;
    opts.use_hosts_file = false;

    let resolver = TokioAsyncResolver::tokio(resolver_config, opts)?;

    if format == OutputFormat::Text {
        println!(
            "{} Querying {} record for {} via {}",
            "DNS".green().bold(),
            record_type_str.to_uppercase().yellow(),
            domain.bold(),
            server_name.cyan()
        );
        println!();
    }

    let start = Instant::now();
    let records = perform_lookup(&resolver, domain, record_type, record_type_str).await?;
    let query_time = start.elapsed();

    if format == OutputFormat::Text {
        if records.is_empty() {
            println!("{}", "No records found.".yellow());
        } else {
            println!(
                "{:<40} {:<8} {:<8} {}",
                "NAME".bold(),
                "TYPE".bold(),
                "TTL".bold(),
                "VALUE".bold()
            );
            println!("{}", "-".repeat(80));

            for record in &records {
                println!(
                    "{:<40} {:<8} {:<8} {}",
                    record.name.white(),
                    record.record_type.cyan(),
                    record.ttl.to_string().dimmed(),
                    record.value.green()
                );
            }
        }

        println!();
        println!(
            "Query time: {}",
            format!("{:.2}ms", query_time.as_secs_f64() * 1000.0).yellow()
        );
        println!("Server: {}", server_name.cyan());
    } else {
        let result = DnsResult {
            domain: domain.to_string(),
            record_type: record_type_str.to_uppercase(),
            server: server_name,
            query_time_ms: query_time.as_secs_f64() * 1000.0,
            records,
        };
        output::print_json(&result)?;
    }

    Ok(())
}

fn parse_record_type(s: &str) -> Result<RecordType, NetprobeError> {
    match s.to_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "MX" => Ok(RecordType::MX),
        "CNAME" => Ok(RecordType::CNAME),
        "TXT" => Ok(RecordType::TXT),
        "NS" => Ok(RecordType::NS),
        "SOA" => Ok(RecordType::SOA),
        "PTR" => Ok(RecordType::PTR),
        "SRV" => Ok(RecordType::SRV),
        _ => Err(NetprobeError::InvalidRecordType(s.to_string())),
    }
}

async fn perform_lookup(
    resolver: &TokioAsyncResolver,
    domain: &str,
    record_type: RecordType,
    type_str: &str,
) -> Result<Vec<DnsRecord>> {
    let mut records = Vec::new();
    let name = trust_dns_resolver::Name::from_str(domain)
        .map_err(|e| NetprobeError::ParseError(format!("Invalid domain name: {}", e)))?;

    match record_type {
        RecordType::A => {
            let lookup = resolver.ipv4_lookup(domain).await?;
            for addr in lookup.iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: "A".to_string(),
                    ttl: lookup.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0),
                    value: addr.to_string(),
                });
            }
        }
        RecordType::AAAA => {
            let lookup = resolver.ipv6_lookup(domain).await?;
            for addr in lookup.iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: "AAAA".to_string(),
                    ttl: lookup.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0),
                    value: addr.to_string(),
                });
            }
        }
        RecordType::MX => {
            let lookup = resolver.mx_lookup(domain).await?;
            for mx in lookup.iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: "MX".to_string(),
                    ttl: lookup.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0),
                    value: format!("{} {}", mx.preference(), mx.exchange()),
                });
            }
        }
        RecordType::TXT => {
            let lookup = resolver.txt_lookup(domain).await?;
            for txt in lookup.iter() {
                let txt_data: Vec<String> = txt.iter().map(|d| {
                    String::from_utf8_lossy(d).to_string()
                }).collect();
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: "TXT".to_string(),
                    ttl: lookup.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0),
                    value: txt_data.join(""),
                });
            }
        }
        RecordType::NS => {
            let lookup = resolver.ns_lookup(domain).await?;
            for ns in lookup.iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: "NS".to_string(),
                    ttl: lookup.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0),
                    value: ns.to_string(),
                });
            }
        }
        RecordType::SOA => {
            let lookup = resolver.soa_lookup(domain).await?;
            for soa in lookup.iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: "SOA".to_string(),
                    ttl: lookup.as_lookup().record_iter().next().map(|r| r.ttl()).unwrap_or(0),
                    value: format!(
                        "{} {} {} {} {} {} {}",
                        soa.mname(),
                        soa.rname(),
                        soa.serial(),
                        soa.refresh(),
                        soa.retry(),
                        soa.expire(),
                        soa.minimum()
                    ),
                });
            }
        }
        _ => {
            let lookup = resolver.lookup(name, record_type).await?;
            for record in lookup.record_iter() {
                records.push(DnsRecord {
                    name: domain.to_string(),
                    record_type: type_str.to_uppercase(),
                    ttl: record.ttl(),
                    value: format!("{:?}", record.data()),
                });
            }
        }
    }

    Ok(records)
}
