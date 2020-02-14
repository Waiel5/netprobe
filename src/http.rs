use crate::lib::LatencyStats;
use crate::output::{self, OutputFormat};
use anyhow::Result;
use colored::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[derive(Debug, Serialize)]
struct HttpBenchResult {
    url: String,
    method: String,
    total_requests: u32,
    concurrency: u32,
    successful: u32,
    failed: u32,
    total_duration_ms: f64,
    requests_per_second: f64,
    bytes_transferred: u64,
    status_codes: HashMap<u16, u32>,
    latency: Option<LatencyStats>,
    error_messages: Vec<String>,
}

#[derive(Debug)]
struct RequestResult {
    status: Option<StatusCode>,
    latency: Duration,
    bytes: u64,
    error: Option<String>,
}

pub async fn run(
    url: &str,
    total_requests: u32,
    concurrency: u32,
    method_str: &str,
    timeout: Duration,
    headers: &[String],
    body: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let method = Method::from_str(method_str)
        .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method_str))?;

    let mut header_map = HeaderMap::new();
    for h in headers {
        let parts: Vec<&str> = h.splitn(2, ':').collect();
        if parts.len() == 2 {
            let name = HeaderName::from_str(parts[0].trim())?;
            let value = HeaderValue::from_str(parts[1].trim())?;
            header_map.insert(name, value);
        }
    }

    let client = Client::builder()
        .timeout(timeout)
        .default_headers(header_map)
        .pool_max_idle_per_host(concurrency as usize)
        .build()?;

    if format == OutputFormat::Text {
        println!(
            "{} Benchmarking {} {}",
            "HTTP".green().bold(),
            method_str.to_uppercase().yellow(),
            url.bold()
        );
        println!(
            "{} total requests, {} concurrent workers, timeout {}s",
            total_requests.to_string().yellow(),
            concurrency.to_string().yellow(),
            timeout.as_secs().to_string().cyan()
        );
        println!();
        println!("Running benchmark...");
    }

    let semaphore = Arc::new(Semaphore::new(concurrency as usize));
    let client = Arc::new(client);
    let body_data: Option<Arc<String>> = body.map(|b| Arc::new(b.to_string()));

    let bench_start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..total_requests {
        let sem = semaphore.clone();
        let client = client.clone();
        let url = url.to_string();
        let method = method.clone();
        let body_data = body_data.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            execute_request(&client, &url, method, body_data.as_deref().map(|s| s.as_str())).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await?);
    }

    let total_duration = bench_start.elapsed();

    // Compute stats
    let mut successful: u32 = 0;
    let mut failed: u32 = 0;
    let mut bytes_transferred: u64 = 0;
    let mut status_codes: HashMap<u16, u32> = HashMap::new();
    let mut latencies = Vec::new();
    let mut error_messages = Vec::new();

    for result in &results {
        if let Some(status) = result.status {
            successful += 1;
            *status_codes.entry(status.as_u16()).or_insert(0) += 1;
            latencies.push(result.latency);
            bytes_transferred += result.bytes;
        } else {
            failed += 1;
            if let Some(ref err) = result.error {
                if !error_messages.contains(err) && error_messages.len() < 10 {
                    error_messages.push(err.clone());
                }
            }
        }
    }

    let rps = total_requests as f64 / total_duration.as_secs_f64();
    let latency_stats = LatencyStats::from_durations(&latencies);

    if format == OutputFormat::Text {
        println!();
        println!("{}", "=".repeat(60));
        println!("{}", "Results".bold());
        println!("{}", "=".repeat(60));
        println!();

        println!("  Total requests:   {}", total_requests.to_string().yellow());
        println!("  Concurrency:      {}", concurrency.to_string().yellow());
        println!(
            "  Total time:       {:.2}s",
            total_duration.as_secs_f64()
        );
        println!(
            "  Requests/sec:     {}",
            format!("{:.2}", rps).green().bold()
        );
        println!(
            "  Transfer:         {}",
            format_bytes(bytes_transferred).cyan()
        );
        println!();

        println!(
            "  Successful:       {}",
            successful.to_string().green()
        );
        println!(
            "  Failed:           {}",
            if failed > 0 {
                failed.to_string().red().to_string()
            } else {
                failed.to_string().green().to_string()
            }
        );
        println!();

        // Status code distribution
        println!("  {} {}", "Status codes:".bold(), "");
        let mut codes: Vec<_> = status_codes.iter().collect();
        codes.sort_by_key(|(code, _)| *code);
        for (code, count) in codes {
            let code_color = if *code < 300 {
                code.to_string().green()
            } else if *code < 400 {
                code.to_string().yellow()
            } else {
                code.to_string().red()
            };
            println!("    [{}] {} responses", code_color, count);
        }
        println!();

        // Latency breakdown
        if let Some(ref stats) = latency_stats {
            println!("  {}", "Latency distribution:".bold());
            println!("    Min:      {:.2}ms", stats.min_ms);
            println!(
                "    Avg:      {}",
                format!("{:.2}ms", stats.avg_ms).green()
            );
            println!("    Max:      {:.2}ms", stats.max_ms);
            println!("    Stddev:   {:.2}ms", stats.stddev_ms);
            println!();
            println!("    Median:   {:.2}ms", stats.median_ms);
            println!(
                "    p95:      {}",
                format!("{:.2}ms", stats.p95_ms).yellow()
            );
            println!(
                "    p99:      {}",
                format!("{:.2}ms", stats.p99_ms).red()
            );
        }

        if !error_messages.is_empty() {
            println!();
            println!("  {}", "Errors:".red().bold());
            for msg in &error_messages {
                println!("    - {}", msg.red());
            }
        }
    } else {
        let result = HttpBenchResult {
            url: url.to_string(),
            method: method_str.to_uppercase(),
            total_requests,
            concurrency,
            successful,
            failed,
            total_duration_ms: total_duration.as_secs_f64() * 1000.0,
            requests_per_second: rps,
            bytes_transferred,
            status_codes,
            latency: latency_stats,
            error_messages,
        };
        output::print_json(&result)?;
    }

    Ok(())
}

async fn execute_request(
    client: &Client,
    url: &str,
    method: Method,
    body: Option<&str>,
) -> RequestResult {
    let start = Instant::now();

    let mut req = client.request(method, url);
    if let Some(body_data) = body {
        req = req.body(body_data.to_owned());
    }

    match req.send().await {
        Ok(response) => {
            let status = response.status();
            let bytes = response
                .bytes()
                .await
                .map(|b| b.len() as u64)
                .unwrap_or(0);
            RequestResult {
                status: Some(status),
                latency: start.elapsed(),
                bytes,
                error: None,
            }
        }
        Err(e) => RequestResult {
            status: None,
            latency: start.elapsed(),
            bytes: 0,
            error: Some(e.to_string()),
        },
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
