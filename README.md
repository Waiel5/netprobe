# netprobe

[![CI](https://github.com/Waiel5/netprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Waiel5/netprobe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.65%2B-orange.svg)](https://www.rust-lang.org/)

Fast network diagnostics toolkit written in Rust. Ping, port scan, DNS lookup, traceroute, and HTTP benchmarking in a single binary.

## Why netprobe?

Instead of juggling `ping`, `nmap`, `dig`, `traceroute`, and `ab` separately, netprobe puts all common network diagnostics into one fast, portable binary with consistent output formatting and JSON export.

- **Single binary** -- no dependencies to install
- **Async I/O** -- powered by tokio for high-throughput port scanning and HTTP benchmarking
- **Structured output** -- colored terminal output or `--format json` for scripts
- **Cross-platform** -- Linux and macOS

## Installation

### From source

```bash
git clone https://github.com/Waiel5/netprobe.git
cd netprobe
cargo build --release
# Binary at ./target/release/netprobe
```

### Cargo install

```bash
cargo install --git https://github.com/Waiel5/netprobe.git
```

## Usage

### Ping

Send ICMP echo requests with detailed statistics including jitter and percentile latencies.

```bash
# Basic ping (4 packets)
netprobe ping google.com

# 10 packets with 500ms interval
netprobe ping google.com --count 10 --interval 500

# JSON output
netprobe --format json ping 8.8.8.8 --count 5
```

```
PING google.com (142.250.80.46) with 64 bytes of data

64 bytes from 142.250.80.46: icmp_seq=1 ttl=117 time=12.34ms
64 bytes from 142.250.80.46: icmp_seq=2 ttl=117 time=11.89ms
64 bytes from 142.250.80.46: icmp_seq=3 ttl=117 time=12.56ms
64 bytes from 142.250.80.46: icmp_seq=4 ttl=117 time=11.72ms

--- google.com ping statistics ---
4 packets transmitted, 4 received, 0.0% packet loss
rtt min/avg/max/stddev = 11.720/12.128/12.560/0.338 ms
jitter: 0.287ms  median: 12.115ms  p95: 12.493ms  p99: 12.547ms
```

### Port Scanner

Async TCP port scanner with optional service/banner detection.

```bash
# Scan common ports
netprobe scan target.com --ports 1-1024

# Scan specific ports with service detection
netprobe scan target.com --ports 22,80,443,3306,5432,8080 --service-detection

# Fast scan with high concurrency
netprobe scan target.com --ports 1-65535 -j 500 --timeout 200
```

```
SCAN target.com (93.184.216.34) - 6 ports with 200 concurrent connections

PORT     STATE        SERVICE              BANNER
----------------------------------------------------------------------
22/tcp   open         ssh                  SSH-2.0-OpenSSH_8.4p1
80/tcp   open         http                 HTTP/1.1 200 OK
443/tcp  open         https
3306/tcp open         mysql                5.7.38-0ubuntu0.18.04.1

Scan complete: 6 ports scanned in 0.43s
4 open, 2 closed, 0 filtered
```

### DNS Lookup

Query DNS records with support for A, AAAA, MX, CNAME, TXT, NS, and SOA record types.

```bash
# A record lookup
netprobe dns google.com

# MX records
netprobe dns google.com -t MX

# Query specific DNS server
netprobe dns example.com -t AAAA --server 8.8.8.8

# TXT records (SPF, DKIM, etc.)
netprobe dns google.com -t TXT
```

```
DNS Querying MX record for google.com via system default

NAME                                     TYPE     TTL      VALUE
--------------------------------------------------------------------------------
google.com                               MX       300      10 smtp.google.com.
google.com                               MX       300      20 smtp2.google.com.
google.com                               MX       300      30 smtp3.google.com.

Query time: 23.45ms
Server: system default
```

### Traceroute

Trace the network path to a host with per-hop timing.

```bash
# Basic traceroute
netprobe trace google.com

# Limit to 15 hops with 5 probes each
netprobe trace google.com --max-hops 15 -q 5

# Short timeout for faster results
netprobe trace google.com --timeout 1000
```

```
TRACEROUTE to google.com (142.250.80.46), 30 hops max

  1  router.local (192.168.1.1)  1.23ms  0.98ms  1.05ms
  2  isp-gw.net (10.0.0.1)  5.67ms  5.43ms  5.89ms
  3  core-rtr.isp.net (203.0.113.1)  8.12ms  7.98ms  8.34ms
  4  *  *  *
  5  google-peer.net (72.14.236.217)  11.23ms  10.87ms  11.56ms
  6  142.250.80.46 (142.250.80.46)  12.01ms  11.78ms  12.34ms

Destination 142.250.80.46 reached in 6 hops
```

### HTTP Benchmark

Load test HTTP endpoints with concurrent workers and detailed latency percentiles.

```bash
# Basic benchmark (100 requests, 10 concurrent)
netprobe http https://example.com

# Heavy load test
netprobe http https://api.example.com/health -n 10000 -c 100

# POST with custom headers and body
netprobe http https://api.example.com/data \
  -m POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -b '{"key": "value"}' \
  -n 500 -c 50
```

```
HTTP Benchmarking GET https://example.com
100 total requests, 10 concurrent workers, timeout 30s

Running benchmark...

============================================================
Results
============================================================

  Total requests:   100
  Concurrency:      10
  Total time:       2.34s
  Requests/sec:     42.74
  Transfer:         1.23 MB

  Successful:       98
  Failed:           2

  Status codes:
    [200] 98 responses

  Latency distribution:
    Min:      12.34ms
    Avg:      23.12ms
    Max:      156.78ms
    Stddev:   18.45ms

    Median:   19.87ms
    p95:      45.23ms
    p99:      134.56ms
```

## JSON Output

All commands support `--format json` for structured output, useful for scripting and pipelines:

```bash
netprobe --format json scan target.com --ports 80,443 | jq '.open_ports[].port'
netprobe --format json ping 8.8.8.8 --count 3 | jq '.stats.avg_ms'
netprobe --format json dns google.com -t MX | jq '.records[].value'
```

## Benchmarks

Informal benchmarks on a 2020 MacBook Pro (M1), scanning localhost:

| Tool | Task | Time |
|------|------|------|
| netprobe | Scan 1-1024 ports | 0.8s |
| nmap | Scan 1-1024 ports | 2.1s |
| netprobe | Scan 1-65535 ports | 12.4s |
| nmap | Scan 1-65535 ports | 38.7s |
| netprobe | HTTP bench 1000 req | 1.2s |
| ab (Apache) | HTTP bench 1000 req | 1.4s |

*Note: nmap provides much deeper analysis (OS detection, version detection, NSE scripts). netprobe is designed for quick diagnostics, not security auditing.*

## Permissions

The `ping` and `trace` subcommands require raw socket access. On Linux, you can either:

```bash
# Run with sudo
sudo netprobe ping google.com

# Or set capabilities (recommended)
sudo setcap cap_net_raw+ep ./target/release/netprobe
```

On macOS, raw sockets require root privileges for ICMP.

## Building

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release

# Run tests
cargo test

# Run with clippy lints
cargo clippy -- -D warnings
```

## License

MIT License. See [LICENSE](LICENSE) for details.
