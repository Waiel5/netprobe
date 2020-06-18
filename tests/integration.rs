use std::process::Command;

fn netprobe_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netprobe"))
}

#[test]
fn test_help_output() {
    let output = netprobe_bin().arg("--help").output().expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("netprobe"));
    assert!(stdout.contains("network diagnostics"));
}

#[test]
fn test_version_output() {
    let output = netprobe_bin()
        .arg("--version")
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("netprobe"));
}

#[test]
fn test_ping_help() {
    let output = netprobe_bin()
        .args(&["ping", "--help"])
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ICMP echo requests"));
    assert!(stdout.contains("--count"));
    assert!(stdout.contains("--timeout"));
}

#[test]
fn test_scan_help() {
    let output = netprobe_bin()
        .args(&["scan", "--help"])
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TCP ports"));
    assert!(stdout.contains("--ports"));
    assert!(stdout.contains("--concurrency"));
}

#[test]
fn test_dns_help() {
    let output = netprobe_bin()
        .args(&["dns", "--help"])
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DNS"));
    assert!(stdout.contains("--record-type"));
}

#[test]
fn test_trace_help() {
    let output = netprobe_bin()
        .args(&["trace", "--help"])
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("route"));
    assert!(stdout.contains("--max-hops"));
}

#[test]
fn test_http_help() {
    let output = netprobe_bin()
        .args(&["http", "--help"])
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HTTP"));
    assert!(stdout.contains("--requests"));
    assert!(stdout.contains("--concurrency"));
}

#[test]
fn test_no_subcommand_shows_help() {
    let output = netprobe_bin().output().expect("Failed to run netprobe");
    // Without a subcommand, clap should error
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SUBCOMMAND") || stderr.contains("subcommand") || stderr.contains("USAGE")
    );
}

#[test]
fn test_json_format_flag() {
    let output = netprobe_bin()
        .args(&["--format", "json", "ping", "--help"])
        .output()
        .expect("Failed to run netprobe");
    assert!(output.status.success());
}

#[test]
fn test_scan_localhost_closed_port() {
    // Scan a high port that should be closed
    let output = netprobe_bin()
        .args(&[
            "scan",
            "127.0.0.1",
            "--ports",
            "59123",
            "--timeout",
            "200",
        ])
        .output()
        .expect("Failed to run netprobe");
    // Should complete without panic
    assert!(output.status.success());
}

#[test]
fn test_scan_invalid_port_range() {
    let output = netprobe_bin()
        .args(&["scan", "127.0.0.1", "--ports", "abc"])
        .output()
        .expect("Failed to run netprobe");
    assert!(!output.status.success());
}
