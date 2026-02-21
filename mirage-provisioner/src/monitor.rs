//! Domain health monitoring — probe domains to detect blocking.

use std::time::Duration;

use tracing::info;

use crate::manifest;

/// Probe all domains in a manifest and report status.
pub async fn cmd_run(manifest_path: &str, timeout_secs: u64) -> anyhow::Result<()> {
    let m = manifest::load_manifest(std::path::Path::new(manifest_path))?;

    println!(
        "Probing {} domains (manifest v{}, timeout {}s):",
        m.domains.len(),
        m.version,
        timeout_secs
    );
    println!();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(false)
        .build()?;

    let mut alive = 0;
    let mut blocked = 0;
    let mut errors = 0;

    for entry in &m.domains {
        let url = format!("https://{}/", entry.hostname);
        let status = match client.get(&url).send().await {
            Ok(resp) => {
                alive += 1;
                format!("ALIVE (HTTP {})", resp.status().as_u16())
            }
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    blocked += 1;
                    format!("BLOCKED ({})", summarize_error(&e))
                } else {
                    errors += 1;
                    format!("ERROR ({})", summarize_error(&e))
                }
            }
        };

        println!("  {}: {}", entry.hostname, status);
        info!(hostname = %entry.hostname, status = %status, "probe result");
    }

    println!();
    println!(
        "Summary: {} alive, {} blocked, {} errors (of {} total)",
        alive,
        blocked,
        errors,
        m.domains.len()
    );

    if blocked > 0 {
        println!();
        println!(
            "WARNING: {} domain(s) appear blocked. Consider rotating them.",
            blocked
        );
    }

    Ok(())
}

fn summarize_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connection refused/reset".to_string()
    } else if e.is_request() {
        "request error".to_string()
    } else {
        format!("{}", e)
    }
}
