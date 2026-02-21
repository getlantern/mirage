//! MIRAGE Server — authenticated HTTP/2 relay with cover site.

mod config;
mod connection;
mod cover;
mod manifest;
mod relay;
mod server;

use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Parser)]
#[command(name = "mirage-server", about = "MIRAGE protocol server")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "mirage-server.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_text = std::fs::read_to_string(&cli.config)
        .map_err(|e| anyhow::anyhow!("read config {}: {}", cli.config, e))?;

    let config_file: config::ServerConfigFile = toml::from_str(&config_text)
        .map_err(|e| anyhow::anyhow!("parse config: {}", e))?;

    let config = config::ServerConfig::from_file(config_file)
        .map_err(|e| anyhow::anyhow!("validate config: {}", e))?;

    // Initialize tracing.
    let filter = tracing_subscriber::EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "mirage-server starting");

    // Load domain manifest if configured.
    let manifest_handle = if let Some(ref path) = config.manifest_path {
        let initial = manifest::load_manifest(path, config.manifest_verify_key.as_ref())
            .map_err(|e| anyhow::anyhow!("load manifest: {}", e))?;
        info!(
            version = initial.version,
            domains = initial.domains.len(),
            "domain manifest loaded"
        );
        Some(manifest::watch_manifest(
            path.clone(),
            config.manifest_verify_key,
            Some(initial),
        ))
    } else {
        None
    };

    let config = Arc::new(config);
    let cancel = CancellationToken::new();

    // Handle SIGTERM / SIGINT for graceful shutdown.
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("register SIGTERM");
        let sigint = tokio::signal::ctrl_c();

        tokio::select! {
            _ = sigterm.recv() => {
                info!("received SIGTERM");
            }
            _ = sigint => {
                info!("received SIGINT");
            }
        }

        cancel_clone.cancel();
    });

    server::run(config, manifest_handle, cancel).await
}
