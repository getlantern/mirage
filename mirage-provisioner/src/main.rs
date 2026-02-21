//! MIRAGE Domain Provisioner — CLI tool for domain lifecycle management.
//!
//! Manages the domain rotation pool: CDN provisioning (Cloudflare for SaaS),
//! Ed25519 manifest signing, and domain health monitoring.

mod cloudflare;
mod domain_gen;
mod manifest;
mod monitor;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mirage-provisioner",
    about = "MIRAGE domain provisioner: manage domain rotation pool"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an Ed25519 signing keypair for manifest signatures.
    Keygen {
        /// Output path for the private key (default: signing.key).
        #[arg(long, default_value = "signing.key")]
        private_key: String,
        /// Output path for the public key (default: verify.pub).
        #[arg(long, default_value = "verify.pub")]
        public_key: String,
    },

    /// Domain pool management.
    #[command(subcommand)]
    Domain(DomainCommands),

    /// Manifest generation and signing.
    #[command(subcommand)]
    Manifest(ManifestCommands),

    /// Domain health monitoring.
    #[command(subcommand)]
    Monitor(MonitorCommands),
}

#[derive(Subcommand)]
enum DomainCommands {
    /// Add a domain to the pool (register on CDN).
    Add {
        /// Hostname to add.
        hostname: String,
        /// Cloudflare zone ID.
        #[arg(long)]
        cloudflare_zone_id: String,
        /// Cloudflare API token.
        #[arg(long, env = "CF_API_TOKEN")]
        cloudflare_token: String,
        /// Domain pool config file.
        #[arg(long, default_value = "pool.toml")]
        pool: String,
    },
    /// Remove a domain from the pool (deprecate on CDN).
    Remove {
        /// Hostname to remove.
        hostname: String,
        /// Cloudflare zone ID.
        #[arg(long)]
        cloudflare_zone_id: String,
        /// Cloudflare API token.
        #[arg(long, env = "CF_API_TOKEN")]
        cloudflare_token: String,
        /// Domain pool config file.
        #[arg(long, default_value = "pool.toml")]
        pool: String,
    },
    /// List all domains in the pool with status.
    List {
        /// Domain pool config file.
        #[arg(long, default_value = "pool.toml")]
        pool: String,
    },
    /// Check NRD (Newly Registered Domain) age status.
    AgeCheck {
        /// Domain pool config file.
        #[arg(long, default_value = "pool.toml")]
        pool: String,
    },
}

#[derive(Subcommand)]
enum ManifestCommands {
    /// Generate and sign a manifest from the domain pool.
    Generate {
        /// Domain pool config file.
        #[arg(long, default_value = "pool.toml")]
        pool: String,
        /// Ed25519 signing key file.
        #[arg(long, default_value = "signing.key")]
        key: String,
        /// Output manifest file (postcard binary format).
        #[arg(short, long, default_value = "manifest.bin")]
        output: String,
    },
    /// Sign an existing manifest file.
    Sign {
        /// Manifest file to sign.
        file: String,
        /// Ed25519 signing key file.
        #[arg(long, default_value = "signing.key")]
        key: String,
    },
}

#[derive(Subcommand)]
enum MonitorCommands {
    /// Probe all domains in a manifest and report status.
    Run {
        /// Manifest file to probe.
        #[arg(long, default_value = "manifest.bin")]
        manifest: String,
        /// Timeout per probe in seconds.
        #[arg(long, default_value = "10")]
        timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen {
            private_key,
            public_key,
        } => manifest::cmd_keygen(&private_key, &public_key),

        Commands::Domain(cmd) => match cmd {
            DomainCommands::Add {
                hostname,
                cloudflare_zone_id,
                cloudflare_token,
                pool,
            } => {
                cloudflare::cmd_domain_add(
                    &hostname,
                    &cloudflare_zone_id,
                    &cloudflare_token,
                    &pool,
                )
                .await
            }
            DomainCommands::Remove {
                hostname,
                cloudflare_zone_id,
                cloudflare_token,
                pool,
            } => {
                cloudflare::cmd_domain_remove(
                    &hostname,
                    &cloudflare_zone_id,
                    &cloudflare_token,
                    &pool,
                )
                .await
            }
            DomainCommands::List { pool } => cloudflare::cmd_domain_list(&pool),
            DomainCommands::AgeCheck { pool } => cloudflare::cmd_age_check(&pool),
        },

        Commands::Manifest(cmd) => match cmd {
            ManifestCommands::Generate { pool, key, output } => {
                manifest::cmd_generate(&pool, &key, &output)
            }
            ManifestCommands::Sign { file, key } => manifest::cmd_sign(&file, &key),
        },

        Commands::Monitor(cmd) => match cmd {
            MonitorCommands::Run {
                manifest,
                timeout_secs,
            } => monitor::cmd_run(&manifest, timeout_secs).await,
        },
    }
}
