//! Cloudflare for SaaS API integration for domain lifecycle management.

use serde::{Deserialize, Serialize};
use tracing::info;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare API client.
struct CfClient {
    client: reqwest::Client,
    token: String,
    zone_id: String,
}

#[derive(Serialize)]
struct CreateCustomHostnameRequest {
    hostname: String,
    ssl: SslSettings,
}

#[derive(Serialize)]
struct SslSettings {
    method: String,
    #[serde(rename = "type")]
    ssl_type: String,
}

#[derive(Deserialize, Debug)]
struct CfResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<CfError>,
}

#[derive(Deserialize, Debug)]
struct CfError {
    code: u64,
    message: String,
}

#[derive(Deserialize, Debug)]
struct CustomHostname {
    id: String,
    hostname: String,
    ssl: Option<SslStatus>,
}

#[derive(Deserialize, Debug)]
struct SslStatus {
    status: Option<String>,
}

#[derive(Deserialize, Debug)]
struct CfListResult {
    result: Vec<CustomHostname>,
    success: bool,
}

/// Domain pool config entry (persisted in pool.toml).
#[derive(Serialize, Deserialize, Clone)]
pub struct PoolEntry {
    pub hostname: String,
    #[serde(default)]
    pub cdn_ips: Vec<String>,
    #[serde(default = "default_path")]
    pub origin_path_prefix: String,
    pub server_public_key: String,
    pub psk: String,
    #[serde(default = "default_priority")]
    pub priority: u8,
    pub region_hint: Option<String>,
    #[serde(default)]
    pub valid_until: u64,
    /// Cloudflare custom hostname ID (for lifecycle management).
    pub cf_hostname_id: Option<String>,
    /// When the domain was registered (Unix timestamp).
    pub registered_at: Option<u64>,
    /// Whether the domain is deprecated.
    #[serde(default)]
    pub deprecated: bool,
}

fn default_path() -> String {
    "/api/v2/".to_string()
}

fn default_priority() -> u8 {
    10
}

/// Pool config file format.
#[derive(Serialize, Deserialize)]
pub struct PoolFile {
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    #[serde(default)]
    pub domains: Vec<PoolEntry>,
    #[serde(default)]
    pub deprecated: Vec<String>,
}

fn default_refresh() -> u64 {
    3600
}

impl CfClient {
    fn new(token: &str, zone_id: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            token: token.to_string(),
            zone_id: zone_id.to_string(),
        }
    }

    /// Create a custom hostname on Cloudflare for SaaS.
    async fn create_custom_hostname(
        &self,
        hostname: &str,
    ) -> anyhow::Result<CustomHostname> {
        let url = format!(
            "{}/zones/{}/custom_hostnames",
            CF_API_BASE, self.zone_id
        );

        let body = CreateCustomHostnameRequest {
            hostname: hostname.to_string(),
            ssl: SslSettings {
                method: "http".to_string(),
                ssl_type: "dv".to_string(),
            },
        };

        let resp: CfResponse<CustomHostname> = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let errs: Vec<String> = resp.errors.iter().map(|e| e.message.clone()).collect();
            return Err(anyhow::anyhow!(
                "Cloudflare API error: {}",
                errs.join(", ")
            ));
        }

        resp.result
            .ok_or_else(|| anyhow::anyhow!("no result in Cloudflare response"))
    }

    /// Delete a custom hostname by ID.
    async fn delete_custom_hostname(&self, hostname_id: &str) -> anyhow::Result<()> {
        let url = format!(
            "{}/zones/{}/custom_hostnames/{}",
            CF_API_BASE, self.zone_id, hostname_id
        );

        let resp: CfResponse<serde_json::Value> = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let errs: Vec<String> = resp.errors.iter().map(|e| e.message.clone()).collect();
            return Err(anyhow::anyhow!(
                "Cloudflare delete error: {}",
                errs.join(", ")
            ));
        }

        Ok(())
    }

    /// List all custom hostnames in the zone.
    async fn list_custom_hostnames(&self) -> anyhow::Result<Vec<CustomHostname>> {
        let url = format!(
            "{}/zones/{}/custom_hostnames",
            CF_API_BASE, self.zone_id
        );

        let resp: CfListResult = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            return Err(anyhow::anyhow!("Cloudflare list failed"));
        }

        Ok(resp.result)
    }
}

fn load_pool(path: &str) -> anyhow::Result<PoolFile> {
    if std::path::Path::new(path).exists() {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    } else {
        Ok(PoolFile {
            version: None,
            refresh_interval_secs: 3600,
            domains: Vec::new(),
            deprecated: Vec::new(),
        })
    }
}

fn save_pool(pool: &PoolFile, path: &str) -> anyhow::Result<()> {
    let text = toml::to_string_pretty(pool)?;
    std::fs::write(path, text)?;
    Ok(())
}

/// Add a domain to the pool and register it on Cloudflare.
pub async fn cmd_domain_add(
    hostname: &str,
    zone_id: &str,
    token: &str,
    pool_path: &str,
) -> anyhow::Result<()> {
    let mut pool = load_pool(pool_path)?;

    // Check if already exists.
    if pool.domains.iter().any(|d| d.hostname == hostname) {
        return Err(anyhow::anyhow!("domain {} already in pool", hostname));
    }

    let client = CfClient::new(token, zone_id);
    let result = client.create_custom_hostname(hostname).await?;

    info!(
        hostname = hostname,
        cf_id = %result.id,
        "custom hostname created on Cloudflare"
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Add to pool with placeholder keys — operator must fill in real keys.
    pool.domains.push(PoolEntry {
        hostname: hostname.to_string(),
        cdn_ips: Vec::new(),
        origin_path_prefix: "/api/v2/".to_string(),
        server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        psk: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        priority: 10,
        region_hint: None,
        valid_until: 0,
        cf_hostname_id: Some(result.id.clone()),
        registered_at: Some(now),
        deprecated: false,
    });

    save_pool(&pool, pool_path)?;

    println!("Added domain: {}", hostname);
    println!("  Cloudflare ID: {}", result.id);
    println!("  Pool file: {}", pool_path);
    println!();
    println!(
        "IMPORTANT: Update server_public_key and psk in {} before generating a manifest.",
        pool_path
    );

    Ok(())
}

/// Remove a domain from the pool and delete from Cloudflare.
pub async fn cmd_domain_remove(
    hostname: &str,
    zone_id: &str,
    token: &str,
    pool_path: &str,
) -> anyhow::Result<()> {
    let mut pool = load_pool(pool_path)?;

    let idx = pool
        .domains
        .iter()
        .position(|d| d.hostname == hostname)
        .ok_or_else(|| anyhow::anyhow!("domain {} not found in pool", hostname))?;

    let entry = &pool.domains[idx];

    // Delete from Cloudflare if we have an ID.
    if let Some(ref cf_id) = entry.cf_hostname_id {
        let client = CfClient::new(token, zone_id);
        client.delete_custom_hostname(cf_id).await?;
        info!(hostname = hostname, cf_id = %cf_id, "deleted from Cloudflare");
    }

    // Move to deprecated list.
    pool.deprecated.push(hostname.to_string());
    pool.domains.remove(idx);

    save_pool(&pool, pool_path)?;

    println!("Removed domain: {}", hostname);
    println!("  Added to deprecated list");
    println!("  Pool file: {}", pool_path);

    Ok(())
}

/// List all domains in the pool.
pub fn cmd_domain_list(pool_path: &str) -> anyhow::Result<()> {
    let pool = load_pool(pool_path)?;

    println!("Domain pool ({}):", pool_path);
    println!();

    if pool.domains.is_empty() {
        println!("  (empty)");
    }

    for (i, entry) in pool.domains.iter().enumerate() {
        println!(
            "  {}. {} (priority: {}, deprecated: {})",
            i + 1,
            entry.hostname,
            entry.priority,
            entry.deprecated
        );
        if let Some(ref region) = entry.region_hint {
            println!("     Region: {}", region);
        }
        if let Some(ref cf_id) = entry.cf_hostname_id {
            println!("     CF ID:  {}", cf_id);
        }
        if let Some(registered) = entry.registered_at {
            let age_days = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - registered)
                / 86400;
            println!("     Age:    {} days", age_days);
        }
    }

    if !pool.deprecated.is_empty() {
        println!();
        println!("  Deprecated:");
        for hostname in &pool.deprecated {
            println!("    - {}", hostname);
        }
    }

    Ok(())
}

/// Check NRD (Newly Registered Domain) age status — domains should be 60+ days old.
pub fn cmd_age_check(pool_path: &str) -> anyhow::Result<()> {
    let pool = load_pool(pool_path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let nrd_threshold_days: u64 = 60;
    let threshold_secs = nrd_threshold_days * 86400;

    println!("NRD age check (threshold: {} days):", nrd_threshold_days);
    println!();

    let mut all_clear = true;
    for entry in &pool.domains {
        if let Some(registered) = entry.registered_at {
            let age_secs = now.saturating_sub(registered);
            let age_days = age_secs / 86400;

            if age_secs < threshold_secs {
                println!(
                    "  WARNING: {} is only {} days old (need {} days)",
                    entry.hostname, age_days, nrd_threshold_days
                );
                all_clear = false;
            } else {
                println!("  OK: {} ({} days old)", entry.hostname, age_days);
            }
        } else {
            println!(
                "  UNKNOWN: {} (no registration date recorded)",
                entry.hostname
            );
            all_clear = false;
        }
    }

    if all_clear {
        println!();
        println!("All domains are past the NRD threshold.");
    }

    Ok(())
}
