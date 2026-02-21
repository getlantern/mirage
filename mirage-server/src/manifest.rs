//! Server-side manifest loading, verification, and delta computation.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{info, warn};

use mirage_core::config::{DomainDelta, DomainEntry, DomainManifest, DomainUpdate};
use mirage_core::manifest as manifest_crypto;

/// Shared handle to the current manifest.
pub type ManifestHandle = watch::Receiver<Option<Arc<DomainManifest>>>;

/// Load a manifest from a file, verify its signature, and return it.
pub fn load_manifest(
    path: &Path,
    verify_key: Option<&[u8; 32]>,
) -> anyhow::Result<DomainManifest> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("read manifest {}: {}", path.display(), e))?;

    let manifest: DomainManifest = postcard::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("deserialize manifest: {}", e))?;

    if let Some(key) = verify_key {
        manifest_crypto::verify_manifest(&manifest, key)
            .map_err(|e| anyhow::anyhow!("manifest signature invalid: {:?}", e))?;
        info!(version = manifest.version, "manifest signature verified");
    }

    info!(
        version = manifest.version,
        domains = manifest.domains.len(),
        "loaded domain manifest"
    );

    Ok(manifest)
}

/// Start a background task that watches the manifest file for changes
/// and updates the shared handle.
pub fn watch_manifest(
    path: std::path::PathBuf,
    verify_key: Option<[u8; 32]>,
    initial: Option<DomainManifest>,
) -> ManifestHandle {
    let (tx, rx) = watch::channel(initial.map(Arc::new));

    tokio::spawn(async move {
        let mut last_version = tx.borrow().as_ref().map(|m| m.version).unwrap_or(0);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

        loop {
            interval.tick().await;

            match load_manifest(&path, verify_key.as_ref()) {
                Ok(manifest) => {
                    if manifest.version > last_version {
                        info!(
                            old_version = last_version,
                            new_version = manifest.version,
                            "manifest updated"
                        );
                        last_version = manifest.version;
                        let _ = tx.send(Some(Arc::new(manifest)));
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to reload manifest");
                }
            }
        }
    });

    rx
}

/// Compute a delta between two manifest versions.
/// Returns `None` if no delta is possible (e.g. base version mismatch).
pub fn compute_delta(
    old: &DomainManifest,
    new: &DomainManifest,
) -> Option<DomainDelta> {
    if new.version <= old.version {
        return None;
    }

    let old_hostnames: std::collections::HashSet<&str> =
        old.domains.iter().map(|d| d.hostname.as_str()).collect();
    let new_hostnames: std::collections::HashSet<&str> =
        new.domains.iter().map(|d| d.hostname.as_str()).collect();

    let added: Vec<DomainEntry> = new
        .domains
        .iter()
        .filter(|d| !old_hostnames.contains(d.hostname.as_str()))
        .cloned()
        .collect();

    let removed: Vec<String> = old
        .domains
        .iter()
        .filter(|d| !new_hostnames.contains(d.hostname.as_str()))
        .map(|d| d.hostname.clone())
        .collect();

    Some(DomainDelta {
        base_version: old.version,
        new_version: new.version,
        added,
        removed,
        signature: [0u8; 64], // Unsigned — sign before sending if needed.
    })
}

/// Serialize a `DomainUpdate` to bytes (postcard format) for framing.
pub fn encode_domain_update(update: &DomainUpdate) -> Vec<u8> {
    postcard::to_allocvec(update).expect("DomainUpdate serialization should not fail")
}
