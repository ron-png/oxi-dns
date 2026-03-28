use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO_OWNER: &str = "ron-png";
const REPO_NAME: &str = "oxi-hole";
const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(8 * 60 * 60); // 8 hours

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub download_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Clone)]
pub struct UpdateChecker {
    inner: Arc<RwLock<UpdateCheckerInner>>,
}

struct UpdateCheckerInner {
    cached: Option<VersionInfo>,
    last_check: Option<std::time::Instant>,
}

impl UpdateChecker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(UpdateCheckerInner {
                cached: None,
                last_check: None,
            })),
        }
    }

    /// Return cached version info if still fresh, otherwise fetch from GitHub.
    pub async fn check(&self, force: bool) -> VersionInfo {
        {
            let inner = self.inner.read().await;
            if !force {
                if let (Some(ref cached), Some(last)) = (&inner.cached, inner.last_check) {
                    if last.elapsed() < CHECK_INTERVAL {
                        return cached.clone();
                    }
                }
            }
        }

        let info = match fetch_latest_release().await {
            Ok(release) => {
                let latest = release.tag_name.trim_start_matches('v').to_string();
                let update_available = version_newer(&latest, VERSION);
                let download_url = pick_download_asset(&release.assets);
                VersionInfo {
                    current_version: VERSION.to_string(),
                    latest_version: Some(latest),
                    update_available,
                    release_url: Some(release.html_url),
                    download_url,
                }
            }
            Err(e) => {
                warn!("Failed to check for updates: {}", e);
                VersionInfo {
                    current_version: VERSION.to_string(),
                    latest_version: None,
                    update_available: false,
                    release_url: None,
                    download_url: None,
                }
            }
        };

        let mut inner = self.inner.write().await;
        inner.cached = Some(info.clone());
        inner.last_check = Some(std::time::Instant::now());
        info
    }

    /// Download the new binary and replace the current one, then restart.
    pub async fn perform_update(&self) -> Result<String, String> {
        let info = self.check(false).await;
        let download_url = info
            .download_url
            .ok_or("No download URL available for this platform")?;
        let latest = info.latest_version.ok_or("Latest version unknown")?;

        info!("Downloading update v{} from {}", latest, download_url);

        let bytes = reqwest::get(&download_url)
            .await
            .map_err(|e| format!("Download failed: {}", e))?
            .error_for_status()
            .map_err(|e| format!("Download failed: {}", e))?
            .bytes()
            .await
            .map_err(|e| format!("Failed to read download: {}", e))?;

        let current_exe =
            std::env::current_exe().map_err(|e| format!("Cannot find current binary: {}", e))?;
        let backup = current_exe.with_extension("bak");

        // Backup current binary
        std::fs::copy(&current_exe, &backup)
            .map_err(|e| format!("Failed to backup current binary: {}", e))?;

        // Write new binary
        std::fs::write(&current_exe, &bytes)
            .map_err(|e| format!("Failed to write new binary: {}", e))?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&current_exe, perms)
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }

        info!(
            "Update to v{} complete. Restart the service to apply.",
            latest
        );
        Ok(format!("Updated to v{}. Restart to apply.", latest))
    }
}

async fn fetch_latest_release() -> anyhow::Result<GitHubRelease> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        REPO_OWNER, REPO_NAME
    );
    let client = reqwest::Client::new();
    let release: GitHubRelease = client
        .get(&url)
        .header("User-Agent", format!("oxi-hole/{}", VERSION))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(release)
}

/// Returns true if `latest` is semantically newer than `current`.
fn version_newer(latest: &str, current: &str) -> bool {
    let parse =
        |v: &str| -> Vec<u64> { v.split('.').filter_map(|s| s.parse::<u64>().ok()).collect() };
    let l = parse(latest);
    let c = parse(current);
    l > c
}

/// Pick the right binary asset for the current OS/arch.
fn pick_download_asset(assets: &[GitHubAsset]) -> Option<String> {
    let os = std::env::consts::OS; // "linux", "macos", "windows"
    let arch = std::env::consts::ARCH; // "x86_64", "aarch64", etc.

    // Map Rust arch names to common release naming
    let arch_patterns: Vec<&str> = match arch {
        "x86_64" => vec!["x86_64", "amd64"],
        "aarch64" => vec!["aarch64", "arm64"],
        "arm" => vec!["armv7", "armhf", "arm"],
        other => vec![other],
    };

    for asset in assets {
        let name = asset.name.to_lowercase();
        let os_match = name.contains(os);
        let arch_match = arch_patterns.iter().any(|p| name.contains(p));
        if os_match && arch_match {
            return Some(asset.browser_download_url.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_newer() {
        assert!(version_newer("0.4.0", "0.3.0"));
        assert!(version_newer("0.3.1", "0.3.0"));
        assert!(version_newer("1.0.0", "0.9.9"));
        assert!(!version_newer("0.3.0", "0.3.0"));
        assert!(!version_newer("0.2.0", "0.3.0"));
    }
}
