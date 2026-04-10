pub mod providers;

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{AcmeConfig, Config, TlsConfig};

// ── Public constants ─────────────────────────────────────────────────────────

pub const CERT_PATH: &str = "/etc/oxi-dns/cert.pem";
pub const KEY_PATH: &str = "/etc/oxi-dns/key.pem";

// ── IssuanceState ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    Idle,
    CreatingAccount,
    PlacingOrder,
    WaitingForChallenge,
    Validating,
    Downloading,
    Installing,
    Complete,
    Failed,
}

// ── IssuanceProgress ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuanceProgress {
    pub state: IssuanceState,
    pub message: String,
    pub challenge_record_name: Option<String>,
    pub challenge_record_value: Option<String>,
}

impl Default for IssuanceProgress {
    fn default() -> Self {
        Self {
            state: IssuanceState::Idle,
            message: String::new(),
            challenge_record_name: None,
            challenge_record_value: None,
        }
    }
}

// ── AcmeState ────────────────────────────────────────────────────────────────

pub struct AcmeState {
    pub progress: Arc<RwLock<IssuanceProgress>>,
    pub manual_confirm: Arc<tokio::sync::Notify>,
}

impl AcmeState {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(RwLock::new(IssuanceProgress::default())),
            manual_confirm: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

// ── Helper: set progress ─────────────────────────────────────────────────────

async fn set_progress(
    progress: &Arc<RwLock<IssuanceProgress>>,
    state: IssuanceState,
    message: impl Into<String>,
) {
    let mut p = progress.write().await;
    p.state = state;
    p.message = message.into();
    p.challenge_record_name = None;
    p.challenge_record_value = None;
}

async fn set_progress_challenge(
    progress: &Arc<RwLock<IssuanceProgress>>,
    message: impl Into<String>,
    record_name: String,
    record_value: String,
) {
    let mut p = progress.write().await;
    p.state = IssuanceState::WaitingForChallenge;
    p.message = message.into();
    p.challenge_record_name = Some(record_name);
    p.challenge_record_value = Some(record_value);
}

// ── issue_certificate ────────────────────────────────────────────────────────

pub async fn issue_certificate(
    acme_config: &AcmeConfig,
    progress: Arc<RwLock<IssuanceProgress>>,
    manual_confirm: Arc<tokio::sync::Notify>,
) -> Result<()> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
        RetryPolicy,
    };

    let domain = acme_config.domain.clone();
    let email = acme_config.email.clone();

    // ── Step 1: Create ACME account ──────────────────────────────────────────
    set_progress(&progress, IssuanceState::CreatingAccount, "Creating ACME account…").await;

    let directory_url = if acme_config.use_staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned()
    } else {
        "https://acme-v02.api.letsencrypt.org/directory".to_owned()
    };

    let contact = format!("mailto:{}", email);
    let (account, _credentials) = Account::builder()
        .context("Failed to create ACME account builder")?
        .create(
            &NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .context("Failed to create ACME account")?;

    info!("ACME account created for {}", email);

    // ── Step 2: Place order ──────────────────────────────────────────────────
    set_progress(&progress, IssuanceState::PlacingOrder, "Placing certificate order…").await;

    let identifier = Identifier::Dns(domain.clone());
    let mut order = account
        .new_order(&NewOrder::new(&[identifier]))
        .await
        .context("Failed to place ACME order")?;

    info!("ACME order placed for domain {}", domain);

    // ── Step 3: Get DNS-01 challenge ─────────────────────────────────────────
    set_progress(
        &progress,
        IssuanceState::WaitingForChallenge,
        "Fetching DNS-01 challenge…",
    )
    .await;

    let mut authorizations = order.authorizations();
    let mut authz_handle = authorizations
        .next()
        .await
        .context("No ACME authorizations returned")?
        .context("Failed to fetch ACME authorization")?;

    let mut cf_record_id: Option<String> = None;

    if authz_handle.status != AuthorizationStatus::Valid {
        let mut challenge_handle = authz_handle
            .challenge(ChallengeType::Dns01)
            .context("No DNS-01 challenge found in authorization")?;

        let key_auth = challenge_handle.key_authorization();
        let dns_value = key_auth.dns_value();
        let record_name = format!("_acme-challenge.{}", domain);

        info!("DNS-01 challenge: {} = {}", record_name, dns_value);

        // ── Step 4/5: Provider-specific challenge fulfillment ────────────────
        if acme_config.provider == "cloudflare" {
            let cf = providers::CloudflareProvider::new(&acme_config.cloudflare_api_token);

            set_progress(
                &progress,
                IssuanceState::WaitingForChallenge,
                "Creating Cloudflare TXT record…",
            )
            .await;

            let record_id = cf
                .create_txt_record(&domain, &dns_value)
                .await
                .context("Failed to create Cloudflare TXT record")?;

            cf_record_id = Some(record_id);

            info!("Polling for DNS propagation of {}", record_name);

            // Poll for propagation (up to 40 tries, 5s apart = 200s max)
            let mut propagated = false;
            for attempt in 1..=40u32 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                if providers::poll_dns_txt_record(&domain, &dns_value).await {
                    info!("DNS TXT record propagated after {} attempts", attempt);
                    propagated = true;
                    break;
                }

                set_progress(
                    &progress,
                    IssuanceState::WaitingForChallenge,
                    format!("Waiting for DNS propagation… (attempt {}/40)", attempt),
                )
                .await;
            }

            if !propagated {
                warn!(
                    "DNS TXT record may not have fully propagated after 200s, proceeding anyway"
                );
            }
        } else {
            // Manual provider
            set_progress_challenge(
                &progress,
                "Add the following DNS TXT record manually, then click Confirm.",
                record_name.clone(),
                dns_value.clone(),
            )
            .await;

            // Wait for user confirmation, background polling, or 10-minute timeout
            let confirmed = tokio::select! {
                _ = manual_confirm.notified() => {
                    info!("Manual DNS challenge confirmed by user");
                    true
                }
                _ = async {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                        if providers::poll_dns_txt_record(&domain, &dns_value).await {
                            info!("DNS TXT record auto-detected via polling");
                            break;
                        }
                    }
                } => true,
                _ = tokio::time::sleep(std::time::Duration::from_secs(600)) => {
                    false
                }
            };

            if !confirmed {
                bail!("DNS-01 challenge timed out after 10 minutes");
            }
        }

        // Notify ACME server that challenge is ready
        challenge_handle
            .set_ready()
            .await
            .context("Failed to set challenge ready")?;
    }

    // ── Step 6: Validate ─────────────────────────────────────────────────────
    set_progress(
        &progress,
        IssuanceState::Validating,
        "Validating challenge with ACME server…",
    )
    .await;

    // Poll order status until Ready or Valid using built-in RetryPolicy
    let retry_policy = RetryPolicy::default()
        .initial_delay(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(60));

    let order_status = order
        .poll_ready(&retry_policy)
        .await
        .context("ACME order validation timed out or failed")?;

    if order_status == OrderStatus::Invalid {
        bail!("ACME order became Invalid during validation");
    }

    info!("Order validated (status: {:?})", order_status);

    // ── Step 7: Download certificate ─────────────────────────────────────────
    set_progress(
        &progress,
        IssuanceState::Downloading,
        "Generating key pair and finalizing order…",
    )
    .await;

    // order.finalize() uses the rcgen feature to generate a key + CSR internally
    let key_pem = order
        .finalize()
        .await
        .context("Failed to finalize ACME order")?;

    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("Failed to download certificate")?;

    info!("Certificate downloaded for domain {}", domain);

    // ── Step 8: Install ──────────────────────────────────────────────────────
    set_progress(
        &progress,
        IssuanceState::Installing,
        "Writing certificate and key to disk…",
    )
    .await;

    let cert_path = Path::new(CERT_PATH);
    let key_path = Path::new(KEY_PATH);

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    std::fs::write(cert_path, cert_chain_pem.as_bytes())
        .with_context(|| format!("Failed to write cert to {:?}", cert_path))?;
    std::fs::write(key_path, key_pem.as_bytes())
        .with_context(|| format!("Failed to write key to {:?}", key_path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("Failed to set permissions on {:?}", cert_path))?;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {:?}", key_path))?;
    }

    info!("Certificate installed to {} and {}", CERT_PATH, KEY_PATH);

    // ── Step 9: Cleanup ──────────────────────────────────────────────────────
    if let Some(record_id) = cf_record_id {
        let cf = providers::CloudflareProvider::new(&acme_config.cloudflare_api_token);
        if let Err(e) = cf.delete_txt_record(&domain, &record_id).await {
            warn!("Failed to delete Cloudflare TXT record: {}", e);
        } else {
            info!("Cleaned up Cloudflare TXT record");
        }
    }

    // ── Step 10: Complete ────────────────────────────────────────────────────
    set_progress(
        &progress,
        IssuanceState::Complete,
        "Certificate issued and installed successfully.",
    )
    .await;

    Ok(())
}

// ── cert_expires_within_days ─────────────────────────────────────────────────

pub fn cert_expires_within_days(tls_config: &TlsConfig, days: u64) -> Result<bool> {
    use chrono::Utc;

    let cert_info = crate::cert_parser::get_current_cert_info(tls_config)
        .context("Failed to read current certificate")?;

    let parsed = match cert_info {
        Some(c) => c,
        None => return Ok(false),
    };

    // not_after is formatted as RFC 2822 by cert_parser, e.g.
    // "Thu, 31 Dec 2025 23:59:59 +0000"
    // Fall back to the task's documented format "2025-12-31 23:59:59 UTC" as well.
    let expiry = chrono::DateTime::parse_from_rfc2822(&parsed.not_after)
        .or_else(|_| {
            chrono::DateTime::parse_from_str(&parsed.not_after, "%Y-%m-%d %H:%M:%S %Z")
        })
        .with_context(|| {
            format!(
                "Failed to parse certificate not_after: {}",
                parsed.not_after
            )
        })?;

    let now = Utc::now();
    let threshold = now + chrono::Duration::days(days as i64);

    Ok(expiry < threshold)
}

// ── renewal_loop ─────────────────────────────────────────────────────────────

pub async fn renewal_loop(
    config_path: std::path::PathBuf,
    progress: Arc<RwLock<IssuanceProgress>>,
    manual_confirm: Arc<tokio::sync::Notify>,
    restart_signal: tokio::sync::watch::Sender<bool>,
) {
    // Initial startup delay
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

    loop {
        let result: Result<()> = async {
            let config = Config::load(&config_path).context("Failed to load config for renewal")?;
            let acme = &config.tls.acme;

            // Only auto-renew for Cloudflare provider (manual can't auto-renew)
            if !acme.enabled || acme.domain.is_empty() || acme.provider != "cloudflare" {
                return Ok(());
            }

            let expiring = cert_expires_within_days(&config.tls, 30)
                .context("Failed to check certificate expiry")?;

            if !expiring {
                return Ok(());
            }

            info!("Certificate expires within 30 days — starting auto-renewal");

            issue_certificate(acme, progress.clone(), manual_confirm.clone()).await?;

            // Update config timestamps on success
            let mut updated_config = Config::load(&config_path)
                .context("Failed to reload config after renewal")?;
            updated_config.tls.acme.last_renewed =
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
            updated_config.tls.acme.last_renewal_error = String::new();
            updated_config
                .save(&config_path)
                .context("Failed to save config after renewal")?;

            // Signal server restart to pick up new certificate
            let _ = restart_signal.send(true);

            Ok(())
        }
        .await;

        if let Err(e) = result {
            warn!("ACME renewal loop error: {}", e);

            // Save error to config
            if let Ok(mut config) = Config::load(&config_path) {
                config.tls.acme.last_renewal_error = e.to_string();
                let _ = config.save(&config_path);
            }

            // Set progress to Failed
            let mut p = progress.write().await;
            p.state = IssuanceState::Failed;
            p.message = e.to_string();
        }

        // Sleep 24 hours before next check
        tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
    }
}
