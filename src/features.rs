use crate::blocklist::BlocklistManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Known blocklist URLs for each feature.
pub const BLOCKLIST_ADS_MALWARE: &str =
    "https://raw.githubusercontent.com/ron-png/UltimateDNSBlockList/refs/heads/main/list/UltimateDNSBlockList.txt";
pub const BLOCKLIST_NSFW: &str = "https://nsfw.oisd.nl/domainswild";
pub const BLOCKLIST_SOCIAL_MEDIA: &str =
    "https://raw.githubusercontent.com/nickspaargaren/no-google/master/categories/social-media.txt";
pub const BLOCKLIST_GAMBLING: &str =
    "https://raw.githubusercontent.com/nickspaargaren/no-google/master/categories/gambling.txt";
pub const BLOCKLIST_CRYPTO_MINING: &str =
    "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser";

/// Safe search domains that get rewritten to their "safe" IP/CNAME.
/// Google: forcesafesearch.google.com -> 216.239.38.120
/// Bing: strict.bing.com
/// YouTube: restrict.youtube.com / restrictmoderate.youtube.com
/// DuckDuckGo: safe.duckduckgo.com
pub const SAFE_SEARCH_MAPPINGS: &[(&str, &str)] = &[
    // Google (A record -> 216.239.38.120)
    ("www.google.com", "216.239.38.120"),
    ("www.google.co.uk", "216.239.38.120"),
    ("www.google.ca", "216.239.38.120"),
    ("www.google.com.au", "216.239.38.120"),
    ("www.google.de", "216.239.38.120"),
    ("www.google.fr", "216.239.38.120"),
    ("www.google.es", "216.239.38.120"),
    ("www.google.it", "216.239.38.120"),
    ("www.google.nl", "216.239.38.120"),
    ("www.google.co.jp", "216.239.38.120"),
    ("www.google.com.br", "216.239.38.120"),
    ("www.google.co.in", "216.239.38.120"),
    ("www.google.ru", "216.239.38.120"),
    // YouTube restrict
    ("www.youtube.com", "216.239.38.120"),
    ("m.youtube.com", "216.239.38.120"),
    ("youtubei.googleapis.com", "216.239.38.120"),
    ("youtube.googleapis.com", "216.239.38.120"),
    ("www.youtube-nocookie.com", "216.239.38.120"),
    // Bing
    ("www.bing.com", "204.79.197.220"),
    // DuckDuckGo
    ("duckduckgo.com", "52.142.124.215"),
    ("www.duckduckgo.com", "52.142.124.215"),
    // Pixabay (safe search)
    ("pixabay.com", "216.239.38.120"),
];

/// Feature definition - a named toggle with an associated blocklist URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub blocklist_url: Option<String>,
    pub enabled: bool,
}

/// Manages feature toggles and their state.
#[derive(Clone)]
pub struct FeatureManager {
    features: Arc<RwLock<Vec<FeatureDefinition>>>,
    safe_search_enabled: Arc<RwLock<bool>>,
    blocklist: BlocklistManager,
}

impl FeatureManager {
    pub fn new(blocklist: BlocklistManager) -> Self {
        let features = vec![
            FeatureDefinition {
                id: "ads_malware".to_string(),
                name: "Block Ads, Malware & Trackers".to_string(),
                description: "Blocks advertising, malware, and tracking domains using a comprehensive blocklist.".to_string(),
                icon: "shield".to_string(),
                blocklist_url: Some(BLOCKLIST_ADS_MALWARE.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "nsfw".to_string(),
                name: "Block NSFW Content".to_string(),
                description: "Blocks adult and explicit content domains using the OISD NSFW list.".to_string(),
                icon: "eye-off".to_string(),
                blocklist_url: Some(BLOCKLIST_NSFW.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "safe_search".to_string(),
                name: "Enforce Safe Search".to_string(),
                description: "Forces safe search on Google, Bing, YouTube, and DuckDuckGo via DNS.".to_string(),
                icon: "search".to_string(),
                blocklist_url: None, // Handled via DNS rewriting, not blocklist
                enabled: false,
            },
            FeatureDefinition {
                id: "social_media".to_string(),
                name: "Block Social Media".to_string(),
                description: "Blocks Facebook, Instagram, TikTok, Twitter/X, and other social media platforms.".to_string(),
                icon: "users".to_string(),
                blocklist_url: Some(BLOCKLIST_SOCIAL_MEDIA.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "gambling".to_string(),
                name: "Block Gambling & Betting".to_string(),
                description: "Blocks online gambling, betting, and casino websites.".to_string(),
                icon: "dice".to_string(),
                blocklist_url: Some(BLOCKLIST_GAMBLING.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "cryptomining".to_string(),
                name: "Block Cryptomining".to_string(),
                description: "Blocks browser-based cryptocurrency mining scripts and domains.".to_string(),
                icon: "cpu".to_string(),
                blocklist_url: Some(BLOCKLIST_CRYPTO_MINING.to_string()),
                enabled: false,
            },
        ];

        Self {
            features: Arc::new(RwLock::new(features)),
            safe_search_enabled: Arc::new(RwLock::new(false)),
            blocklist,
        }
    }

    pub async fn get_features(&self) -> Vec<FeatureDefinition> {
        self.features.read().await.clone()
    }

    #[allow(dead_code)]
    pub async fn is_safe_search_enabled(&self) -> bool {
        *self.safe_search_enabled.read().await
    }

    /// Toggle a feature on or off. If it has a blocklist, load/unload it.
    pub async fn set_feature(&self, feature_id: &str, enabled: bool) {
        let mut features = self.features.write().await;
        let feature = match features.iter_mut().find(|f| f.id == feature_id) {
            Some(f) => f,
            None => {
                warn!("Unknown feature: {}", feature_id);
                return;
            }
        };

        if feature.enabled == enabled {
            return;
        }

        feature.enabled = enabled;
        let blocklist_url = feature.blocklist_url.clone();
        let name = feature.name.clone();

        // Handle safe search separately
        if feature_id == "safe_search" {
            *self.safe_search_enabled.write().await = enabled;
            info!(
                "Safe search {}",
                if enabled { "enabled" } else { "disabled" }
            );
            return;
        }

        // Handle blocklist-based features
        if let Some(url) = blocklist_url {
            if enabled {
                info!("Enabling feature '{}', loading blocklist...", name);
                self.blocklist.add_blocklist_source(&url).await;
            } else {
                info!("Disabling feature '{}', removing blocklist...", name);
                self.blocklist.remove_blocklist_source(&url).await;
            }
        }
    }

    /// Get safe search IP mapping for a domain, if safe search is on.
    pub async fn get_safe_search_ip(&self, domain: &str) -> Option<std::net::Ipv4Addr> {
        if !*self.safe_search_enabled.read().await {
            return None;
        }

        let domain_lower = domain.to_lowercase();
        let domain_trimmed = domain_lower.trim_end_matches('.');

        for (search_domain, ip) in SAFE_SEARCH_MAPPINGS {
            if domain_trimmed == *search_domain {
                if let Ok(addr) = ip.parse() {
                    return Some(addr);
                }
            }
        }
        None
    }
}
