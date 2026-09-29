use crate::http::{HttpClient, HttpRequest};
use crate::store::commands::DeviceCommand;
use crate::store::persistence_manager::PersistenceManager;
use anyhow::{Result, anyhow};
use log::debug;
use std::sync::Arc;

pub use wa_rs_core::version::parse_sw_js;

const SW_URL: &str = "https://web.whatsapp.com/sw.js";

pub async fn fetch_latest_app_version(
    http_client: &Arc<dyn HttpClient>,
) -> Result<(u32, u32, u32)> {
    let request = HttpRequest::get(SW_URL).with_header("sec-fetch-site", "none")
    .with_header(
        "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    );
    let response = http_client
        .execute(request)
        .await
        .map_err(|e| anyhow!("HTTP request to {} failed: {}", SW_URL, e))?;

    let body_str = response
        .body_string()
        .map_err(|e| anyhow!("Failed to decode response body: {}", e))?;

    parse_sw_js(&body_str)
        .ok_or_else(|| anyhow!("Could not find 'client_revision' version in sw.js response"))
}

pub async fn resolve_and_update_version(
    persistence_manager: &Arc<PersistenceManager>,
    http_client: &Arc<dyn HttpClient>,
    override_version: Option<(u32, u32, u32)>,
) -> Result<()> {
    if let Some((p, s, t)) = override_version {
        debug!("Using user-provided override version: {}.{}.{}", p, s, t);
        persistence_manager
            .process_command(DeviceCommand::SetAppVersion((p, s, t)))
            .await;
        return Ok(());
    }

    let device = persistence_manager.get_device_snapshot().await;
    let last_fetched_ms = device.app_version_last_fetched_ms;

    let needs_fetch = if last_fetched_ms == 0 {
        true
    } else {
        match chrono::DateTime::from_timestamp_millis(last_fetched_ms) {
            Some(last_fetched_dt) => {
                chrono::Utc::now().signed_duration_since(last_fetched_dt)
                    > chrono::Duration::hours(24)
            }
            None => true,
        }
    };

    if needs_fetch {
        debug!("WhatsApp version is stale or missing, fetching latest...");
        let (p, s, t) = fetch_latest_app_version(http_client)
            .await
            .map_err(|e| anyhow!("Failed to fetch latest WhatsApp version: {}", e))?;
        debug!("Fetched latest version: {}.{}.{}", p, s, t);
        persistence_manager
            .process_command(DeviceCommand::SetAppVersion((p, s, t)))
            .await;
    } else {
        debug!(
            "Using cached version: {}.{}.{}",
            device.app_version_primary, device.app_version_secondary, device.app_version_tertiary
        );
    }

    Ok(())
}
