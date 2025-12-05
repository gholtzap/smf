use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::db::AppState;
use crate::types::NotificationData;

pub async fn handle_nf_status_notification(
    State(state): State<AppState>,
    Json(notification): Json<NotificationData>,
) -> Result<StatusCode, (StatusCode, String)> {
    if let Some(discovery_service) = &state.nrf_discovery {
        discovery_service
            .handle_nf_status_notification(notification)
            .await
            .map_err(|e| {
                tracing::error!("Failed to handle NF status notification: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to handle notification: {}", e))
            })?;

        Ok(StatusCode::NO_CONTENT)
    } else {
        tracing::warn!("Received NF status notification but discovery service is not configured");
        Ok(StatusCode::NO_CONTENT)
    }
}
