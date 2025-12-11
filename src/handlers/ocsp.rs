use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use crate::services::ocsp_client::OcspClient;
use crate::services::certificate::CertificateService;
use crate::db::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckCertificateRequest {
    pub certificate_name: String,
    pub certificate_purpose: crate::types::CertificatePurpose,
    pub issuer_name: String,
    pub issuer_purpose: crate::types::CertificatePurpose,
    pub responder_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckCertificateResponse {
    pub certificate_name: String,
    pub status: String,
    pub revocation_time: Option<i64>,
    pub revocation_reason: Option<u8>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

pub async fn check_certificate(
    State(state): State<AppState>,
    Json(request): Json<CheckCertificateRequest>,
) -> impl IntoResponse {
    let ocsp_client = OcspClient::new(state.db.clone());

    let cert = match CertificateService::get_by_name_and_purpose(&state.db, &request.certificate_name, request.certificate_purpose).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": format!("Certificate '{}' not found", request.certificate_name)
            }))).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to get certificate: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to get certificate: {}", e)
            }))).into_response()
        }
    };

    let issuer = match CertificateService::get_by_name_and_purpose(&state.db, &request.issuer_name, request.issuer_purpose).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": format!("Issuer certificate '{}' not found", request.issuer_name)
            }))).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to get issuer certificate: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to get issuer certificate: {}", e)
            }))).into_response()
        }
    };

    match ocsp_client.check_certificate(&cert, &issuer, &request.responder_url).await {
        Ok(cert_status) => {
            let (status, revocation_time, revocation_reason) = match cert_status {
                crate::types::ocsp::CertStatus::Good => ("good".to_string(), None, None),
                crate::types::ocsp::CertStatus::Revoked { revocation_time, revocation_reason } => {
                    ("revoked".to_string(), Some(revocation_time), revocation_reason)
                }
                crate::types::ocsp::CertStatus::Unknown => ("unknown".to_string(), None, None),
            };

            let response = CheckCertificateResponse {
                certificate_name: request.certificate_name,
                status,
                revocation_time,
                revocation_reason,
                checked_at: chrono::Utc::now(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to check certificate via OCSP: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to check certificate via OCSP: {}", e)
            }))).into_response()
        }
    }
}

pub async fn list_cache(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ocsp_client = OcspClient::new(state.db.clone());

    match ocsp_client.list_cached_responses().await {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list OCSP cache: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to list OCSP cache: {}", e)
            }))).into_response()
        }
    }
}

pub async fn list_expired_cache(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ocsp_client = OcspClient::new(state.db.clone());

    match ocsp_client.list_expired_cache_entries().await {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list expired OCSP cache entries: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to list expired OCSP cache entries: {}", e)
            }))).into_response()
        }
    }
}

pub async fn delete_cache_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ocsp_client = OcspClient::new(state.db.clone());

    match ocsp_client.delete_cache_entry(&id).await {
        Ok(true) => (StatusCode::NO_CONTENT, ()).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Cache entry not found"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete OCSP cache entry: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to delete OCSP cache entry: {}", e)
            }))).into_response()
        }
    }
}

pub async fn clear_cache(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ocsp_client = OcspClient::new(state.db.clone());

    match ocsp_client.clear_cache().await {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({
            "deleted_count": count
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to clear OCSP cache: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to clear OCSP cache: {}", e)
            }))).into_response()
        }
    }
}

pub async fn delete_expired_cache(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ocsp_client = OcspClient::new(state.db.clone());

    match ocsp_client.delete_expired_cache_entries().await {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({
            "deleted_count": count
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete expired OCSP cache entries: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to delete expired OCSP cache entries: {}", e)
            }))).into_response()
        }
    }
}
