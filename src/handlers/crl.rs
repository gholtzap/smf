use axum::{
    extract::{Json, State, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use crate::services::crl::CrlService;
use crate::db::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchCrlRequest {
    pub distribution_point_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshQueryParams {
    pub hours_threshold: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationCheckResponse {
    pub is_revoked: bool,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

pub async fn fetch_crl(
    State(state): State<AppState>,
    Json(request): Json<FetchCrlRequest>,
) -> impl IntoResponse {
    match CrlService::fetch_and_store(&state.db, request.distribution_point_url).await {
        Ok(crl) => (StatusCode::OK, Json(crl)).into_response(),
        Err(e) => {
            tracing::error!("Failed to fetch CRL: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to fetch CRL: {}", e)
            }))).into_response()
        }
    }
}

pub async fn get_crl(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match CrlService::get_by_id(&state.db, &id).await {
        Ok(Some(crl)) => (StatusCode::OK, Json(crl)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "CRL not found"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to get CRL: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to get CRL: {}", e)
            }))).into_response()
        }
    }
}

pub async fn list_crls(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match CrlService::list_all(&state.db).await {
        Ok(crls) => (StatusCode::OK, Json(crls)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list CRLs: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to list CRLs: {}", e)
            }))).into_response()
        }
    }
}

pub async fn list_expired_crls(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match CrlService::list_expired(&state.db).await {
        Ok(crls) => (StatusCode::OK, Json(crls)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list expired CRLs: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to list expired CRLs: {}", e)
            }))).into_response()
        }
    }
}

pub async fn list_crls_needs_refresh(
    State(state): State<AppState>,
    Query(params): Query<RefreshQueryParams>,
) -> impl IntoResponse {
    let hours_threshold = params.hours_threshold.unwrap_or(24);

    match CrlService::list_needs_refresh(&state.db, hours_threshold).await {
        Ok(crls) => (StatusCode::OK, Json(crls)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list CRLs that need refresh: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to list CRLs that need refresh: {}", e)
            }))).into_response()
        }
    }
}

pub async fn delete_crl(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match CrlService::delete(&state.db, &id).await {
        Ok(_) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete CRL: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to delete CRL: {}", e)
            }))).into_response()
        }
    }
}

pub async fn check_revocation(
    State(state): State<AppState>,
    Path((serial_number, issuer)): Path<(String, String)>,
) -> impl IntoResponse {
    match CrlService::is_certificate_revoked(&state.db, &serial_number, &issuer).await {
        Ok(is_revoked) => {
            let response = RevocationCheckResponse {
                is_revoked,
                checked_at: chrono::Utc::now(),
            };
            (StatusCode::OK, Json(response)).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to check certificate revocation: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to check certificate revocation: {}", e)
            }))).into_response()
        }
    }
}

pub async fn get_fetch_attempts(
    State(state): State<AppState>,
    Query(params): Query<FetchAttemptsQueryParams>,
) -> impl IntoResponse {
    let url = match params.url {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Missing required parameter: url"
        }))).into_response(),
    };

    let limit = params.limit.unwrap_or(10);

    match CrlService::get_fetch_attempts(&state.db, &url, limit).await {
        Ok(attempts) => (StatusCode::OK, Json(attempts)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get fetch attempts: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to get fetch attempts: {}", e)
            }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchAttemptsQueryParams {
    pub url: Option<String>,
    pub limit: Option<i64>,
}
