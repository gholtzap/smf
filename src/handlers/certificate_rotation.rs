use axum::{
    extract::{State, Path, Query},
    http::StatusCode,
    Json,
};
use crate::db::AppState;
use crate::types::{
    CertificatePurpose, CertificateRotationRequest, CertificateRotationResponse,
    CertificateRollbackRequest, CertificateRollbackResponse, RotationHistoryResponse,
};
use crate::services::certificate_rotation::CertificateRotationService;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RotateCertificateParams {
    pub name: String,
    pub purpose: CertificatePurpose,
}

#[derive(Debug, Deserialize)]
pub struct RotationHistoryQuery {
    pub name: Option<String>,
    pub purpose: Option<CertificatePurpose>,
}

pub async fn rotate_certificate(
    State(state): State<AppState>,
    Path(params): Path<RotateCertificateParams>,
    Json(request): Json<CertificateRotationRequest>,
) -> Result<Json<CertificateRotationResponse>, (StatusCode, String)> {
    match CertificateRotationService::rotate_certificate(
        &state.db,
        &params.name,
        params.purpose,
        request,
        None,
        None,
    )
    .await
    {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            tracing::error!("Failed to rotate certificate: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to rotate certificate: {}", e),
            ))
        }
    }
}

pub async fn rollback_certificate_rotation(
    State(state): State<AppState>,
    Json(request): Json<CertificateRollbackRequest>,
) -> Result<Json<CertificateRollbackResponse>, (StatusCode, String)> {
    match CertificateRotationService::rollback_rotation(&state.db, request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            tracing::error!("Failed to rollback certificate rotation: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to rollback certificate rotation: {}", e),
            ))
        }
    }
}

pub async fn get_rotation_history(
    State(state): State<AppState>,
    Query(query): Query<RotationHistoryQuery>,
) -> Result<Json<RotationHistoryResponse>, (StatusCode, String)> {
    match CertificateRotationService::get_rotation_history(
        &state.db,
        query.name,
        query.purpose,
    )
    .await
    {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            tracing::error!("Failed to get rotation history: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get rotation history: {}", e),
            ))
        }
    }
}
