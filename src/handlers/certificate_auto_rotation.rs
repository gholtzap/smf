use axum::{
    extract::{State, Path, Query},
    http::StatusCode,
    Json,
};
use crate::db::AppState;
use crate::types::{
    AutoRotationConfig, AutoRotationStatus, CreateAutoRotationConfigRequest,
    UpdateAutoRotationConfigRequest, AutoRotationAttempt, CertificatePurpose,
};
use crate::services::{
    certificate_auto_rotation::CertificateAutoRotationService,
    certificate::CertificateService,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct GetConfigQuery {
    pub certificate_name: Option<String>,
    pub certificate_purpose: Option<CertificatePurpose>,
}

#[derive(Debug, Deserialize)]
pub struct GetAttemptsQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListConfigsResponse {
    pub configs: Vec<AutoRotationConfig>,
    pub total_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ListAttemptsResponse {
    pub attempts: Vec<AutoRotationAttempt>,
    pub total_count: usize,
}

pub async fn create_auto_rotation_config(
    State(state): State<AppState>,
    Json(request): Json<CreateAutoRotationConfigRequest>,
) -> Result<Json<AutoRotationConfig>, (StatusCode, String)> {
    match CertificateAutoRotationService::create_config(
        &state.db,
        request.certificate_name,
        request.certificate_purpose,
        request.rotation_threshold_days,
        request.provider_type,
        request.provider_config,
    )
    .await
    {
        Ok(config) => Ok(Json(config)),
        Err(e) => {
            tracing::error!("Failed to create auto-rotation config: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create auto-rotation config: {}", e),
            ))
        }
    }
}

pub async fn get_auto_rotation_config(
    State(state): State<AppState>,
    Path(config_id): Path<String>,
) -> Result<Json<AutoRotationConfig>, (StatusCode, String)> {
    match CertificateAutoRotationService::get_config(&state.db, &config_id).await {
        Ok(Some(config)) => Ok(Json(config)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "Auto-rotation config not found".to_string(),
        )),
        Err(e) => {
            tracing::error!("Failed to get auto-rotation config: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get auto-rotation config: {}", e),
            ))
        }
    }
}

pub async fn list_auto_rotation_configs(
    State(state): State<AppState>,
) -> Result<Json<ListConfigsResponse>, (StatusCode, String)> {
    match CertificateAutoRotationService::list_all_configs(&state.db).await {
        Ok(configs) => {
            let total_count = configs.len();
            Ok(Json(ListConfigsResponse {
                configs,
                total_count,
            }))
        }
        Err(e) => {
            tracing::error!("Failed to list auto-rotation configs: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to list auto-rotation configs: {}", e),
            ))
        }
    }
}

pub async fn update_auto_rotation_config(
    State(state): State<AppState>,
    Path(config_id): Path<String>,
    Json(request): Json<UpdateAutoRotationConfigRequest>,
) -> Result<Json<AutoRotationConfig>, (StatusCode, String)> {
    match CertificateAutoRotationService::update_config(
        &state.db,
        &config_id,
        request.enabled,
        request.rotation_threshold_days,
        request.provider_config,
    )
    .await
    {
        Ok(config) => Ok(Json(config)),
        Err(e) => {
            tracing::error!("Failed to update auto-rotation config: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update auto-rotation config: {}", e),
            ))
        }
    }
}

pub async fn delete_auto_rotation_config(
    State(state): State<AppState>,
    Path(config_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    match CertificateAutoRotationService::delete_config(&state.db, &config_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!("Failed to delete auto-rotation config: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete auto-rotation config: {}", e),
            ))
        }
    }
}

pub async fn get_auto_rotation_status(
    State(state): State<AppState>,
    Path(config_id): Path<String>,
) -> Result<Json<AutoRotationStatus>, (StatusCode, String)> {
    let config = match CertificateAutoRotationService::get_config(&state.db, &config_id).await {
        Ok(Some(config)) => config,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                "Auto-rotation config not found".to_string(),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get auto-rotation config: {}", e),
            ))
        }
    };

    let cert = match CertificateService::get_by_name_and_purpose(
        &state.db,
        &config.certificate_name,
        config.certificate_purpose,
    )
    .await
    {
        Ok(Some(cert)) => cert,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                "Certificate not found".to_string(),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get certificate: {}", e),
            ))
        }
    };

    let days_until_expiration = cert.days_until_expiration();
    let should_rotate = config.should_rotate(days_until_expiration);

    Ok(Json(AutoRotationStatus {
        config_id: config.id,
        certificate_name: config.certificate_name,
        certificate_purpose: config.certificate_purpose,
        enabled: config.enabled,
        rotation_threshold_days: config.rotation_threshold_days,
        days_until_expiration,
        should_rotate,
        last_rotation_attempt: config.last_rotation_attempt,
        last_rotation_success: config.last_rotation_success,
        last_rotation_error: config.last_rotation_error,
    }))
}

pub async fn get_config_attempts(
    State(state): State<AppState>,
    Path(config_id): Path<String>,
    Query(query): Query<GetAttemptsQuery>,
) -> Result<Json<ListAttemptsResponse>, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).min(500);

    match CertificateAutoRotationService::get_attempts_for_config(&state.db, &config_id, limit)
        .await
    {
        Ok(attempts) => {
            let total_count = attempts.len();
            Ok(Json(ListAttemptsResponse {
                attempts,
                total_count,
            }))
        }
        Err(e) => {
            tracing::error!("Failed to get rotation attempts: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get rotation attempts: {}", e),
            ))
        }
    }
}

pub async fn get_recent_attempts(
    State(state): State<AppState>,
    Query(query): Query<GetAttemptsQuery>,
) -> Result<Json<ListAttemptsResponse>, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).min(500);

    match CertificateAutoRotationService::get_recent_attempts(&state.db, limit).await {
        Ok(attempts) => {
            let total_count = attempts.len();
            Ok(Json(ListAttemptsResponse {
                attempts,
                total_count,
            }))
        }
        Err(e) => {
            tracing::error!("Failed to get recent attempts: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get recent attempts: {}", e),
            ))
        }
    }
}
