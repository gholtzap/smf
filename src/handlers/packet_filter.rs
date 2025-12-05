use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use crate::db::AppState;
use crate::types::{PacketFilter, SdfTemplate};
use crate::services::packet_filter::PacketFilterManager;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPacketFiltersRequest {
    pub packet_filters: Vec<PacketFilter>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPacketFiltersFromSdfRequest {
    pub sdf_templates: Vec<SdfTemplateWithMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdfTemplateWithMetadata {
    pub sdf_template: SdfTemplate,
    pub packet_filter_id: Option<u8>,
    pub precedence: u8,
    pub qfi: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifyPacketFilterRequest {
    pub packet_filter: PacketFilter,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovePacketFiltersRequest {
    pub packet_filter_ids: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketFiltersResponse {
    pub packet_filters: Vec<PacketFilter>,
}

pub async fn add_packet_filters(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<AddPacketFiltersRequest>,
) -> Result<StatusCode, AppError> {
    let manager = PacketFilterManager::new(Arc::new(state.db.clone()));

    manager
        .add_packet_filters(&sm_context_ref, payload.packet_filters)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Added packet filters to SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::CREATED)
}

pub async fn add_packet_filters_from_sdf(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<AddPacketFiltersFromSdfRequest>,
) -> Result<StatusCode, AppError> {
    let manager = PacketFilterManager::new(Arc::new(state.db.clone()));

    let existing_filters = manager
        .get_packet_filters(&sm_context_ref)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    let mut packet_filters = Vec::new();
    let mut next_filter_id = 1u8;

    for sdf_meta in payload.sdf_templates {
        crate::utils::validate_sdf_template(&sdf_meta.sdf_template)
            .map_err(|e| AppError::ValidationError(e))?;

        let filter_id = if let Some(id) = sdf_meta.packet_filter_id {
            id
        } else {
            while existing_filters.iter().any(|f| f.packet_filter_id == next_filter_id)
                || packet_filters.iter().any(|f: &PacketFilter| f.packet_filter_id == next_filter_id)
            {
                next_filter_id = next_filter_id.wrapping_add(1);
                if next_filter_id == 0 {
                    return Err(AppError::ValidationError(
                        "No available packet filter IDs".to_string(),
                    ));
                }
            }
            let id = next_filter_id;
            next_filter_id = next_filter_id.wrapping_add(1);
            id
        };

        let packet_filter = crate::utils::create_packet_filter_from_sdf(
            filter_id,
            sdf_meta.precedence,
            &sdf_meta.sdf_template,
            sdf_meta.qfi,
        )
        .map_err(|e| AppError::ValidationError(e))?;

        packet_filters.push(packet_filter);
    }

    manager
        .add_packet_filters(&sm_context_ref, packet_filters)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Added packet filters from SDF templates to SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::CREATED)
}

pub async fn modify_packet_filter(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<ModifyPacketFilterRequest>,
) -> Result<StatusCode, AppError> {
    let manager = PacketFilterManager::new(Arc::new(state.db.clone()));

    manager
        .modify_packet_filter(&sm_context_ref, payload.packet_filter)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Modified packet filter in SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::OK)
}

pub async fn remove_packet_filters(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<RemovePacketFiltersRequest>,
) -> Result<StatusCode, AppError> {
    let manager = PacketFilterManager::new(Arc::new(state.db.clone()));

    manager
        .remove_packet_filters(&sm_context_ref, payload.packet_filter_ids)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Removed packet filters from SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_packet_filters(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
) -> Result<Json<PacketFiltersResponse>, AppError> {
    let manager = PacketFilterManager::new(Arc::new(state.db.clone()));

    let packet_filters = manager
        .get_packet_filters(&sm_context_ref)
        .await
        .map_err(|e| AppError::NotFound(e))?;

    tracing::debug!(
        "Retrieved {} packet filters for SM context: {}",
        packet_filters.len(),
        sm_context_ref
    );

    Ok(Json(PacketFiltersResponse { packet_filters }))
}

#[derive(Debug)]
pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    NotFound(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (status, error_message).into_response()
    }
}
