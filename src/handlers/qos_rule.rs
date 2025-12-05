use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use crate::db::AppState;
use crate::types::QosRule;
use crate::services::qos_rule::QosRuleManager;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddQosRulesRequest {
    pub qos_rules: Vec<QosRule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifyQosRuleRequest {
    pub qos_rule: QosRule,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveQosRulesRequest {
    pub qos_rule_ids: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosRulesResponse {
    pub qos_rules: Vec<QosRule>,
}

pub async fn add_qos_rules(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<AddQosRulesRequest>,
) -> Result<StatusCode, AppError> {
    let manager = QosRuleManager::new(Arc::new(state.db.clone()));

    manager
        .add_qos_rules(&sm_context_ref, payload.qos_rules)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Added QoS rules to SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::CREATED)
}

pub async fn modify_qos_rule(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<ModifyQosRuleRequest>,
) -> Result<StatusCode, AppError> {
    let manager = QosRuleManager::new(Arc::new(state.db.clone()));

    manager
        .modify_qos_rule(&sm_context_ref, payload.qos_rule)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Modified QoS rule in SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::OK)
}

pub async fn remove_qos_rules(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<RemoveQosRulesRequest>,
) -> Result<StatusCode, AppError> {
    let manager = QosRuleManager::new(Arc::new(state.db.clone()));

    manager
        .remove_qos_rules(&sm_context_ref, payload.qos_rule_ids)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Removed QoS rules from SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_qos_rules(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
) -> Result<Json<QosRulesResponse>, AppError> {
    let manager = QosRuleManager::new(Arc::new(state.db.clone()));

    let qos_rules = manager
        .get_qos_rules(&sm_context_ref)
        .await
        .map_err(|e| AppError::NotFound(e))?;

    tracing::debug!(
        "Retrieved {} QoS rules for SM context: {}",
        qos_rules.len(),
        sm_context_ref
    );

    Ok(Json(QosRulesResponse { qos_rules }))
}

pub async fn apply_qos_rules(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
) -> Result<StatusCode, AppError> {
    let manager = QosRuleManager::new(Arc::new(state.db.clone()));

    manager
        .apply_qos_rules(&sm_context_ref)
        .await
        .map_err(|e| AppError::ValidationError(e))?;

    tracing::info!(
        "Applied QoS rules for SM context: {}",
        sm_context_ref
    );

    Ok(StatusCode::OK)
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
