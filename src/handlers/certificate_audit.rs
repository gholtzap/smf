use axum::{
    extract::{Json, State, Query},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use crate::types::{AuditLogQuery, UsageRecordQuery, AuditEventType, CertificateUsageType};
use crate::services::certificate_audit::CertificateAuditService;
use crate::db::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogQueryParams {
    pub certificate_id: Option<String>,
    pub certificate_name: Option<String>,
    pub event_type: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub actor: Option<String>,
    pub success: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageRecordQueryParams {
    pub certificate_id: Option<String>,
    pub certificate_name: Option<String>,
    pub usage_type: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub service: Option<String>,
    pub success: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<u64>,
}

pub async fn query_audit_logs(
    State(state): State<AppState>,
    Query(params): Query<AuditLogQueryParams>,
) -> impl IntoResponse {
    let event_type = if let Some(ref et) = params.event_type {
        match et.to_uppercase().as_str() {
            "CERTIFICATE_CREATED" => Some(AuditEventType::CertificateCreated),
            "CERTIFICATE_UPDATED" => Some(AuditEventType::CertificateUpdated),
            "CERTIFICATE_DELETED" => Some(AuditEventType::CertificateDeleted),
            "CERTIFICATE_ACCESSED" => Some(AuditEventType::CertificateAccessed),
            "CERTIFICATE_VALIDATED" => Some(AuditEventType::CertificateValidated),
            "CERTIFICATE_ROTATED" => Some(AuditEventType::CertificateRotated),
            "CERTIFICATE_ROLLED_BACK" => Some(AuditEventType::CertificateRolledBack),
            "CERTIFICATE_EXPORTED" => Some(AuditEventType::CertificateExported),
            "PRIVATE_KEY_ACCESSED" => Some(AuditEventType::PrivateKeyAccessed),
            "CHAIN_VALIDATED" => Some(AuditEventType::ChainValidated),
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Invalid event type: {}", et)
            }))).into_response(),
        }
    } else {
        None
    };

    let start_time = if let Some(ref st) = params.start_time {
        match chrono::DateTime::parse_from_rfc3339(st) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Invalid start_time format: {}", st)
            }))).into_response(),
        }
    } else {
        None
    };

    let end_time = if let Some(ref et) = params.end_time {
        match chrono::DateTime::parse_from_rfc3339(et) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Invalid end_time format: {}", et)
            }))).into_response(),
        }
    } else {
        None
    };

    let query = AuditLogQuery {
        certificate_id: params.certificate_id,
        certificate_name: params.certificate_name,
        event_type,
        start_time,
        end_time,
        actor: params.actor,
        success: params.success,
        limit: params.limit,
        offset: params.offset,
    };

    match CertificateAuditService::query_audit_logs(&state.db, &query).await {
        Ok(logs) => (StatusCode::OK, Json(logs)).into_response(),
        Err(e) => {
            tracing::error!("Failed to query audit logs: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to query audit logs"
            }))).into_response()
        }
    }
}

pub async fn query_usage_records(
    State(state): State<AppState>,
    Query(params): Query<UsageRecordQueryParams>,
) -> impl IntoResponse {
    let usage_type = if let Some(ref ut) = params.usage_type {
        match ut.to_uppercase().as_str() {
            "TLS_HANDSHAKE" => Some(CertificateUsageType::TlsHandshake),
            "MTLS_VALIDATION" => Some(CertificateUsageType::MtlsValidation),
            "SIGNATURE_VERIFICATION" => Some(CertificateUsageType::SignatureVerification),
            "SIGNATURE_GENERATION" => Some(CertificateUsageType::SignatureGeneration),
            "ENCRYPTION" => Some(CertificateUsageType::Encryption),
            "DECRYPTION" => Some(CertificateUsageType::Decryption),
            _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Invalid usage type: {}", ut)
            }))).into_response(),
        }
    } else {
        None
    };

    let start_time = if let Some(ref st) = params.start_time {
        match chrono::DateTime::parse_from_rfc3339(st) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Invalid start_time format: {}", st)
            }))).into_response(),
        }
    } else {
        None
    };

    let end_time = if let Some(ref et) = params.end_time {
        match chrono::DateTime::parse_from_rfc3339(et) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Invalid end_time format: {}", et)
            }))).into_response(),
        }
    } else {
        None
    };

    let query = UsageRecordQuery {
        certificate_id: params.certificate_id,
        certificate_name: params.certificate_name,
        usage_type,
        start_time,
        end_time,
        service: params.service,
        success: params.success,
        limit: params.limit,
        offset: params.offset,
    };

    match CertificateAuditService::query_usage_records(&state.db, &query).await {
        Ok(records) => (StatusCode::OK, Json(records)).into_response(),
        Err(e) => {
            tracing::error!("Failed to query usage records: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to query usage records"
            }))).into_response()
        }
    }
}

pub async fn get_audit_summary(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match CertificateAuditService::get_audit_summary(&state.db).await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get audit summary: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to get audit summary"
            }))).into_response()
        }
    }
}

pub async fn get_usage_summary(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match CertificateAuditService::get_usage_summary(&state.db).await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get usage summary: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to get usage summary"
            }))).into_response()
        }
    }
}
