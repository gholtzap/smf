use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::db::AppState;
use crate::services::context_transfer_target::ContextTransferTarget;
use crate::types::sm_context_transfer::{
    SmContextTransferRequest, SmContextTransferResponse,
};

pub async fn receive_sm_context_transfer(
    State(state): State<AppState>,
    Json(payload): Json<SmContextTransferRequest>,
) -> Result<Json<SmContextTransferResponse>, AppError> {
    tracing::info!(
        "Received SM context transfer request - Transfer ID: {}, SUPI: {}, PDU Session ID: {}",
        payload.transfer_id,
        payload.supi,
        payload.pdu_session_id
    );

    let target_smf_id = std::env::var("NF_INSTANCE_ID")
        .unwrap_or_else(|_| "default-target-smf".to_string());

    let pfcp_client = state
        .pfcp_client
        .clone()
        .ok_or_else(|| AppError::InternalError("PFCP client not initialized".to_string()))?;

    let context_transfer_target =
        ContextTransferTarget::new(state.db.clone(), pfcp_client, target_smf_id);

    match context_transfer_target
        .receive_and_process_transfer(payload)
        .await
    {
        Ok(response) => {
            if response.accepted {
                tracing::info!(
                    "SM context transfer accepted - Transfer ID: {}, Target Context Ref: {:?}",
                    response.transfer_id,
                    response.target_sm_context_ref
                );
                Ok(Json(response))
            } else {
                tracing::warn!(
                    "SM context transfer rejected - Transfer ID: {}, Cause: {:?}",
                    response.transfer_id,
                    response.cause
                );
                Ok(Json(response))
            }
        }
        Err(e) => {
            tracing::error!(
                "Failed to process SM context transfer - Error: {}",
                e
            );
            Err(AppError::InternalError(format!(
                "Context transfer processing failed: {}",
                e
            )))
        }
    }
}

pub async fn receive_transfer_acknowledgment(
    State(_state): State<AppState>,
    Json(_payload): Json<crate::types::sm_context_transfer::SmContextTransferAck>,
) -> Result<StatusCode, AppError> {
    tracing::info!(
        "Received transfer acknowledgment - Transfer ID: {}",
        _payload.transfer_id
    );

    tracing::debug!(
        "Transfer acknowledged by source SMF - Source SMF ID: {}, Released Resources: {}",
        _payload.source_smf_id,
        _payload.released_resources.len()
    );

    Ok(StatusCode::NO_CONTENT)
}

pub async fn receive_transfer_cancellation(
    State(_state): State<AppState>,
    Json(_payload): Json<crate::types::sm_context_transfer::SmContextTransferCancel>,
) -> Result<StatusCode, AppError> {
    tracing::warn!(
        "Received transfer cancellation - Transfer ID: {}, Cause: {:?}",
        _payload.transfer_id,
        _payload.cancel_cause
    );

    Ok(StatusCode::NO_CONTENT)
}

pub enum AppError {
    ValidationError(String),
    InternalError(String),
    NotFound(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (status, message).into_response()
    }
}
