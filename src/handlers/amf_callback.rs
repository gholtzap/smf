use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::db::AppState;
use crate::types::{N1N2MessageTransferStatusNotification, N2InfoNotification, N2SmInfoType};

pub async fn handle_n1n2_transfer_status(
    State(_state): State<AppState>,
    Path((ue_id, transaction_id)): Path<(String, String)>,
    Json(payload): Json<N1N2MessageTransferStatusNotification>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "Received N1N2 message transfer status notification for UE: {}, transaction: {}, status: {:?}",
        ue_id,
        transaction_id,
        payload.status_info.status
    );

    if let Some(ref cause) = payload.status_info.cause {
        tracing::debug!(
            "N1N2 message transfer cause: {:?} for transaction: {}",
            cause,
            transaction_id
        );
    }

    if let Some(ref n1_container) = payload.n1_message_container {
        tracing::debug!(
            "Received N1 message container in status notification, class: {:?}",
            n1_container.n1_message_class
        );
    }

    if let Some(ref n2_container) = payload.n2_info_container {
        tracing::debug!(
            "Received N2 info container in status notification, class: {:?}",
            n2_container.n2_information_class
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn handle_n2_info_notify(
    State(_state): State<AppState>,
    Path((ue_id, pdu_session_id)): Path<(String, u8)>,
    Json(payload): Json<N2InfoNotification>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "Received N2 info notification for UE: {}, PDU session: {}, info type: {:?}",
        ue_id,
        pdu_session_id,
        payload.sm_info_type
    );

    match payload.sm_info_type {
        Some(N2SmInfoType::PduResSetupRsp) => {
            tracing::info!(
                "Processing PDU Resource Setup Response for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PduResSetupFail) => {
            tracing::warn!(
                "Received PDU Resource Setup Failure for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PduResModifyRsp) => {
            tracing::info!(
                "Processing PDU Resource Modify Response for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PduResModifyFail) => {
            tracing::warn!(
                "Received PDU Resource Modify Failure for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PduResReleaseCmd) => {
            tracing::info!(
                "Processing PDU Resource Release Command for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PduResReleaseRsp) => {
            tracing::info!(
                "Processing PDU Resource Release Response for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PduResNotifyRel) => {
            tracing::info!(
                "Processing PDU Resource Notify Release for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PathSwitchRequestAck) => {
            tracing::info!(
                "Processing Path Switch Request Acknowledgment for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::PathSwitchRequestFail) => {
            tracing::warn!(
                "Received Path Switch Request Failure for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::HandoverRequired) => {
            tracing::info!(
                "Processing Handover Required notification for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::HandoverRequestAck) => {
            tracing::info!(
                "Processing Handover Request Acknowledgment for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        Some(N2SmInfoType::HandoverPreparationFail) => {
            tracing::warn!(
                "Received Handover Preparation Failure for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
        None => {
            tracing::debug!(
                "Received N2 info notification without SM info type for UE: {}, PDU session: {}",
                ue_id,
                pdu_session_id
            );
        }
    }

    if let Some(ref subscription_id) = payload.n2_notify_subscription_id {
        tracing::debug!(
            "N2 notification subscription ID: {} for UE: {}",
            subscription_id,
            ue_id
        );
    }

    if let Some(ref cell_id) = payload.ng_ran_cell_id {
        tracing::debug!(
            "NG-RAN cell ID: {} for UE: {}",
            cell_id,
            ue_id
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug)]
pub enum AppError {
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(serde_json::json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::InternalError(err.to_string())
    }
}
