use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures::TryStreamExt;
use mongodb::bson::doc;
use mongodb::Collection;
use crate::db::AppState;
use crate::models::SmContext;
use crate::types::{AppError, N1N2MsgTxfrFailureNotification, N1N2MessageTransferCause, N2InfoNotification, N2SmInfoType, SmContextState};
use crate::services::pfcp_session::PfcpSessionManager;

pub async fn handle_n1n2_transfer_status(
    State(state): State<AppState>,
    Path((ue_id, transaction_id)): Path<(String, String)>,
    Json(payload): Json<N1N2MsgTxfrFailureNotification>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "N1N2 transfer failure for UE: {}, txn: {}, cause: {:?}, uri: {}",
        ue_id, transaction_id, payload.cause, payload.n1n2_msg_data_uri
    );

    if let Some(retry_after) = payload.retry_after {
        tracing::info!(
            "AMF suggests retry after {} seconds for UE: {}, txn: {}",
            retry_after, ue_id, transaction_id
        );
    }

    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let supi = if ue_id.starts_with("imsi-") || ue_id.starts_with("nai-") {
        ue_id.clone()
    } else {
        format!("imsi-{}", ue_id)
    };

    let filter = doc! { "supi": &supi };
    let contexts: Vec<SmContext> = collection
        .find(filter)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .try_collect()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if contexts.is_empty() {
        tracing::warn!(
            "No SM contexts found for UE {} on N1N2 failure notification, txn: {}",
            supi, transaction_id
        );
        return Ok(StatusCode::NO_CONTENT);
    }

    match payload.cause {
        N1N2MessageTransferCause::UeNotResponding
        | N1N2MessageTransferCause::UeNotReachableForSession
        | N1N2MessageTransferCause::RejectionDueToPagingRestriction => {
            tracing::warn!(
                "UE {} unreachable (cause: {:?}), deactivating user plane for {} session(s)",
                supi, payload.cause, contexts.len()
            );

            for ctx in &contexts {
                if let Some(pfcp_seid) = ctx.pfcp_session_id {
                    if let Some(ref pfcp_client) = state.pfcp_client {
                        if let Err(e) = PfcpSessionManager::deactivate_downlink(
                            pfcp_client, pfcp_seid,
                        ).await {
                            tracing::error!(
                                "Failed to deactivate DL for SUPI: {}, PSI: {}, SEID: {}: {}",
                                ctx.supi, ctx.pdu_session_id, pfcp_seid, e
                            );
                        }
                    }
                }

                collection
                    .update_one(
                        doc! { "_id": &ctx.id },
                        doc! { "$set": {
                            "state": mongodb::bson::to_bson(&SmContextState::Inactive)
                                .unwrap_or(mongodb::bson::Bson::String("INACTIVE".to_string())),
                            "updated_at": mongodb::bson::DateTime::now()
                        }},
                    )
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
            }
        }

        N1N2MessageTransferCause::AnNotResponding => {
            tracing::error!(
                "AN not responding for UE {}, deactivating user plane for {} session(s)",
                supi, contexts.len()
            );

            for ctx in &contexts {
                if let Some(pfcp_seid) = ctx.pfcp_session_id {
                    if let Some(ref pfcp_client) = state.pfcp_client {
                        if let Err(e) = PfcpSessionManager::deactivate_downlink(
                            pfcp_client, pfcp_seid,
                        ).await {
                            tracing::error!(
                                "Failed to deactivate DL for SUPI: {}, PSI: {}: {}",
                                ctx.supi, ctx.pdu_session_id, e
                            );
                        }
                    }
                }

                collection
                    .update_one(
                        doc! { "_id": &ctx.id },
                        doc! { "$set": {
                            "state": mongodb::bson::to_bson(&SmContextState::Inactive)
                                .unwrap_or(mongodb::bson::Bson::String("INACTIVE".to_string())),
                            "updated_at": mongodb::bson::DateTime::now()
                        }},
                    )
                    .await
                    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
            }
        }

        N1N2MessageTransferCause::N1MsgNotTransferred
        | N1N2MessageTransferCause::N2MsgNotTransferred => {
            tracing::error!(
                "N1/N2 message not transferred for UE {} (cause: {:?}), txn: {}",
                supi, payload.cause, transaction_id
            );

            for ctx in &contexts {
                if ctx.state == SmContextState::ActivePending {
                    tracing::warn!(
                        "Session setup failed for SUPI: {}, PSI: {} - N1/N2 not delivered",
                        ctx.supi, ctx.pdu_session_id
                    );
                }
            }
        }

        N1N2MessageTransferCause::TemporaryRejectRegistrationOngoing
        | N1N2MessageTransferCause::TemporaryRejectHandoverOngoing => {
            tracing::info!(
                "Temporary reject for UE {} (cause: {:?}), retry_after: {:?}",
                supi, payload.cause, payload.retry_after
            );
        }

        N1N2MessageTransferCause::AttemptingToReachUe
        | N1N2MessageTransferCause::WaitingForAsynchronousTransfer => {
            tracing::debug!(
                "AMF still processing for UE {} (cause: {:?}), txn: {}",
                supi, payload.cause, transaction_id
            );
        }

        N1N2MessageTransferCause::N1N2TransferInitiated => {
            tracing::debug!(
                "N1N2 transfer initiated for UE {}, txn: {}",
                supi, transaction_id
            );
        }

        N1N2MessageTransferCause::FailureCauseUnspecified => {
            tracing::error!(
                "Unspecified N1N2 transfer failure for UE {}, txn: {}",
                supi, transaction_id
            );
        }
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
