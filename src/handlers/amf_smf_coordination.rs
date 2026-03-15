use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::db::AppState;
use crate::services::amf_smf_coordination::AmfSmfCoordinationService;
use crate::types::AppError;
use crate::types::amf_smf_coordination::{
    SmContextRetrieveRequest, SmContextRetrieveResponse,
    SmContextReleaseNotification, SmContextReleaseResponse,
};

// NON-STANDARD: This endpoint does not exist in TS 29.502.
// It is a custom inter-SMF coordination API used during AMF-driven context transfer.
// In 3GPP, SM context transfer is initiated by the target SMF calling
// POST /sm-contexts (with smfTransferInd=true) on the source SMF.
pub async fn retrieve_sm_context_for_amf(
    State(state): State<AppState>,
    Json(payload): Json<SmContextRetrieveRequest>,
) -> Result<Json<SmContextRetrieveResponse>, AppError> {
    tracing::info!(
        "AMF SM context retrieval request - SUPI: {}, PDU Session ID: {}",
        payload.supi,
        payload.pdu_session_id
    );

    let source_smf_id = std::env::var("NF_INSTANCE_ID")
        .unwrap_or_else(|_| "default-source-smf".to_string());

    let pfcp_client = state
        .pfcp_client
        .clone()
        .ok_or_else(|| AppError::InternalError("PFCP client not initialized".to_string()))?;

    let coordination_service =
        AmfSmfCoordinationService::new(state.db.clone(), pfcp_client, source_smf_id);

    match coordination_service.retrieve_sm_context(payload).await {
        Ok(response) => {
            match response.result {
                crate::types::SmContextRetrieveResult::Success => {
                    tracing::info!(
                        "SM context retrieved successfully for AMF - SUPI: {}, PDU Session ID: {}",
                        response.supi,
                        response.pdu_session_id
                    );
                }
                _ => {
                    tracing::warn!(
                        "SM context retrieval failed for AMF - SUPI: {}, Result: {:?}",
                        response.supi,
                        response.result
                    );
                }
            }
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!(
                "Failed to process SM context retrieval for AMF - Error: {}",
                e
            );
            Err(AppError::InternalError(format!(
                "Context retrieval processing failed: {}",
                e
            )))
        }
    }
}

// NON-STANDARD: This endpoint does not exist in TS 29.502.
// It is a custom notification for the source SMF to clean up after a context
// transfer completes. In 3GPP, this is handled by the target SMF calling
// POST /sm-contexts/{ref}/release on the source SMF with cause=SMF_CONTEXT_TRANSFER.
pub async fn release_sm_context_on_transfer(
    State(state): State<AppState>,
    Json(payload): Json<SmContextReleaseNotification>,
) -> Result<Json<SmContextReleaseResponse>, AppError> {
    tracing::info!(
        "AMF SM context release notification - SUPI: {}, PDU Session ID: {}, Target SMF: {}",
        payload.supi,
        payload.pdu_session_id,
        payload.target_smf_id
    );

    let source_smf_id = std::env::var("NF_INSTANCE_ID")
        .unwrap_or_else(|_| "default-source-smf".to_string());

    let pfcp_client = state
        .pfcp_client
        .clone()
        .ok_or_else(|| AppError::InternalError("PFCP client not initialized".to_string()))?;

    let coordination_service =
        AmfSmfCoordinationService::new(state.db.clone(), pfcp_client, source_smf_id);

    match coordination_service.release_sm_context_on_transfer(payload).await {
        Ok(response) => {
            if response.released {
                tracing::info!(
                    "SM context released successfully on AMF notification - Released Resources: {}",
                    response.released_resources.len()
                );
            } else {
                tracing::warn!(
                    "SM context release failed on AMF notification - Context may not exist"
                );
            }
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!(
                "Failed to process SM context release on AMF notification - Error: {}",
                e
            );
            Err(AppError::InternalError(format!(
                "Context release processing failed: {}",
                e
            )))
        }
    }
}
