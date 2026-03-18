use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose;
use base64::Engine;
use futures::TryStreamExt;
use mongodb::bson::doc;
use mongodb::Collection;
use crate::db::AppState;
use crate::models::SmContext;
use crate::types::{AppError, N1N2MsgTxfrFailureNotification, N1N2MessageTransferCause, N2InformationNotification, N2InformationClass, N2InfoNotifyReason, SmContextState};
use crate::services::pfcp_session::PfcpSessionManager;
use crate::services::ipam::IpamService;

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
    State(state): State<AppState>,
    Path((ue_id, pdu_session_id)): Path<(String, u8)>,
    Json(payload): Json<N2InformationNotification>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "N2 info notification for UE: {}, PSI: {}, sub_id: {}, reason: {:?}",
        ue_id, pdu_session_id, payload.n2_notify_subscription_id, payload.notify_reason
    );

    let supi = if ue_id.starts_with("imsi-") || ue_id.starts_with("nai-") {
        ue_id.clone()
    } else {
        format!("imsi-{}", ue_id)
    };

    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    if let Some(ref reason) = payload.notify_reason {
        if *reason == N2InfoNotifyReason::HandoverCompleted {
            return handle_n2_handover_completed(&collection, &supi, pdu_session_id).await;
        }
    }

    if let Some(ref release_list) = payload.to_release_session_list {
        return handle_n2_release_sessions(&state, &collection, &supi, release_list).await;
    }

    let container = match payload.n2_info_container {
        Some(ref c) => c,
        None => {
            tracing::debug!("N2 info notification with no container for UE: {}", supi);
            return Ok(StatusCode::NO_CONTENT);
        }
    };

    match container.n2_information_class {
        N2InformationClass::SM => {
            let sm_info = container.sm_info.as_ref().ok_or_else(|| {
                AppError::ValidationError("SM info required for SM class notification".into())
            })?;

            let sm_context = collection
                .find_one(doc! { "supi": &supi, "pdu_session_id": pdu_session_id as i32 })
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?
                .ok_or_else(|| AppError::NotFound(format!(
                    "SM Context not found for SUPI: {}, PSI: {}", supi, pdu_session_id
                )))?;

            let n2_content = sm_info.n2_info_content.as_ref();
            let ngap_ie_type = n2_content
                .and_then(|c| c.ngap_ie_type.as_deref())
                .unwrap_or("");

            match ngap_ie_type {
                "PDU_RES_SETUP_RSP" => {
                    handle_n2_notify_setup_response(&state, &collection, &sm_context, n2_content).await?;
                }
                "PDU_RES_SETUP_FAIL" | "PDU_RES_SETUP_REQ" => {
                    handle_n2_notify_setup_failure(&state, &collection, &sm_context).await?;
                }
                "PDU_RES_REL_RSP" => {
                    handle_n2_notify_release_response(&state, &collection, &sm_context).await?;
                }
                "SECONDARY_RAT_USAGE" => {
                    tracing::info!(
                        "Secondary RAT usage report for SUPI: {}, PSI: {}",
                        sm_context.supi, sm_context.pdu_session_id
                    );
                }
                other => {
                    tracing::info!(
                        "N2 SM notification IE type '{}' for SUPI: {}, PSI: {}",
                        other, sm_context.supi, sm_context.pdu_session_id
                    );
                }
            }
        }
        ref other => {
            tracing::info!("N2 info notification class: {:?} for UE: {}", other, supi);
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn handle_n2_handover_completed(
    collection: &Collection<SmContext>,
    supi: &str,
    pdu_session_id: u8,
) -> Result<StatusCode, AppError> {
    tracing::info!("Handover completed for SUPI: {}, PSI: {}", supi, pdu_session_id);

    let result = collection
        .update_one(
            doc! { "supi": supi, "pdu_session_id": pdu_session_id as i32 },
            doc! { "$set": {
                "handover_state": mongodb::bson::Bson::Null,
                "source_an_tunnel_info": mongodb::bson::Bson::Null,
                "state": mongodb::bson::to_bson(&SmContextState::Active)
                    .unwrap_or(mongodb::bson::Bson::String("ACTIVE".into())),
                "updated_at": mongodb::bson::DateTime::now()
            }},
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if result.matched_count == 0 {
        tracing::warn!("No SM context found for handover completion: SUPI={}, PSI={}", supi, pdu_session_id);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn handle_n2_release_sessions(
    state: &AppState,
    collection: &Collection<SmContext>,
    supi: &str,
    session_ids: &[u8],
) -> Result<StatusCode, AppError> {
    tracing::info!("N2 release notification for SUPI: {}, sessions: {:?}", supi, session_ids);

    for &psi in session_ids {
        let ctx = collection
            .find_one(doc! { "supi": supi, "pdu_session_id": psi as i32 })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        if let Some(ctx) = ctx {
            if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, ctx.pfcp_session_id) {
                if let Err(e) = PfcpSessionManager::delete_session(pfcp_client, seid).await {
                    tracing::warn!("Failed to delete PFCP session for SUPI: {}, PSI: {}: {}", supi, psi, e);
                }
            }

            IpamService::release_ip(&state.db, &ctx.id).await.ok();

            collection
                .delete_one(doc! { "_id": &ctx.id })
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;

            tracing::info!("Released SM context for SUPI: {}, PSI: {}", supi, psi);
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn handle_n2_notify_setup_response(
    state: &AppState,
    collection: &Collection<SmContext>,
    sm_context: &SmContext,
    n2_content: Option<&crate::types::N2InfoContentAmf>,
) -> Result<(), AppError> {
    let content = n2_content.ok_or_else(|| {
        AppError::ValidationError("N2 info content required for setup response".into())
    })?;

    let decoded_bytes = general_purpose::STANDARD
        .decode(&content.ngap_data.content_id)
        .map_err(|e| AppError::ValidationError(format!("Failed to decode NGAP data: {}", e)))?;

    let parser = crate::parsers::ngap::NgapParser::new();
    let response_transfer = parser
        .extract_pdu_session_resource_setup_response_transfer(&decoded_bytes)
        .map_err(|e| AppError::ValidationError(format!("Failed to parse setup response transfer: {}", e)))?;

    let gtp_tunnel = &response_transfer.dl_qos_flow_per_tnl_information.up_transport_layer_information;
    let ipv4_addr = gtp_tunnel.get_ip_address();
    let teid = gtp_tunnel.get_teid()
        .ok_or_else(|| AppError::ValidationError("Failed to extract GTP TEID".into()))?;
    let teid_hex = format!("{:08x}", teid);

    let an_tunnel_info = crate::models::TunnelInfo {
        ipv4_addr: ipv4_addr.clone(),
        ipv6_addr: None,
        gtp_teid: teid_hex.clone(),
    };

    tracing::info!(
        "N2 notify setup response - gNB tunnel: TEID={}, IP={:?} for SUPI: {}, PSI: {}",
        teid_hex, ipv4_addr, sm_context.supi, sm_context.pdu_session_id
    );

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let an_ipv4_str = ipv4_addr.as_ref()
            .ok_or_else(|| AppError::ValidationError("gNB IPv4 address required".into()))?;
        let an_ipv4 = an_ipv4_str.parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid gNB IPv4 address: {}", e))
        })?;

        PfcpSessionManager::modify_session_for_handover(
            pfcp_client, seid, an_ipv4, &teid_hex,
            sm_context.up_security_context.as_ref(), false,
        ).await.map_err(|e| {
            AppError::InternalError(format!("Failed to activate DL FAR: {}", e))
        })?;
    }

    collection
        .update_one(
            doc! { "_id": &sm_context.id },
            doc! { "$set": {
                "an_tunnel_info": mongodb::bson::to_bson(&an_tunnel_info)
                    .map_err(|e| AppError::DatabaseError(format!("BSON error: {}", e)))?,
                "state": mongodb::bson::to_bson(&SmContextState::Active)
                    .map_err(|e| AppError::DatabaseError(format!("BSON error: {}", e)))?,
                "updated_at": mongodb::bson::DateTime::now()
            }},
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(())
}

async fn handle_n2_notify_setup_failure(
    state: &AppState,
    collection: &Collection<SmContext>,
    sm_context: &SmContext,
) -> Result<(), AppError> {
    tracing::warn!(
        "N2 notify setup failure for SUPI: {}, PSI: {}",
        sm_context.supi, sm_context.pdu_session_id
    );

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        if let Err(e) = PfcpSessionManager::delete_session(pfcp_client, seid).await {
            tracing::warn!("Failed to delete PFCP session: {}", e);
        }
    }

    IpamService::release_ip(&state.db, &sm_context.id).await.ok();

    collection
        .delete_one(doc! { "_id": &sm_context.id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(())
}

async fn handle_n2_notify_release_response(
    state: &AppState,
    collection: &Collection<SmContext>,
    sm_context: &SmContext,
) -> Result<(), AppError> {
    tracing::info!(
        "N2 notify release response for SUPI: {}, PSI: {}",
        sm_context.supi, sm_context.pdu_session_id
    );

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        if let Err(e) = PfcpSessionManager::delete_session(pfcp_client, seid).await {
            tracing::warn!("Failed to delete PFCP session: {}", e);
        }
    }

    IpamService::release_ip(&state.db, &sm_context.id).await.ok();

    collection
        .delete_one(doc! { "_id": &sm_context.id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(())
}
