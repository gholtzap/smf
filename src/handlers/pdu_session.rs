use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{bson::doc, Collection};
use crate::db::AppState;
use crate::models::{Ambr, PduSessionCreateData, PduSessionCreatedData, PduSessionReleaseData, PduSessionReleasedData, PduSessionUpdateData, PduSessionUpdatedData, SmContext};
use crate::types::{N2SmInfo, N2InfoContent, NgapIeType, PduSessionType};
use crate::services::pfcp_session::PfcpSessionManager;

pub async fn create_pdu_session(
    State(state): State<AppState>,
    Json(payload): Json<PduSessionCreateData>,
) -> Result<Json<PduSessionCreatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let mut sm_context = SmContext::new(&payload);

    let ue_ipv4_address = "10.0.0.1".to_string();
    let ue_ipv4 = ue_ipv4_address.parse().map_err(|e| {
        AppError::ValidationError(format!("Invalid UE IPv4 address: {}", e))
    })?;

    if let Some(ref pfcp_client) = state.pfcp_client {
        let seid = PfcpSessionManager::generate_seid(&sm_context.id, payload.pdu_session_id);

        let upf_ipv4 = pfcp_client.upf_address().ip().to_string().parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid UPF IPv4 address: {}", e))
        })?;

        match PfcpSessionManager::establish_session(
            pfcp_client,
            seid,
            ue_ipv4,
            upf_ipv4,
        ).await {
            Ok(_) => {
                sm_context.pfcp_session_id = Some(seid);
                tracing::info!(
                    "PFCP Session established for SUPI: {}, SEID: {}",
                    payload.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to establish PFCP session for SUPI: {}: {}",
                    payload.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client not available, skipping PFCP session establishment");
    }

    collection
        .insert_one(&sm_context)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response = PduSessionCreatedData {
        pdu_session_type: PduSessionType::Ipv4,
        ssc_mode: "1".to_string(),
        h_smf_uri: None,
        smf_uri: Some(format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context.id)),
        pdu_session_id: payload.pdu_session_id,
        s_nssai: payload.s_nssai.clone(),
        enable_pause_charging: Some(false),
        ue_ipv4_address: Some(ue_ipv4_address.clone()),
        ue_ipv6_prefix: None,
        n1_sm_info_to_ue: None,
        eps_pdn_cnx_info: None,
        supported_features: None,
        session_ambr: Some(Ambr {
            uplink: "100 Mbps".to_string(),
            downlink: "100 Mbps".to_string(),
        }),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        dnai_list: None,
        n2_sm_info: Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResSetupReq,
                ngap_data: "base64_encoded_ngap_data".to_string(),
            },
        }),
        n2_sm_info_type: Some(crate::models::N2SmInfoType::PduResSetupReq),
        sm_context_ref: sm_context.id.clone(),
    };

    tracing::info!(
        "Created PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        payload.supi,
        payload.pdu_session_id,
        sm_context.id
    );

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::UeIpChange,
        &payload.supi,
        payload.pdu_session_id,
        Some(payload.dnn.clone()),
        Some(payload.s_nssai.clone()),
        Some(ue_ipv4_address.clone()),
        None,
        Some(sm_context.id.clone()),
        None,
    ).await;

    Ok(Json(response))
}

pub async fn retrieve_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
) -> Result<Json<SmContext>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    tracing::info!(
        "Retrieved PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context.id
    );

    Ok(Json(sm_context))
}

pub async fn update_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<PduSessionUpdateData>,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        match PfcpSessionManager::modify_session(pfcp_client, seid, None).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP Session modified for SUPI: {}, SEID: {}",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to modify PFCP session for SUPI: {}: {}",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client or session ID not available, skipping PFCP session modification");
    }

    let updated_ambr = payload.session_ambr.clone().or(Some(Ambr {
        uplink: "100 Mbps".to_string(),
        downlink: "100 Mbps".to_string(),
    }));

    let update_doc = doc! {
        "$set": {
            "updated_at": mongodb::bson::DateTime::now()
        }
    };

    collection
        .update_one(doc! { "_id": &sm_context_ref }, update_doc)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response = PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n2_sm_info: payload.n2_sm_info.or(Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResModifyReq,
                ngap_data: "base64_encoded_ngap_data".to_string(),
            },
        })),
        n2_sm_info_type: payload.n2_sm_info_type.or(Some(crate::models::N2SmInfoType::PduResSetupReq)),
        eps_bearer_info: None,
        supported_features: None,
        session_ambr: updated_ambr,
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
    };

    tracing::info!(
        "Updated PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(Json(response))
}

pub async fn release_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<PduSessionReleaseData>,
) -> Result<Json<PduSessionReleasedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        match PfcpSessionManager::delete_session(pfcp_client, seid).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP Session deleted for SUPI: {}, SEID: {}",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete PFCP session for SUPI: {}: {}",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client or session ID not available, skipping PFCP session deletion");
    }

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::PduSesRelease,
        &sm_context.supi,
        sm_context.pdu_session_id,
        Some(sm_context.dnn.clone()),
        Some(sm_context.s_nssai.clone()),
        None,
        None,
        Some(sm_context_ref.clone()),
        Some(crate::types::Cause::RegularDeactivation),
    ).await;

    collection
        .delete_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response = PduSessionReleasedData {
        n1_sm_info_to_ue: None,
        n2_sm_info: payload.n2_sm_info.or(Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResRelCmd,
                ngap_data: "base64_encoded_ngap_data".to_string(),
            },
        })),
        n2_sm_info_type: payload.n2_sm_info_type.or(Some(crate::models::N2SmInfoType::PduResRelCmd)),
    };

    tracing::info!(
        "Released PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(Json(response))
}

#[derive(Debug)]
pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    NotFound(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (status, message).into_response()
    }
}
