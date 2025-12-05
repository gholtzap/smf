use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{bson::doc, Collection};
use futures::TryStreamExt;
use crate::db::AppState;
use crate::models::{Ambr, PduSessionCreateData, PduSessionCreatedData, PduSessionReleaseData, PduSessionReleasedData, PduSessionUpdateData, PduSessionUpdatedData, SmContext};
use crate::types::{N2SmInfo, N2InfoContent, NgapIeType, PduAddress, PduSessionType, QosFlow};
use crate::services::pfcp_session::PfcpSessionManager;
use crate::services::ipam::IpamService;
use crate::services::qos_flow::QosFlowManager;
use std::sync::Arc;

pub async fn create_pdu_session(
    State(state): State<AppState>,
    Json(payload): Json<PduSessionCreateData>,
) -> Result<Json<PduSessionCreatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let slice_config = state
        .slice_selector
        .validate_snssai(&payload.s_nssai)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "S-NSSAI validated for SUPI: {}, Slice: {} (SST: {}, SD: {:?})",
        payload.supi,
        slice_config.slice_name,
        payload.s_nssai.sst,
        payload.s_nssai.sd
    );

    let dnn_config = state
        .dnn_selector
        .validate_dnn(&payload.dnn)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "DNN validated for SUPI: {}, DNN: {}, Description: {}",
        payload.supi,
        dnn_config.dnn,
        dnn_config.description
    );

    let existing = collection
        .find_one(doc! { "supi": &payload.supi, "pdu_session_id": payload.pdu_session_id as i32 })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if existing.is_some() {
        return Err(AppError::ValidationError(format!(
            "PDU Session already exists for SUPI {} with PDU Session ID {}",
            payload.supi, payload.pdu_session_id
        )));
    }

    let mut sm_context = SmContext::new(&payload);

    let default_5qi = dnn_config.default_5qi
        .or(slice_config.default_5qi)
        .unwrap_or(9);

    sm_context.qos_flows = vec![QosFlow::new_with_5qi(1, default_5qi)];
    tracing::debug!(
        "Applied default 5QI: {} for DNN: {}, Slice: {}",
        default_5qi,
        dnn_config.dnn,
        slice_config.slice_name
    );

    let ip_pool_name = &dnn_config.ip_pool_name;
    let ip_allocation = IpamService::allocate_ip(
        &state.db,
        ip_pool_name,
        &sm_context.id,
        &payload.supi,
    )
    .await
    .map_err(|e| AppError::ValidationError(format!("IP allocation failed: {}", e)))?;

    sm_context.pdu_address = Some(PduAddress {
        pdu_session_type: PduSessionType::Ipv4,
        ipv4_addr: Some(ip_allocation.ip_address.clone()),
        ipv6_addr: None,
        dns_primary: ip_allocation.dns_primary.clone(),
        dns_secondary: ip_allocation.dns_secondary.clone(),
    });

    let ue_ipv4 = ip_allocation.ip_address.parse().map_err(|e| {
        AppError::ValidationError(format!("Invalid UE IPv4 address: {}", e))
    })?;

    if let Some(ref pcf_client) = state.pcf_client {
        let pcf_uri = std::env::var("PCF_URI").unwrap_or_default();

        let notification_uri = format!(
            "http://{}:{}/npcf-callback/v1/sm-policy-notify/{}",
            std::env::var("SMF_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()),
            sm_context.id
        );

        let context_data = crate::types::pcf::SmPolicyContextData {
            supi: payload.supi.clone(),
            pdu_session_id: payload.pdu_session_id,
            dnn: payload.dnn.clone(),
            slice_info: payload.s_nssai.clone(),
            notification_uri,
            ipv4_address: Some(ip_allocation.ip_address.clone()),
            ipv6_address_prefix: None,
            ip_domain: None,
            subs_sess_ambr: None,
            auth_prof_index: None,
            subs_def_qos: None,
            num_of_pack_filter: None,
            online: Some(true),
            offline: Some(false),
            access_type: Some(crate::types::pcf::AccessType::Gpe3gppAccess),
            rat_type: Some(crate::types::pcf::RatType::Nr),
            servingNetwork: None,
            user_location_info: None,
            ue_time_zone: None,
            pei: None,
            ipv4_frame_route_list: None,
            ipv6_frame_route_list: None,
            supp_feat: None,
        };

        match pcf_client.create_sm_policy(&pcf_uri, context_data).await {
            Ok((policy_id, policy_decision)) => {
                sm_context.pcf_policy_id = Some(policy_id.clone());
                tracing::info!(
                    "SM policy created for SUPI: {}, Policy ID: {}",
                    payload.supi,
                    policy_id
                );

                if let Some(ref sess_rules) = policy_decision.sess_rules {
                    tracing::debug!("Received {} session rules from PCF", sess_rules.len());
                }

                if let Some(ref pcc_rules) = policy_decision.pcc_rules {
                    tracing::debug!("Received {} PCC rules from PCF", pcc_rules.len());
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create SM policy for SUPI: {}: {}, continuing without PCF policy",
                    payload.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PCF client not available, skipping SM policy creation");
    }

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
            &sm_context.qos_flows,
        ).await {
            Ok(_) => {
                sm_context.pfcp_session_id = Some(seid);
                sm_context.state = crate::types::SmContextState::Active;
                tracing::info!(
                    "PFCP Session established for SUPI: {}, SEID: {}, State: Active",
                    payload.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to establish PFCP session for SUPI: {}: {}, State remains: ActivePending",
                    payload.supi,
                    e
                );
            }
        }
    } else {
        sm_context.state = crate::types::SmContextState::Active;
        tracing::debug!("PFCP client not available, skipping PFCP session establishment, State: Active");
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
        ue_ipv4_address: Some(ip_allocation.ip_address.clone()),
        ue_ipv6_prefix: None,
        dns_primary: ip_allocation.dns_primary.clone(),
        dns_secondary: ip_allocation.dns_secondary.clone(),
        n1_sm_info_to_ue: None,
        eps_pdn_cnx_info: None,
        supported_features: None,
        session_ambr: Some(Ambr {
            uplink: dnn_config.default_session_ambr_uplink.clone(),
            downlink: dnn_config.default_session_ambr_downlink.clone(),
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
        "Created PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}, DNN: {}, Slice: {} (SST: {}, SD: {:?})",
        payload.supi,
        payload.pdu_session_id,
        sm_context.id,
        dnn_config.dnn,
        slice_config.slice_name,
        payload.s_nssai.sst,
        payload.s_nssai.sd
    );

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::UeIpChange,
        &payload.supi,
        payload.pdu_session_id,
        Some(payload.dnn.clone()),
        Some(payload.s_nssai.clone()),
        Some(ip_allocation.ip_address.clone()),
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

    let mut new_state = crate::types::SmContextState::Active;

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::ModificationPending).unwrap(),
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let qos_mgr = QosFlowManager::new(Arc::new(state.db.clone()));

    let mut add_qos_flows: Vec<QosFlow> = Vec::new();
    let mut remove_qfis: Vec<u8> = Vec::new();

    if let Some(ref qos_flows_add_mod) = payload.qos_flows_add_mod_request_list {
        for qf_item in qos_flows_add_mod {
            let qos_flow = if let Some(ref profile) = qf_item.qos_profile {
                QosFlow::new_with_5qi(qf_item.qfi, profile.five_qi)
            } else {
                QosFlow::new_default(qf_item.qfi)
            };
            add_qos_flows.push(qos_flow.clone());
        }

        if !add_qos_flows.is_empty() {
            if let Err(e) = qos_mgr.add_qos_flows(&sm_context_ref, add_qos_flows.clone()).await {
                tracing::warn!("Failed to add QoS flows: {}", e);
            }
        }
    }

    if let Some(ref qos_flows_rel) = payload.qos_flows_rel_request_list {
        for qf_item in qos_flows_rel {
            remove_qfis.push(qf_item.qfi);
        }

        if !remove_qfis.is_empty() {
            if let Err(e) = qos_mgr.remove_qos_flows(&sm_context_ref, remove_qfis.clone()).await {
                tracing::warn!("Failed to remove QoS flows: {}", e);
            }
        }
    }

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let add_flows_opt = if !add_qos_flows.is_empty() { Some(add_qos_flows.as_slice()) } else { None };
        let remove_qfis_opt = if !remove_qfis.is_empty() { Some(remove_qfis.as_slice()) } else { None };

        match PfcpSessionManager::modify_session(pfcp_client, seid, None, add_flows_opt, remove_qfis_opt).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP Session modified for SUPI: {}, SEID: {}, State: ModificationPending -> Active",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                new_state = crate::types::SmContextState::ModificationPending;
                tracing::warn!(
                    "Failed to modify PFCP session for SUPI: {}: {}, State remains: ModificationPending",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client or session ID not available, skipping PFCP session modification, State: ModificationPending -> Active");
    }

    let updated_ambr = payload.session_ambr.clone().or(Some(Ambr {
        uplink: "100 Mbps".to_string(),
        downlink: "100 Mbps".to_string(),
    }));

    let update_doc = doc! {
        "$set": {
            "state": mongodb::bson::to_bson(&new_state).unwrap(),
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

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::InactivePending).unwrap(),
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        match PfcpSessionManager::delete_session(pfcp_client, seid).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP Session deleted for SUPI: {}, SEID: {}, State: InactivePending -> Deleted",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete PFCP session for SUPI: {}: {}, proceeding with SM Context deletion",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client or session ID not available, skipping PFCP session deletion, State: InactivePending -> Deleted");
    }

    if let (Some(ref pcf_client), Some(ref policy_id)) = (&state.pcf_client, &sm_context.pcf_policy_id) {
        let pcf_uri = std::env::var("PCF_URI").unwrap_or_default();

        match pcf_client.delete_sm_policy(&pcf_uri, policy_id).await {
            Ok(_) => {
                tracing::info!(
                    "SM policy deleted for SUPI: {}, Policy ID: {}",
                    sm_context.supi,
                    policy_id
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete SM policy for SUPI: {}: {}, proceeding with SM Context deletion",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PCF client or policy ID not available, skipping SM policy deletion");
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

    IpamService::release_ip(&state.db, &sm_context_ref)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to release IP for SM Context {}: {}", sm_context_ref, e);
        })
        .ok();

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

pub async fn list_ue_pdu_sessions(
    State(state): State<AppState>,
    Path(supi): Path<String>,
) -> Result<Json<Vec<SmContext>>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sessions: Vec<SmContext> = collection
        .find(doc! { "supi": &supi })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .try_collect()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Retrieved {} PDU sessions for SUPI: {}",
        sessions.len(),
        supi
    );

    Ok(Json(sessions))
}

pub async fn retrieve_pdu_session_by_supi(
    State(state): State<AppState>,
    Path((supi, pdu_session_id)): Path<(String, u8)>,
) -> Result<Json<SmContext>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "supi": &supi, "pdu_session_id": pdu_session_id as i32 })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!(
            "SM Context not found for SUPI {} with PDU Session ID {}",
            supi, pdu_session_id
        )))?;

    tracing::info!(
        "Retrieved PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        supi,
        pdu_session_id,
        sm_context.id
    );

    Ok(Json(sm_context))
}
