use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{bson::doc, Collection};
use crate::db::AppState;
use crate::models::{Ambr, PduSessionCreateData, PduSessionCreatedData, SmContext};
use crate::types::{N2SmInfo, N2InfoContent, NgapIeType, PduSessionType};

pub async fn create_pdu_session(
    State(db): State<AppState>,
    Json(payload): Json<PduSessionCreateData>,
) -> Result<Json<PduSessionCreatedData>, AppError> {
    let collection: Collection<SmContext> = db.collection("sm_contexts");

    let sm_context = SmContext::new(&payload);

    collection
        .insert_one(&sm_context)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let ue_ipv4_address = "10.0.0.1".to_string();

    let response = PduSessionCreatedData {
        pdu_session_type: PduSessionType::Ipv4,
        ssc_mode: "1".to_string(),
        h_smf_uri: None,
        smf_uri: Some(format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context.id)),
        pdu_session_id: payload.pdu_session_id,
        s_nssai: payload.s_nssai.clone(),
        enable_pause_charging: Some(false),
        ue_ipv4_address: Some(ue_ipv4_address),
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

    Ok(Json(response))
}

pub async fn retrieve_pdu_session(
    State(db): State<AppState>,
    Path(sm_context_ref): Path<String>,
) -> Result<Json<SmContext>, AppError> {
    let collection: Collection<SmContext> = db.collection("sm_contexts");

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
