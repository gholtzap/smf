use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::types::{Snssai, PduSessionType, SmContextState, PduAddress, QosFlow, SscMode, HoState};
use crate::models::{Ambr, SmContext};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextSummary {
    pub sm_context_ref: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: SscMode,
    pub state: SmContextState,
    pub pdu_address: Option<PduAddress>,
    pub qos_flows: Vec<QosFlow>,
    pub session_ambr: Option<Ambr>,
    pub is_emergency: bool,
    pub handover_state: Option<HoState>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<SmContext> for SmContextSummary {
    fn from(ctx: SmContext) -> Self {
        Self {
            sm_context_ref: ctx.id,
            pdu_session_id: ctx.pdu_session_id,
            dnn: ctx.dnn,
            s_nssai: ctx.s_nssai,
            pdu_session_type: ctx.pdu_session_type,
            ssc_mode: ctx.ssc_mode,
            state: ctx.state,
            pdu_address: ctx.pdu_address,
            qos_flows: ctx.qos_flows,
            session_ambr: ctx.session_ambr,
            is_emergency: ctx.is_emergency,
            handover_state: ctx.handover_state,
            created_at: ctx.created_at,
            updated_at: ctx.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SmContextListQuery {
    pub pdu_session_id: Option<u8>,
    pub dnn: Option<String>,
}

pub fn validate_supi(supi: &str) -> Result<(), String> {
    if let Some(digits) = supi.strip_prefix("imsi-") {
        if digits.len() < 5 || digits.len() > 15 {
            return Err(format!("Invalid IMSI length: expected 5-15 digits, got {}", digits.len()));
        }
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err("Invalid IMSI: must contain only digits".to_string());
        }
        return Ok(());
    }

    if let Some(nai) = supi.strip_prefix("nai-") {
        if !nai.contains('@') || nai.starts_with('@') || nai.ends_with('@') {
            return Err("Invalid NAI format: must be username@realm".to_string());
        }
        return Ok(());
    }

    Err("Invalid SUPI format: must start with 'imsi-' or 'nai-'".to_string())
}

pub fn validate_pdu_session_id(id: u8) -> Result<(), String> {
    if id < 1 || id > 15 {
        return Err(format!("Invalid PDU Session ID: must be 1-15, got {}", id));
    }
    Ok(())
}
