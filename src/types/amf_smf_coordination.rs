use serde::{Deserialize, Serialize};
use super::sm_context_transfer::SmContextData;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrieveRequest {
    pub supi: String,
    pub pdu_session_id: u8,
    pub target_smf_id: String,
    pub target_smf_set_id: Option<String>,
    pub ho_state: Option<String>,
    pub cause: SmContextRetrieveCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextRetrieveCause {
    InterSmfHandover,
    SmfChange,
    SmfRelocation,
    AmfInitiatedChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrieveResponse {
    pub supi: String,
    pub pdu_session_id: u8,
    pub sm_context_data: Option<SmContextData>,
    pub result: SmContextRetrieveResult,
    pub failure_cause: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextRetrieveResult {
    Success,
    ContextNotFound,
    InvalidState,
    TransferNotAllowed,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextCreateWithTransferRequest {
    pub sm_context_create_data: crate::models::PduSessionCreateData,
    pub source_sm_context: Option<SmContextData>,
    pub source_smf_id: Option<String>,
    pub transfer_cause: Option<super::sm_context_transfer::TransferCause>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextReleaseNotification {
    pub supi: String,
    pub pdu_session_id: u8,
    pub target_smf_id: String,
    pub target_sm_context_ref: String,
    pub release_cause: SmContextReleaseCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextReleaseCause {
    SmfChange,
    SmfRelocation,
    TransferCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextReleaseResponse {
    pub released: bool,
    pub released_resources: Vec<String>,
}
