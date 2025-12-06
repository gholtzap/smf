use serde::{Deserialize, Serialize};
use super::{Guami, PlmnId, Snssai, RefToBinaryData};
use super::nrf::{Tai, TaiRange};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmfInfo {
    pub amf_set_id: String,
    pub amf_region_id: String,
    pub guami_list: Vec<Guami>,
    pub tai_list: Option<Vec<Tai>>,
    pub tai_range_list: Option<Vec<TaiRange>>,
    pub backup_info_amf_failure: Option<Vec<BackupAmfInfo>>,
    pub backup_info_amf_removal: Option<Vec<BackupAmfInfo>>,
    pub n2_interface_amf_info: Option<N2InterfaceAmfInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupAmfInfo {
    pub backup_amf: String,
    pub guami_list: Option<Vec<Guami>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2InterfaceAmfInfo {
    pub ipv4_endpoint_addresses: Option<Vec<String>>,
    pub ipv6_endpoint_addresses: Option<Vec<String>>,
    pub amf_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AmfSelectionCriteria {
    pub snssai: Option<Snssai>,
    pub plmn_id: Option<PlmnId>,
    pub tai: Option<Tai>,
    pub guami: Option<Guami>,
    pub prefer_local: bool,
}

impl Default for AmfSelectionCriteria {
    fn default() -> Self {
        Self {
            snssai: None,
            plmn_id: None,
            tai: None,
            guami: None,
            prefer_local: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AmfSelectionResult {
    pub nf_instance_id: String,
    pub uri: String,
    pub priority: u16,
    pub capacity: u16,
    pub load: u16,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N1N2MessageTransferRequest {
    pub n1_message_container: Option<N1MessageContainer>,
    pub n2_info_container: Option<N2InfoContainer>,
    pub pdu_session_id: Option<u8>,
    pub lcs_correlation_id: Option<String>,
    pub ppi: Option<u8>,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N1N2MessageTransferResponse {
    pub cause: N1N2MessageTransferCause,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N1N2MessageTransferCause {
    N1N2TransferInitiated,
    AttemptingToReachUe,
    N1MsgNotTransferred,
    UeNotReachable,
    UeNotResponding,
    N1N2TransferError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N1MessageContainer {
    pub n1_message_class: N1MessageClass,
    pub n1_message_content: RefToBinaryData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N1MessageClass {
    Sm,
    Lpp,
    Sms,
    Updp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2InfoContainer {
    pub n2_information_class: N2InformationClass,
    pub sm_info: Option<RefToBinaryData>,
    pub ran_info: Option<RefToBinaryData>,
    pub nrp_pa_info: Option<RefToBinaryData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N2InformationClass {
    Sm,
    Nrppa,
    Pws,
    PwsBcal,
    PwsRf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeContextTransferRequest {
    pub json_data: Option<UeContextTransferReqData>,
    pub binary_data_n2_information: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeContextTransferReqData {
    pub reason: UeContextTransferReason,
    pub access_type: AccessType,
    pub plmn_id: Option<PlmnId>,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UeContextTransferReason {
    UeContextTransfer,
    InitialRegistration,
    EmergencyRegistration,
    PeriodicRegistration,
    MobilityRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessType {
    #[serde(rename = "3GPP_ACCESS")]
    ThreeGppAccess,
    #[serde(rename = "NON_3GPP_ACCESS")]
    NonThreeGppAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeContextTransferResponse {
    pub json_data: Option<UeContextTransferRspData>,
    pub binary_data_n2_information: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeContextTransferRspData {
    pub ue_context: Option<UeContext>,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeContext {
    pub supi: String,
    pub supi_unauth_ind: Option<bool>,
    pub gpsi_list: Option<Vec<String>>,
    pub pei: Option<String>,
    pub mm_context: Option<MmContext>,
    pub session_context_list: Option<Vec<PduSessionContext>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MmContext {
    pub access_type: AccessType,
    pub nas_security_mode: Option<NasSecurityMode>,
    pub allowed_nssai: Option<Vec<Snssai>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NasSecurityMode {
    pub integrity_algorithm: IntegrityAlgorithm,
    pub ciphering_algorithm: CipheringAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityAlgorithm {
    Nia0,
    Nia1,
    Nia2,
    Nia3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CipheringAlgorithm {
    Nea0,
    Nea1,
    Nea2,
    Nea3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionContext {
    pub pdu_session_id: u8,
    pub sm_context_ref: String,
    pub s_nssai: Snssai,
    pub dnn: String,
}

pub type BinaryData = Vec<u8>;
pub type MultipartBody = HashMap<String, MultipartPart>;

#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub content_type: String,
    pub data: BinaryData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N1N2MessageTransferStatusNotification {
    pub status_info: N1N2MessageTransferStatusInfo,
    pub n1_message_container: Option<N1MessageContainer>,
    pub n2_info_container: Option<N2InfoContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N1N2MessageTransferStatusInfo {
    pub status: N1N2MessageTransferStatus,
    pub cause: Option<N1N2MessageTransferCause>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N1N2MessageTransferStatus {
    Success,
    Failure,
    PartialSuccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2InfoNotification {
    pub n2_info_container: N2InfoContainer,
    pub n2_notify_subscription_id: Option<String>,
    pub sm_info_type: Option<N2SmInfoType>,
    pub ng_ran_cell_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N2SmInfoType {
    PduResSetupRsp,
    PduResSetupFail,
    PduResModifyRsp,
    PduResModifyFail,
    PduResReleaseCmd,
    PduResReleaseRsp,
    PduResNotifyRel,
    PathSwitchRequestAck,
    PathSwitchRequestFail,
    HandoverRequired,
    HandoverRequestAck,
    HandoverPreparationFail,
}
