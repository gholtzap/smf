use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::models::{Ambr, RequestType, TunnelInfo, UserLocation};
use crate::types::{
    Guami, HoState, PacketFilter, PduAddress, PduSessionType, QosFlow, QosRule,
    SmContextState, Snssai, SscMode, UpSecurityContext, UeSecurityCapabilities,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextTransferRequest {
    pub supi: String,
    pub pdu_session_id: u8,
    pub target_smf_uri: String,
    pub source_smf_id: String,
    pub sm_context_data: SmContextData,
    pub transfer_cause: TransferCause,
    pub target_amf_id: Option<String>,
    pub transfer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextTransferResponse {
    pub transfer_id: String,
    pub accepted: bool,
    pub cause: Option<TransferResponseCause>,
    pub target_smf_id: String,
    pub target_sm_context_ref: Option<String>,
    pub failed_resources: Option<Vec<FailedResource>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextData {
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: SscMode,
    pub state: SmContextState,
    pub pdu_address: Option<PduAddress>,
    pub pfcp_session_id: Option<u64>,
    pub pcf_policy_id: Option<String>,
    pub chf_charging_ref: Option<String>,
    pub qos_flows: Vec<QosFlow>,
    pub packet_filters: Vec<PacketFilter>,
    pub qos_rules: Vec<QosRule>,
    pub mtu: Option<u16>,
    pub an_tunnel_info: Option<TunnelInfo>,
    pub ue_location: Option<UserLocation>,
    pub handover_state: Option<HoState>,
    pub is_emergency: bool,
    pub request_type: Option<RequestType>,
    pub up_security_context: Option<UpSecurityContext>,
    pub ue_security_capabilities: Option<UeSecurityCapabilities>,
    pub session_ambr: Option<Ambr>,
    pub upf_address: Option<String>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    pub pcf_id: Option<String>,
    pub pcf_group_id: Option<String>,
    pub pcf_set_id: Option<String>,
    pub guami: Option<Guami>,
    pub serving_network: Option<String>,
    pub rat_type: Option<String>,
    pub subscription_data: Option<TransferredSubscriptionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferredSubscriptionData {
    pub allowed_dnns: Vec<String>,
    pub allowed_s_nssais: Vec<Snssai>,
    pub subscribed_ue_ambr: Option<Ambr>,
    pub default_5qi: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferCause {
    InterSmfHandover,
    SmfRelocation,
    LoadBalancing,
    NetworkOptimization,
    UeMovedToTargetArea,
    SourceSmfFailure,
    PolicyChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferResponseCause {
    Success,
    InsufficientResources,
    InvalidContext,
    DnnNotSupported,
    SliceNotSupported,
    QosNotSupported,
    SecuritySetupFailed,
    UpfNotAvailable,
    InternalError,
    TemporarilyUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedResource {
    pub resource_type: FailedResourceType,
    pub resource_id: String,
    pub failure_cause: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailedResourceType {
    QosFlow,
    PacketFilter,
    QosRule,
    PfcpSession,
    PolicyAssociation,
    ChargingSession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextTransferAck {
    pub transfer_id: String,
    pub source_smf_id: String,
    pub acknowledged: bool,
    pub released_resources: Vec<ReleasedResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleasedResource {
    pub resource_type: String,
    pub resource_id: String,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub released_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextTransferCancel {
    pub transfer_id: String,
    pub source_smf_id: String,
    pub cancel_cause: TransferCancelCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferCancelCause {
    UeNotReachable,
    TargetSmfNotReachable,
    TransferTimeout,
    AmfInitiatedCancel,
    ResourcePreparationFailed,
    UeContextChanged,
}

pub struct SmContextValidator;

impl SmContextValidator {
    pub fn validate_transfer_request(request: &SmContextTransferRequest) -> Result<(), String> {
        if request.supi.is_empty() {
            return Err("SUPI cannot be empty".to_string());
        }

        if request.target_smf_uri.is_empty() {
            return Err("Target SMF URI cannot be empty".to_string());
        }

        if request.source_smf_id.is_empty() {
            return Err("Source SMF ID cannot be empty".to_string());
        }

        if request.transfer_id.is_empty() {
            return Err("Transfer ID cannot be empty".to_string());
        }

        Self::validate_context_data(&request.sm_context_data)?;

        Ok(())
    }

    pub fn validate_context_data(context: &SmContextData) -> Result<(), String> {
        if context.supi.is_empty() {
            return Err("SUPI in context data cannot be empty".to_string());
        }

        if context.dnn.is_empty() {
            return Err("DNN cannot be empty".to_string());
        }

        if context.s_nssai.sst == 0 {
            return Err("S-NSSAI SST must be non-zero".to_string());
        }

        if context.qos_flows.is_empty() {
            return Err("At least one QoS flow must be present".to_string());
        }

        for qos_flow in &context.qos_flows {
            if qos_flow.qfi == 0 || qos_flow.qfi > 63 {
                return Err(format!("Invalid QFI: {}. Must be in range 1-63", qos_flow.qfi));
            }
        }

        if let Some(ambr) = &context.session_ambr {
            if ambr.uplink.is_empty() || ambr.downlink.is_empty() {
                return Err("Session AMBR uplink and downlink must be specified".to_string());
            }
        }

        Ok(())
    }

    pub fn validate_transfer_response(response: &SmContextTransferResponse) -> Result<(), String> {
        if response.transfer_id.is_empty() {
            return Err("Transfer ID cannot be empty".to_string());
        }

        if response.target_smf_id.is_empty() {
            return Err("Target SMF ID cannot be empty".to_string());
        }

        if response.accepted && response.target_sm_context_ref.is_none() {
            return Err("Target SM context reference must be provided when transfer is accepted".to_string());
        }

        if !response.accepted && response.cause.is_none() {
            return Err("Cause must be provided when transfer is rejected".to_string());
        }

        Ok(())
    }

    pub fn check_context_compatibility(
        source_context: &SmContextData,
        target_capabilities: &TargetSmfCapabilities,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if !target_capabilities.supported_dnns.contains(&source_context.dnn) {
            errors.push(format!("DNN '{}' not supported by target SMF", source_context.dnn));
        }

        let snssai_supported = target_capabilities.supported_s_nssais.iter().any(|s| {
            s.sst == source_context.s_nssai.sst && s.sd == source_context.s_nssai.sd
        });

        if !snssai_supported {
            errors.push(format!(
                "S-NSSAI (SST: {}, SD: {:?}) not supported by target SMF",
                source_context.s_nssai.sst, source_context.s_nssai.sd
            ));
        }

        let max_5qi = source_context.qos_flows.iter().map(|f| f.five_qi).max().unwrap_or(0);
        if max_5qi > target_capabilities.max_supported_5qi {
            errors.push(format!(
                "5QI {} exceeds target SMF maximum supported 5QI {}",
                max_5qi, target_capabilities.max_supported_5qi
            ));
        }

        if source_context.qos_flows.len() > target_capabilities.max_qos_flows as usize {
            errors.push(format!(
                "Number of QoS flows ({}) exceeds target SMF limit ({})",
                source_context.qos_flows.len(),
                target_capabilities.max_qos_flows
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSmfCapabilities {
    pub supported_dnns: Vec<String>,
    pub supported_s_nssais: Vec<Snssai>,
    pub max_supported_5qi: u8,
    pub max_qos_flows: u16,
    pub supports_emergency: bool,
    pub supported_pdu_session_types: Vec<PduSessionType>,
    pub supported_ssc_modes: Vec<SscMode>,
}

impl Default for TargetSmfCapabilities {
    fn default() -> Self {
        Self {
            supported_dnns: vec!["internet".to_string(), "ims".to_string()],
            supported_s_nssais: vec![
                Snssai { sst: 1, sd: None },
                Snssai { sst: 2, sd: None },
                Snssai { sst: 3, sd: None },
            ],
            max_supported_5qi: 80,
            max_qos_flows: 16,
            supports_emergency: true,
            supported_pdu_session_types: vec![
                PduSessionType::Ipv4,
                PduSessionType::Ipv6,
                PduSessionType::Ipv4v6,
            ],
            supported_ssc_modes: vec![
                SscMode::Mode1,
                SscMode::Mode2,
                SscMode::Mode3,
            ],
        }
    }
}
