use serde::{Deserialize, Serialize};
use crate::models::{SmContext, Ambr};
use crate::types::{Snssai, PduSessionType, PduAddress, SscMode, PlmnId};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextType {
    EpsPdnConnection,
    SmContext,
    AfCoordinationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrieveData {
    pub sm_context_type: Option<SmContextType>,
    pub target_mme_cap: Option<MmeCapabilities>,
    pub serving_network: Option<PlmnId>,
    pub not_to_transfer_ebi_list: Option<Vec<u8>>,
    #[serde(default)]
    pub ran_unchanged_ind: Option<bool>,
    #[serde(default)]
    pub hrsbo_support_ind: Option<bool>,
    pub stored_offload_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MmeCapabilities {
    #[serde(default)]
    pub non_ip_supported: bool,
    #[serde(default)]
    pub ethernet_supported: bool,
    #[serde(default)]
    pub upip_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrievedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_eps_pdn_connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sm_context: Option<SmContextResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextResponse {
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub pdu_session_type: PduSessionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ambr: Option<Ambr>,
    pub qos_flows_list: Vec<QosFlowItemResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_address: Option<PduAddress>,
    pub ssc_mode: SscMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_security: Option<UpSecurityResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ho_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowItemResponse {
    pub qfi: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebi: Option<u8>,
    pub qos_flow_profile: QosFlowProfileResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowProfileResponse {
    #[serde(rename = "5qi")]
    pub five_qi: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arp: Option<ArpResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gbr_qos_flow_info: Option<GbrQosFlowInfoResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpResponse {
    pub priority_level: u8,
    pub preempt_cap: String,
    pub preempt_vuln: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GbrQosFlowInfoResponse {
    pub max_fbr_dl: String,
    pub max_fbr_ul: String,
    pub gua_fbr_dl: String,
    pub gua_fbr_ul: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpSecurityResponse {
    pub up_integr: String,
    pub up_confid: String,
}

impl SmContextResponse {
    pub fn from_internal(ctx: &SmContext) -> Self {
        let qos_flows_list = ctx.qos_flows.iter().map(|f| {
            let gbr_info = match f.qos_flow_type {
                crate::types::qos::QosFlowType::GBR | crate::types::qos::QosFlowType::DelayGBR => {
                    f.gfbr.as_ref().zip(f.mfbr.as_ref()).map(|(gfbr, mfbr)| {
                        GbrQosFlowInfoResponse {
                            max_fbr_dl: format!("{} bps", mfbr.downlink),
                            max_fbr_ul: format!("{} bps", mfbr.uplink),
                            gua_fbr_dl: format!("{} bps", gfbr.downlink),
                            gua_fbr_ul: format!("{} bps", gfbr.uplink),
                        }
                    })
                }
                _ => None,
            };

            QosFlowItemResponse {
                qfi: f.qfi,
                ebi: None,
                qos_flow_profile: QosFlowProfileResponse {
                    five_qi: f.five_qi,
                    arp: Some(ArpResponse {
                        priority_level: f.priority_level,
                        preempt_cap: "NOT_PREEMPT".to_string(),
                        preempt_vuln: "PREEMPTABLE".to_string(),
                    }),
                    gbr_qos_flow_info: gbr_info,
                },
            }
        }).collect();

        let up_security = ctx.up_security_context.as_ref().map(|sec| {
            UpSecurityResponse {
                up_integr: if sec.integrity_protection_activated { "REQUIRED" } else { "NOT_NEEDED" }.to_string(),
                up_confid: if sec.confidentiality_protection_activated { "REQUIRED" } else { "NOT_NEEDED" }.to_string(),
            }
        });

        let ho_state = ctx.handover_state.as_ref().map(|hs| {
            match hs {
                crate::types::HoState::None => "NONE",
                crate::types::HoState::Preparing => "PREPARING",
                crate::types::HoState::Prepared => "PREPARED",
                crate::types::HoState::Completed => "COMPLETED",
                crate::types::HoState::Cancelled => "CANCELLED",
            }.to_string()
        });

        SmContextResponse {
            pdu_session_id: ctx.pdu_session_id,
            dnn: ctx.dnn.clone(),
            s_nssai: ctx.s_nssai.clone(),
            pdu_session_type: ctx.pdu_session_type.clone(),
            session_ambr: ctx.session_ambr.clone(),
            qos_flows_list,
            pdu_address: ctx.pdu_address.clone(),
            ssc_mode: ctx.ssc_mode,
            up_security,
            ho_state,
        }
    }
}
