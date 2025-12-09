use crate::models::{TunnelInfo, N2SmInfoType};
use crate::types::{HoState, SmContextState, AllocatedHandoverResources};
use crate::parsers::ngap::NgapParser;
use base64::{Engine as _, engine::general_purpose};

type HandoverResult<T> = Result<T, String>;

pub struct HandoverService;

impl HandoverService {
    pub fn is_path_switch_request(n2_sm_info_type: &Option<N2SmInfoType>) -> bool {
        matches!(n2_sm_info_type, Some(N2SmInfoType::PathSwitchReq))
    }

    pub fn extract_an_tunnel_info(ngap_data: &str) -> HandoverResult<TunnelInfo> {
        let decoded_bytes = general_purpose::STANDARD
            .decode(ngap_data)
            .map_err(|e| format!("Failed to decode base64 NGAP data: {}", e))?;

        tracing::debug!(
            "Decoded NGAP data: {} bytes from base64 string of {} chars",
            decoded_bytes.len(),
            ngap_data.len()
        );

        let parser = NgapParser::new();

        let path_switch_transfer = parser.extract_path_switch_request_transfer(&decoded_bytes)
            .map_err(|e| format!("Failed to parse Path Switch Request Transfer: {}", e))?;

        let gtp_tunnel = &path_switch_transfer.dl_ngu_up_tnl_information;

        let ipv4_addr = gtp_tunnel.get_ip_address();
        let teid = gtp_tunnel.get_teid()
            .map(|t| format!("{:08x}", t))
            .ok_or_else(|| "Failed to extract GTP TEID".to_string())?;

        tracing::info!(
            "Extracted tunnel info from NGAP: IP={:?}, TEID={}",
            ipv4_addr,
            teid
        );

        Ok(TunnelInfo {
            ipv4_addr,
            ipv6_addr: None,
            gtp_teid: teid,
        })
    }

    pub fn validate_handover_state(current_state: &SmContextState) -> HandoverResult<()> {
        match current_state {
            SmContextState::Active => Ok(()),
            _ => Err(format!(
                "Invalid state for handover: {:?}. PDU session must be in Active state",
                current_state
            )),
        }
    }

    pub fn validate_ho_state_for_request_ack(ho_state: &Option<HoState>) -> HandoverResult<()> {
        match ho_state {
            Some(HoState::Preparing) => Ok(()),
            Some(state) => Err(format!(
                "Invalid handover state for request acknowledgment: {:?}. Expected Preparing state",
                state
            )),
            None => Err("No handover in progress".to_string()),
        }
    }

    pub fn validate_ho_state_for_notify(ho_state: &Option<HoState>) -> HandoverResult<()> {
        match ho_state {
            Some(HoState::Prepared) | Some(HoState::Preparing) => Ok(()),
            Some(state) => Err(format!(
                "Invalid handover state for notify: {:?}. Expected Prepared or Preparing state",
                state
            )),
            None => Err("No handover in progress".to_string()),
        }
    }

    pub fn generate_cn_tunnel_info(upf_ipv4: &str, gtp_teid: &str) -> TunnelInfo {
        TunnelInfo {
            ipv4_addr: Some(upf_ipv4.to_string()),
            ipv6_addr: None,
            gtp_teid: gtp_teid.to_string(),
        }
    }

    pub fn validate_ho_state_for_cancel(ho_state: &Option<HoState>) -> HandoverResult<()> {
        match ho_state {
            Some(HoState::Preparing) | Some(HoState::Prepared) => Ok(()),
            Some(HoState::Completed) => Err(
                "Cannot cancel handover: handover already completed".to_string()
            ),
            Some(HoState::Cancelled) => Err(
                "Handover already cancelled".to_string()
            ),
            Some(HoState::None) | None => Err(
                "No handover in progress to cancel".to_string()
            ),
        }
    }

    pub fn extract_allocated_handover_resources(ngap_data: &str) -> HandoverResult<AllocatedHandoverResources> {
        let decoded_bytes = general_purpose::STANDARD
            .decode(ngap_data)
            .map_err(|e| format!("Failed to decode base64 NGAP data: {}", e))?;

        tracing::debug!(
            "Decoded NGAP data for resource allocation: {} bytes from base64 string of {} chars",
            decoded_bytes.len(),
            ngap_data.len()
        );

        let parser = NgapParser::new();

        let response_transfer = parser.extract_pdu_session_resource_setup_response_transfer(&decoded_bytes)
            .map_err(|e| format!("Failed to parse PDU Session Resource Setup Response Transfer: {}", e))?;

        let target_tunnel = &response_transfer.dl_qos_flow_per_tnl_information.up_transport_layer_information;
        let target_ipv4 = target_tunnel.get_ip_address();
        let target_teid = target_tunnel.get_teid()
            .map(|t| format!("{:08x}", t))
            .ok_or_else(|| "Failed to extract target GTP TEID".to_string())?;

        let allocated_qos_flow_ids: Vec<u8> = response_transfer
            .dl_qos_flow_per_tnl_information
            .associated_qos_flow_list
            .iter()
            .map(|item| item.qos_flow_identifier)
            .collect();

        let failed_qos_flow_ids: Vec<u8> = response_transfer
            .qos_flow_failed_to_setup_list
            .as_ref()
            .map(|failed_list| {
                failed_list.iter().map(|item| item.qos_flow_identifier).collect()
            })
            .unwrap_or_default();

        let security_activated = response_transfer
            .security_result
            .as_ref()
            .map(|sr| {
                sr.integrity_protection_result == crate::types::ngap::IntegrityProtectionResult::Performed
                    || sr.confidentiality_protection_result == crate::types::ngap::ConfidentialityProtectionResult::Performed
            })
            .unwrap_or(false);

        tracing::info!(
            "Extracted allocated handover resources - Target tunnel: IP={:?}, TEID={}, Allocated QoS flows: {:?}, Failed QoS flows: {:?}, Security activated: {}",
            target_ipv4,
            target_teid,
            allocated_qos_flow_ids,
            failed_qos_flow_ids,
            security_activated
        );

        Ok(AllocatedHandoverResources {
            target_tunnel_info: TunnelInfo {
                ipv4_addr: target_ipv4,
                ipv6_addr: None,
                gtp_teid: target_teid,
            },
            allocated_qos_flow_ids,
            failed_qos_flow_ids,
            security_activated,
        })
    }
}
