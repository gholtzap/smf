use crate::models::{TunnelInfo, N2SmInfoType};
use crate::types::{HoState, SmContextState};
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
}
