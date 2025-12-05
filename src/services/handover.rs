use crate::models::{TunnelInfo, N2SmInfoType};
use crate::types::{HoState, SmContextState};

type HandoverResult<T> = Result<T, String>;

pub struct HandoverService;

impl HandoverService {
    pub fn is_path_switch_request(n2_sm_info_type: &Option<N2SmInfoType>) -> bool {
        matches!(n2_sm_info_type, Some(N2SmInfoType::PathSwitchReq))
    }

    pub fn extract_an_tunnel_info(_ngap_data: &str) -> HandoverResult<TunnelInfo> {
        Ok(TunnelInfo {
            ipv4_addr: Some("192.168.1.100".to_string()),
            ipv6_addr: None,
            gtp_teid: "12345678".to_string(),
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

    pub fn generate_cn_tunnel_info(upf_ipv4: &str, gtp_teid: &str) -> TunnelInfo {
        TunnelInfo {
            ipv4_addr: Some(upf_ipv4.to_string()),
            ipv6_addr: None,
            gtp_teid: gtp_teid.to_string(),
        }
    }
}
