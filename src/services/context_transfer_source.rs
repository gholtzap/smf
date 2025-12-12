use crate::models::SmContext;
use crate::types::sm_context_transfer::{
    SmContextData, SmContextTransferRequest, SmContextValidator, TransferCause,
    TransferredSubscriptionData,
};
use uuid::Uuid;

pub struct ContextTransferSource;

impl ContextTransferSource {
    pub fn prepare_context_for_transfer(
        sm_context: &SmContext,
        target_smf_uri: &str,
        source_smf_id: &str,
        transfer_cause: TransferCause,
        target_amf_id: Option<String>,
        subscription_data: Option<TransferredSubscriptionData>,
    ) -> Result<SmContextTransferRequest, String> {
        tracing::info!(
            "Preparing SM context for transfer - SUPI: {}, PDU Session ID: {}, Target SMF: {}",
            sm_context.supi,
            sm_context.pdu_session_id,
            target_smf_uri
        );

        let sm_context_data = Self::serialize_sm_context(sm_context, subscription_data)?;

        let transfer_id = Self::generate_transfer_id();

        let transfer_request = SmContextTransferRequest {
            supi: sm_context.supi.clone(),
            pdu_session_id: sm_context.pdu_session_id,
            target_smf_uri: target_smf_uri.to_string(),
            source_smf_id: source_smf_id.to_string(),
            sm_context_data,
            transfer_cause,
            target_amf_id,
            transfer_id,
        };

        SmContextValidator::validate_transfer_request(&transfer_request)?;

        tracing::info!(
            "SM context transfer request prepared successfully - Transfer ID: {}",
            transfer_request.transfer_id
        );

        Ok(transfer_request)
    }

    pub fn serialize_sm_context(
        sm_context: &SmContext,
        subscription_data: Option<TransferredSubscriptionData>,
    ) -> Result<SmContextData, String> {
        if sm_context.pfcp_session_id.is_none() {
            return Err("Cannot transfer SM context without PFCP session".to_string());
        }

        if sm_context.pdu_address.is_none() {
            return Err("Cannot transfer SM context without PDU address".to_string());
        }

        Ok(SmContextData {
            supi: sm_context.supi.clone(),
            pdu_session_id: sm_context.pdu_session_id,
            dnn: sm_context.dnn.clone(),
            s_nssai: sm_context.s_nssai.clone(),
            pdu_session_type: sm_context.pdu_session_type.clone(),
            ssc_mode: sm_context.ssc_mode.clone(),
            state: sm_context.state.clone(),
            pdu_address: sm_context.pdu_address.clone(),
            pfcp_session_id: sm_context.pfcp_session_id,
            pcf_policy_id: sm_context.pcf_policy_id.clone(),
            chf_charging_ref: sm_context.chf_charging_ref.clone(),
            qos_flows: sm_context.qos_flows.clone(),
            packet_filters: sm_context.packet_filters.clone(),
            qos_rules: sm_context.qos_rules.clone(),
            mtu: sm_context.mtu,
            an_tunnel_info: sm_context.an_tunnel_info.clone(),
            ue_location: sm_context.ue_location.clone(),
            handover_state: sm_context.handover_state.clone(),
            is_emergency: sm_context.is_emergency,
            request_type: sm_context.request_type.clone(),
            up_security_context: sm_context.up_security_context.clone(),
            ue_security_capabilities: sm_context.ue_security_capabilities.clone(),
            session_ambr: sm_context.session_ambr.clone(),
            upf_address: sm_context.upf_address.clone(),
            created_at: sm_context.created_at,
            pcf_id: None,
            pcf_group_id: None,
            pcf_set_id: None,
            guami: None,
            serving_network: None,
            rat_type: None,
            subscription_data,
        })
    }

    pub fn validate_context_for_transfer(sm_context: &SmContext) -> Result<(), String> {
        use crate::types::SmContextState;

        match sm_context.state {
            SmContextState::Active => {},
            SmContextState::ModificationPending => {},
            _ => {
                return Err(format!(
                    "Invalid state for context transfer: {:?}. Expected Active or ModificationPending",
                    sm_context.state
                ));
            }
        }

        if sm_context.pfcp_session_id.is_none() {
            return Err("PFCP session must be established before transfer".to_string());
        }

        if sm_context.pdu_address.is_none() {
            return Err("PDU address must be allocated before transfer".to_string());
        }

        if sm_context.qos_flows.is_empty() {
            return Err("At least one QoS flow must be active before transfer".to_string());
        }

        tracing::debug!(
            "SM context validation passed for transfer - SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Ok(())
    }

    fn generate_transfer_id() -> String {
        format!("xfer-{}", Uuid::new_v4())
    }

    pub fn should_trigger_inter_smf_handover(
        current_upf_address: Option<&String>,
        target_upf_address: &str,
    ) -> bool {
        match current_upf_address {
            Some(current) => current != target_upf_address,
            None => false,
        }
    }

    pub fn extract_subscription_data_for_transfer(
        allowed_dnns: Vec<String>,
        allowed_s_nssais: Vec<crate::types::Snssai>,
        subscribed_ue_ambr: Option<crate::models::Ambr>,
        default_5qi: Option<u8>,
    ) -> TransferredSubscriptionData {
        TransferredSubscriptionData {
            allowed_dnns,
            allowed_s_nssais,
            subscribed_ue_ambr,
            default_5qi,
        }
    }

    pub fn determine_transfer_cause(
        relocation_reason: &str,
    ) -> TransferCause {
        match relocation_reason {
            "handover" => TransferCause::InterSmfHandover,
            "load_balancing" => TransferCause::LoadBalancing,
            "network_optimization" => TransferCause::NetworkOptimization,
            "ue_moved" => TransferCause::UeMovedToTargetArea,
            "source_failure" => TransferCause::SourceSmfFailure,
            "policy" => TransferCause::PolicyChange,
            _ => TransferCause::SmfRelocation,
        }
    }

    pub fn log_transfer_preparation_details(
        sm_context: &SmContext,
        transfer_id: &str,
        target_smf_uri: &str,
        transfer_cause: &TransferCause,
    ) {
        tracing::info!(
            "Context Transfer Preparation Details:\n\
             - Transfer ID: {}\n\
             - SUPI: {}\n\
             - PDU Session ID: {}\n\
             - DNN: {}\n\
             - S-NSSAI: SST={}, SD={:?}\n\
             - Target SMF: {}\n\
             - Transfer Cause: {:?}\n\
             - State: {:?}\n\
             - QoS Flows: {}\n\
             - Emergency: {}",
            transfer_id,
            sm_context.supi,
            sm_context.pdu_session_id,
            sm_context.dnn,
            sm_context.s_nssai.sst,
            sm_context.s_nssai.sd,
            target_smf_uri,
            transfer_cause,
            sm_context.state,
            sm_context.qos_flows.len(),
            sm_context.is_emergency
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SmContext;
    use crate::types::{PduAddress, PduSessionType, QosFlow, SmContextState, Snssai, SscMode};

    fn create_test_sm_context() -> SmContext {
        SmContext {
            id: "test-context-1".to_string(),
            supi: "imsi-123456789012345".to_string(),
            pdu_session_id: 5,
            dnn: "internet".to_string(),
            s_nssai: Snssai { sst: 1, sd: None },
            pdu_session_type: PduSessionType::Ipv4,
            ssc_mode: SscMode::Mode1,
            state: SmContextState::Active,
            pdu_address: Some(PduAddress {
                ipv4_addr: Some("10.60.1.100".to_string()),
                ipv6_prefix: None,
                ipv6_addr: None,
            }),
            pfcp_session_id: Some(12345),
            pcf_policy_id: None,
            chf_charging_ref: None,
            qos_flows: vec![QosFlow::new_default(1)],
            packet_filters: vec![],
            qos_rules: vec![],
            mtu: Some(1500),
            an_tunnel_info: None,
            ue_location: None,
            handover_state: None,
            is_emergency: false,
            request_type: None,
            up_security_context: None,
            ue_security_capabilities: None,
            session_ambr: None,
            upf_address: Some("192.168.1.10".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_validate_context_for_transfer_success() {
        let sm_context = create_test_sm_context();
        let result = ContextTransferSource::validate_context_for_transfer(&sm_context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_context_for_transfer_no_pfcp_session() {
        let mut sm_context = create_test_sm_context();
        sm_context.pfcp_session_id = None;
        let result = ContextTransferSource::validate_context_for_transfer(&sm_context);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PFCP session must be established before transfer"
        );
    }

    #[test]
    fn test_serialize_sm_context() {
        let sm_context = create_test_sm_context();
        let result = ContextTransferSource::serialize_sm_context(&sm_context, None);
        assert!(result.is_ok());
        let context_data = result.unwrap();
        assert_eq!(context_data.supi, sm_context.supi);
        assert_eq!(context_data.pdu_session_id, sm_context.pdu_session_id);
        assert_eq!(context_data.dnn, sm_context.dnn);
    }

    #[test]
    fn test_prepare_context_for_transfer() {
        let sm_context = create_test_sm_context();
        let result = ContextTransferSource::prepare_context_for_transfer(
            &sm_context,
            "http://target-smf:8080",
            "source-smf-001",
            TransferCause::InterSmfHandover,
            None,
            None,
        );
        assert!(result.is_ok());
        let transfer_request = result.unwrap();
        assert_eq!(transfer_request.supi, sm_context.supi);
        assert_eq!(
            transfer_request.target_smf_uri,
            "http://target-smf:8080"
        );
        assert!(transfer_request.transfer_id.starts_with("xfer-"));
    }

    #[test]
    fn test_should_trigger_inter_smf_handover() {
        let current = Some(&"192.168.1.10".to_string());
        assert!(ContextTransferSource::should_trigger_inter_smf_handover(
            current,
            "192.168.2.20"
        ));
        assert!(!ContextTransferSource::should_trigger_inter_smf_handover(
            current,
            "192.168.1.10"
        ));
    }

    #[test]
    fn test_determine_transfer_cause() {
        assert!(matches!(
            ContextTransferSource::determine_transfer_cause("handover"),
            TransferCause::InterSmfHandover
        ));
        assert!(matches!(
            ContextTransferSource::determine_transfer_cause("load_balancing"),
            TransferCause::LoadBalancing
        ));
        assert!(matches!(
            ContextTransferSource::determine_transfer_cause("unknown"),
            TransferCause::SmfRelocation
        ));
    }
}
