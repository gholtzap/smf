use crate::models::SmContext;

pub struct ContextTransferSource;

impl ContextTransferSource {
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
}
