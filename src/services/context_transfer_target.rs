use crate::models::SmContext;
use crate::services::pfcp::PfcpClient;
use crate::services::pfcp_session::PfcpSessionManager;
use crate::types::sm_context_transfer::{
    SmContextData, SmContextTransferRequest,
    SmContextTransferResponse, SmContextValidator, TargetSmfCapabilities, TransferResponseCause,
};
use crate::types::SmContextState;
use chrono::Utc;
use mongodb::Database;
use std::net::Ipv4Addr;
use uuid::Uuid;

pub struct ContextTransferTarget {
    db: Database,
    pfcp_client: PfcpClient,
    target_smf_id: String,
    capabilities: TargetSmfCapabilities,
}

impl ContextTransferTarget {
    pub fn new(
        db: Database,
        pfcp_client: PfcpClient,
        target_smf_id: String,
    ) -> Self {
        Self {
            db,
            pfcp_client,
            target_smf_id,
            capabilities: TargetSmfCapabilities::default(),
        }
    }

    pub fn with_capabilities(
        db: Database,
        pfcp_client: PfcpClient,
        target_smf_id: String,
        capabilities: TargetSmfCapabilities,
    ) -> Self {
        Self {
            db,
            pfcp_client,
            target_smf_id,
            capabilities,
        }
    }

    pub async fn receive_and_process_transfer(
        &self,
        request: SmContextTransferRequest,
    ) -> Result<SmContextTransferResponse, String> {
        tracing::info!(
            "Receiving SM context transfer - Transfer ID: {}, SUPI: {}, PDU Session ID: {}",
            request.transfer_id,
            request.supi,
            request.pdu_session_id
        );

        SmContextValidator::validate_transfer_request(&request)?;

        let compatibility_result = SmContextValidator::check_context_compatibility(
            &request.sm_context_data,
            &self.capabilities,
        );

        if let Err(errors) = compatibility_result {
            tracing::warn!(
                "Context compatibility check failed - Transfer ID: {}, Errors: {:?}",
                request.transfer_id,
                errors
            );

            return Ok(SmContextTransferResponse {
                transfer_id: request.transfer_id,
                accepted: false,
                cause: Some(Self::determine_rejection_cause(&errors)),
                target_smf_id: self.target_smf_id.clone(),
                target_sm_context_ref: None,
                failed_resources: None,
            });
        }

        match self.apply_transferred_context(&request).await {
            Ok(sm_context_ref) => {
                tracing::info!(
                    "SM context transfer accepted successfully - Transfer ID: {}, SM Context Ref: {}",
                    request.transfer_id,
                    sm_context_ref
                );

                Ok(SmContextTransferResponse {
                    transfer_id: request.transfer_id,
                    accepted: true,
                    cause: Some(TransferResponseCause::Success),
                    target_smf_id: self.target_smf_id.clone(),
                    target_sm_context_ref: Some(sm_context_ref),
                    failed_resources: None,
                })
            }
            Err(err) => {
                tracing::error!(
                    "Failed to apply transferred context - Transfer ID: {}, Error: {}",
                    request.transfer_id,
                    err
                );

                Ok(SmContextTransferResponse {
                    transfer_id: request.transfer_id,
                    accepted: false,
                    cause: Some(TransferResponseCause::InternalError),
                    target_smf_id: self.target_smf_id.clone(),
                    target_sm_context_ref: None,
                    failed_resources: Some(vec![]),
                })
            }
        }
    }

    async fn apply_transferred_context(
        &self,
        request: &SmContextTransferRequest,
    ) -> Result<String, String> {
        tracing::debug!(
            "Applying transferred context - SUPI: {}, PDU Session ID: {}",
            request.supi,
            request.pdu_session_id
        );

        let sm_context = self.deserialize_context(&request.sm_context_data)?;

        self.validate_resource_availability(&sm_context).await?;

        let sm_context_ref = self.store_sm_context(&sm_context).await?;

        if let Err(e) = self.setup_pfcp_session(&sm_context).await {
            tracing::error!(
                "PFCP session setup failed - SUPI: {}, PDU Session ID: {}, Error: {}",
                sm_context.supi,
                sm_context.pdu_session_id,
                e
            );

            self.cleanup_stored_context(&sm_context_ref).await;

            return Err(format!("PFCP session setup failed: {}", e));
        }

        tracing::info!(
            "Context applied successfully - SM Context Ref: {}, SUPI: {}, PDU Session ID: {}",
            sm_context_ref,
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Ok(sm_context_ref)
    }

    fn deserialize_context(&self, context_data: &SmContextData) -> Result<SmContext, String> {
        tracing::debug!(
            "Deserializing SM context - SUPI: {}, PDU Session ID: {}",
            context_data.supi,
            context_data.pdu_session_id
        );

        let sm_context_id = format!("ctx-{}", Uuid::new_v4());

        let sm_context = SmContext {
            id: sm_context_id,
            supi: context_data.supi.clone(),
            pdu_session_id: context_data.pdu_session_id,
            dnn: context_data.dnn.clone(),
            s_nssai: context_data.s_nssai.clone(),
            pdu_session_type: context_data.pdu_session_type.clone(),
            ssc_mode: context_data.ssc_mode.clone(),
            state: SmContextState::Active,
            pdu_address: context_data.pdu_address.clone(),
            pfcp_session_id: context_data.pfcp_session_id,
            pcf_policy_id: context_data.pcf_policy_id.clone(),
            chf_charging_ref: context_data.chf_charging_ref.clone(),
            qos_flows: context_data.qos_flows.clone(),
            packet_filters: context_data.packet_filters.clone(),
            qos_rules: context_data.qos_rules.clone(),
            mtu: context_data.mtu,
            an_tunnel_info: context_data.an_tunnel_info.clone(),
            ue_location: context_data.ue_location.clone(),
            handover_state: context_data.handover_state.clone(),
            is_emergency: context_data.is_emergency,
            request_type: context_data.request_type.clone(),
            up_security_context: context_data.up_security_context.clone(),
            ue_security_capabilities: context_data.ue_security_capabilities.clone(),
            session_ambr: context_data.session_ambr.clone(),
            upf_address: context_data.upf_address.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        tracing::debug!(
            "SM context deserialized successfully - Context ID: {}, SUPI: {}",
            sm_context.id,
            sm_context.supi
        );

        Ok(sm_context)
    }

    async fn validate_resource_availability(&self, sm_context: &SmContext) -> Result<(), String> {
        tracing::debug!(
            "Validating resource availability - SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        if sm_context.pdu_address.is_none() {
            return Err("PDU address must be present in transferred context".to_string());
        }

        if sm_context.pfcp_session_id.is_none() {
            return Err("PFCP session ID must be present in transferred context".to_string());
        }

        if sm_context.qos_flows.is_empty() {
            return Err("At least one QoS flow must be present in transferred context".to_string());
        }

        tracing::debug!(
            "Resource availability validated - SUPI: {}, QoS Flows: {}, PDU Address: {:?}",
            sm_context.supi,
            sm_context.qos_flows.len(),
            sm_context.pdu_address
        );

        Ok(())
    }

    async fn store_sm_context(&self, sm_context: &SmContext) -> Result<String, String> {
        tracing::debug!(
            "Storing SM context in database - Context ID: {}, SUPI: {}",
            sm_context.id,
            sm_context.supi
        );

        let collection: mongodb::Collection<SmContext> = self.db.collection("sm_contexts");

        collection
            .insert_one(sm_context.clone())
            .await
            .map_err(|e| format!("Failed to store SM context: {}", e))?;

        tracing::info!(
            "SM context stored successfully - Context ID: {}, SUPI: {}, PDU Session ID: {}",
            sm_context.id,
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Ok(sm_context.id.clone())
    }

    async fn setup_pfcp_session(&self, sm_context: &SmContext) -> Result<(), String> {
        tracing::info!(
            "Setting up PFCP session at target UPF - SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        let pfcp_session_id = sm_context
            .pfcp_session_id
            .ok_or("PFCP session ID not present in context")?;

        let pdu_address = sm_context
            .pdu_address
            .as_ref()
            .ok_or("PDU address not present in context")?;

        let ue_ipv4_str = pdu_address
            .ipv4_addr
            .as_ref()
            .ok_or("IPv4 address not present in PDU address")?;

        let ue_ipv4: Ipv4Addr = ue_ipv4_str
            .parse()
            .map_err(|e| format!("Invalid UE IPv4 address: {}", e))?;

        let upf_address = sm_context
            .upf_address
            .as_ref()
            .ok_or("UPF address not present in context")?;

        let upf_ipv4: Ipv4Addr = upf_address
            .parse()
            .map_err(|e| format!("Invalid UPF IPv4 address: {}", e))?;

        let up_security = sm_context.up_security_context.as_ref();

        let _response = PfcpSessionManager::establish_session(
            &self.pfcp_client,
            pfcp_session_id,
            ue_ipv4,
            upf_ipv4,
            &sm_context.qos_flows,
            up_security,
        )
        .await
        .map_err(|e| format!("PFCP session establishment failed: {}", e))?;

        tracing::info!(
            "PFCP session established at target UPF - Session ID: {}, SUPI: {}, UE IP: {}, UPF IP: {}",
            pfcp_session_id,
            sm_context.supi,
            ue_ipv4,
            upf_ipv4
        );

        Ok(())
    }

    async fn cleanup_stored_context(&self, sm_context_ref: &str) {
        tracing::warn!(
            "Cleaning up stored context after failure - Context Ref: {}",
            sm_context_ref
        );

        let collection: mongodb::Collection<SmContext> = self.db.collection("sm_contexts");

        if let Err(e) = collection
            .delete_one(mongodb::bson::doc! { "id": sm_context_ref })
            .await
        {
            tracing::error!(
                "Failed to cleanup stored context - Context Ref: {}, Error: {}",
                sm_context_ref,
                e
            );
        } else {
            tracing::info!(
                "Stored context cleaned up successfully - Context Ref: {}",
                sm_context_ref
            );
        }
    }

    fn determine_rejection_cause(errors: &[String]) -> TransferResponseCause {
        for error in errors {
            let error_lower = error.to_lowercase();
            if error_lower.contains("dnn") {
                return TransferResponseCause::DnnNotSupported;
            } else if error_lower.contains("s-nssai") || error_lower.contains("slice") {
                return TransferResponseCause::SliceNotSupported;
            } else if error_lower.contains("qos") || error_lower.contains("5qi") {
                return TransferResponseCause::QosNotSupported;
            } else if error_lower.contains("security") {
                return TransferResponseCause::SecuritySetupFailed;
            } else if error_lower.contains("upf") {
                return TransferResponseCause::UpfNotAvailable;
            }
        }

        TransferResponseCause::InvalidContext
    }

    pub fn get_capabilities(&self) -> &TargetSmfCapabilities {
        &self.capabilities
    }

    pub async fn check_existing_context(
        &self,
        supi: &str,
        pdu_session_id: u8,
    ) -> Result<bool, String> {
        let collection: mongodb::Collection<SmContext> = self.db.collection("sm_contexts");

        let filter = mongodb::bson::doc! {
            "supi": supi,
            "pdu_session_id": pdu_session_id as i32,
        };

        let count = collection
            .count_documents(filter)
            .await
            .map_err(|e| format!("Failed to check existing context: {}", e))?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PduAddress, PduSessionType, QosFlow, Snssai, SscMode};

    fn create_test_context_data() -> SmContextData {
        SmContextData {
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
            pcf_id: None,
            pcf_group_id: None,
            pcf_set_id: None,
            guami: None,
            serving_network: None,
            rat_type: None,
            subscription_data: None,
        }
    }

    #[test]
    fn test_deserialize_context() {
        let context_data = create_test_context_data();
        let db = mongodb::Database::default();
        let pfcp_client = PfcpClient::default();
        let target = ContextTransferTarget::new(db, pfcp_client, "target-smf-001".to_string());

        let result = target.deserialize_context(&context_data);
        assert!(result.is_ok());

        let sm_context = result.unwrap();
        assert_eq!(sm_context.supi, context_data.supi);
        assert_eq!(sm_context.pdu_session_id, context_data.pdu_session_id);
        assert_eq!(sm_context.dnn, context_data.dnn);
        assert_eq!(sm_context.state, SmContextState::Active);
    }

    #[test]
    fn test_determine_rejection_cause() {
        assert!(matches!(
            ContextTransferTarget::determine_rejection_cause(&["DNN not supported".to_string()]),
            TransferResponseCause::DnnNotSupported
        ));

        assert!(matches!(
            ContextTransferTarget::determine_rejection_cause(&["S-NSSAI not supported".to_string()]),
            TransferResponseCause::SliceNotSupported
        ));

        assert!(matches!(
            ContextTransferTarget::determine_rejection_cause(&["5QI exceeds limit".to_string()]),
            TransferResponseCause::QosNotSupported
        ));

        assert!(matches!(
            ContextTransferTarget::determine_rejection_cause(&["Unknown error".to_string()]),
            TransferResponseCause::InvalidContext
        ));
    }
}
