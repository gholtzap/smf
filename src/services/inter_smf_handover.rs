use crate::models::SmContext;
use crate::services::context_transfer_source::ContextTransferSource;
use crate::services::n16_client::N16Client;
use crate::services::pfcp::PfcpClient;
use crate::types::sm_context_transfer::{
    ReleasedResource, SmContextTransferAck, SmContextTransferCancel, SmContextTransferResponse,
    TransferCancelCause, TransferCause, TransferredSubscriptionData, TransferResponseCause,
};
use anyhow::{Context as AnyhowContext, Result};
use chrono::Utc;
use mongodb::Database;
use std::sync::Arc;

pub struct InterSmfHandoverService {
    n16_client: Arc<N16Client>,
    pfcp_client: PfcpClient,
    db: Database,
    source_smf_id: String,
}

impl InterSmfHandoverService {
    pub fn new(
        n16_client: Arc<N16Client>,
        pfcp_client: PfcpClient,
        db: Database,
        source_smf_id: String,
    ) -> Self {
        Self {
            n16_client,
            pfcp_client,
            db,
            source_smf_id,
        }
    }

    pub async fn initiate_handover(
        &self,
        sm_context: &SmContext,
        target_smf_uri: &str,
        transfer_cause: TransferCause,
        target_amf_id: Option<String>,
        subscription_data: Option<TransferredSubscriptionData>,
    ) -> Result<SmContextTransferResponse> {
        tracing::info!(
            "Initiating inter-SMF handover - SUPI: {}, PDU Session ID: {}, Target SMF: {}, Cause: {:?}",
            sm_context.supi,
            sm_context.pdu_session_id,
            target_smf_uri,
            transfer_cause
        );

        ContextTransferSource::validate_context_for_transfer(sm_context)
            .map_err(|e| anyhow::anyhow!("Context validation failed: {}", e))?;

        let transfer_request = ContextTransferSource::prepare_context_for_transfer(
            sm_context,
            target_smf_uri,
            &self.source_smf_id,
            transfer_cause.clone(),
            target_amf_id,
            subscription_data,
        )
        .map_err(|e| anyhow::anyhow!("Context preparation failed: {}", e))?;

        ContextTransferSource::log_transfer_preparation_details(
            sm_context,
            &transfer_request.transfer_id,
            target_smf_uri,
            &transfer_cause,
        );

        let transfer_response = self
            .n16_client
            .transfer_sm_context(target_smf_uri, transfer_request)
            .await
            .context("N16 context transfer request failed")?;

        if transfer_response.accepted {
            tracing::info!(
                "Inter-SMF handover successful - SUPI: {}, PDU Session ID: {}, Target Context Ref: {:?}",
                sm_context.supi,
                sm_context.pdu_session_id,
                transfer_response.target_sm_context_ref
            );

            if let Err(e) = self.cleanup_source_resources(sm_context).await {
                tracing::warn!(
                    "Failed to cleanup source resources after successful transfer - SUPI: {}, Error: {}",
                    sm_context.supi,
                    e
                );
            }

            if let Err(e) = self
                .send_acknowledgment(&transfer_response, target_smf_uri)
                .await
            {
                tracing::warn!(
                    "Failed to send transfer acknowledgment - Transfer ID: {}, Error: {}",
                    transfer_response.transfer_id,
                    e
                );
            }
        } else {
            tracing::error!(
                "Inter-SMF handover rejected by target - SUPI: {}, PDU Session ID: {}, Cause: {:?}, Failed Resources: {:?}",
                sm_context.supi,
                sm_context.pdu_session_id,
                transfer_response.cause,
                transfer_response.failed_resources
            );
        }

        Ok(transfer_response)
    }

    pub async fn cancel_handover(
        &self,
        transfer_id: &str,
        target_smf_uri: &str,
        cancel_cause: TransferCancelCause,
    ) -> Result<()> {
        tracing::warn!(
            "Canceling inter-SMF handover - Transfer ID: {}, Cause: {:?}",
            transfer_id,
            cancel_cause
        );

        let cancel = SmContextTransferCancel {
            transfer_id: transfer_id.to_string(),
            source_smf_id: self.source_smf_id.clone(),
            cancel_cause,
        };

        self.n16_client
            .cancel_transfer(target_smf_uri, cancel)
            .await
            .context("Failed to send transfer cancellation")?;

        tracing::info!(
            "Inter-SMF handover cancellation sent - Transfer ID: {}",
            transfer_id
        );

        Ok(())
    }

    async fn cleanup_source_resources(&self, sm_context: &SmContext) -> Result<()> {
        tracing::info!(
            "Cleaning up source resources after successful transfer - SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        if let Some(pfcp_session_id) = sm_context.pfcp_session_id {
            let deletion_request = crate::types::pfcp::PfcpSessionDeletionRequest {
                user_plane_inactivity_timer: None,
            };

            if let Err(e) = self
                .pfcp_client
                .send_session_deletion_request(pfcp_session_id, &deletion_request)
                .await
            {
                tracing::warn!(
                    "Failed to delete PFCP session at source UPF - Session ID: {}, Error: {}",
                    pfcp_session_id,
                    e
                );
            } else {
                tracing::info!(
                    "PFCP session deleted at source UPF - Session ID: {}",
                    pfcp_session_id
                );
            }
        }

        let collection: mongodb::Collection<SmContext> = self.db.collection("sm_contexts");

        collection
            .delete_one(mongodb::bson::doc! { "id": &sm_context.id })
            .await
            .context("Failed to delete SM context from source database")?;

        tracing::info!(
            "Source SM context deleted - Context ID: {}, SUPI: {}, PDU Session ID: {}",
            sm_context.id,
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Ok(())
    }

    async fn send_acknowledgment(
        &self,
        transfer_response: &SmContextTransferResponse,
        target_smf_uri: &str,
    ) -> Result<()> {
        let ack = SmContextTransferAck {
            transfer_id: transfer_response.transfer_id.clone(),
            source_smf_id: self.source_smf_id.clone(),
            acknowledged: true,
            released_resources: vec![
                ReleasedResource {
                    resource_type: "PfcpSession".to_string(),
                    resource_id: "source-pfcp-session".to_string(),
                    released_at: Utc::now(),
                },
                ReleasedResource {
                    resource_type: "SmContext".to_string(),
                    resource_id: "source-sm-context".to_string(),
                    released_at: Utc::now(),
                },
            ],
        };

        self.n16_client
            .send_transfer_acknowledgment(target_smf_uri, ack)
            .await
            .context("Failed to send transfer acknowledgment")?;

        Ok(())
    }

    pub fn should_trigger_handover(
        &self,
        current_upf_address: Option<&String>,
        target_upf_address: &str,
    ) -> bool {
        ContextTransferSource::should_trigger_inter_smf_handover(
            current_upf_address,
            target_upf_address,
        )
    }

    pub fn determine_transfer_cause(&self, relocation_reason: &str) -> TransferCause {
        ContextTransferSource::determine_transfer_cause(relocation_reason)
    }

    pub async fn check_target_smf_availability(&self, target_smf_uri: &str) -> bool {
        self.n16_client.health_check(target_smf_uri).await.unwrap_or(false)
    }

    pub fn is_transfer_successful(response: &SmContextTransferResponse) -> bool {
        response.accepted
            && response.target_sm_context_ref.is_some()
            && matches!(
                response.cause,
                Some(TransferResponseCause::Success) | None
            )
    }

    pub fn should_retry_transfer(response: &SmContextTransferResponse) -> bool {
        matches!(
            response.cause,
            Some(TransferResponseCause::TemporarilyUnavailable)
                | Some(TransferResponseCause::InsufficientResources)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_should_trigger_handover() {
        let n16_client = Arc::new(N16Client::new("source-smf-001".to_string()));
        let pfcp_client = PfcpClient::default();
        let db = mongodb::Database::default();

        let service = InterSmfHandoverService::new(
            n16_client,
            pfcp_client,
            db,
            "source-smf-001".to_string(),
        );

        let current = Some(&"192.168.1.10".to_string());
        assert!(service.should_trigger_handover(current, "192.168.2.20"));
        assert!(!service.should_trigger_handover(current, "192.168.1.10"));
    }

    #[test]
    fn test_determine_transfer_cause() {
        let n16_client = Arc::new(N16Client::new("source-smf-001".to_string()));
        let pfcp_client = PfcpClient::default();
        let db = mongodb::Database::default();

        let service = InterSmfHandoverService::new(
            n16_client,
            pfcp_client,
            db,
            "source-smf-001".to_string(),
        );

        assert!(matches!(
            service.determine_transfer_cause("handover"),
            TransferCause::InterSmfHandover
        ));
        assert!(matches!(
            service.determine_transfer_cause("load_balancing"),
            TransferCause::LoadBalancing
        ));
    }

    #[test]
    fn test_is_transfer_successful() {
        let response = SmContextTransferResponse {
            transfer_id: "xfer-123".to_string(),
            accepted: true,
            cause: Some(TransferResponseCause::Success),
            target_smf_id: "target-smf-001".to_string(),
            target_sm_context_ref: Some("ctx-456".to_string()),
            failed_resources: None,
        };

        assert!(InterSmfHandoverService::is_transfer_successful(&response));

        let failed_response = SmContextTransferResponse {
            transfer_id: "xfer-123".to_string(),
            accepted: false,
            cause: Some(TransferResponseCause::InsufficientResources),
            target_smf_id: "target-smf-001".to_string(),
            target_sm_context_ref: None,
            failed_resources: None,
        };

        assert!(!InterSmfHandoverService::is_transfer_successful(&failed_response));
    }

    #[test]
    fn test_should_retry_transfer() {
        let retry_response = SmContextTransferResponse {
            transfer_id: "xfer-123".to_string(),
            accepted: false,
            cause: Some(TransferResponseCause::TemporarilyUnavailable),
            target_smf_id: "target-smf-001".to_string(),
            target_sm_context_ref: None,
            failed_resources: None,
        };

        assert!(InterSmfHandoverService::should_retry_transfer(&retry_response));

        let no_retry_response = SmContextTransferResponse {
            transfer_id: "xfer-123".to_string(),
            accepted: false,
            cause: Some(TransferResponseCause::DnnNotSupported),
            target_smf_id: "target-smf-001".to_string(),
            target_sm_context_ref: None,
            failed_resources: None,
        };

        assert!(!InterSmfHandoverService::should_retry_transfer(&no_retry_response));
    }
}
