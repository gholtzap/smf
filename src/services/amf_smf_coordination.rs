use crate::models::SmContext;
use crate::services::context_transfer_source::ContextTransferSource;
use crate::services::pfcp::PfcpClient;
use crate::types::amf_smf_coordination::{
    SmContextRetrieveRequest, SmContextRetrieveResponse, SmContextRetrieveResult,
    SmContextReleaseNotification, SmContextReleaseResponse,
};
use crate::types::sm_context_transfer::{SmContextData, TransferCause};
use anyhow::{Context as AnyhowContext, Result};
use mongodb::Database;

pub struct AmfSmfCoordinationService {
    db: Database,
    pfcp_client: PfcpClient,
    source_smf_id: String,
}

impl AmfSmfCoordinationService {
    pub fn new(db: Database, pfcp_client: PfcpClient, source_smf_id: String) -> Self {
        Self {
            db,
            pfcp_client,
            source_smf_id,
        }
    }

    pub async fn retrieve_sm_context(
        &self,
        request: SmContextRetrieveRequest,
    ) -> Result<SmContextRetrieveResponse> {
        tracing::info!(
            "AMF requested SM context retrieval - SUPI: {}, PDU Session ID: {}, Target SMF: {}",
            request.supi,
            request.pdu_session_id,
            request.target_smf_id
        );

        let collection: mongodb::Collection<SmContext> = self.db.collection("sm_contexts");

        let sm_context = collection
            .find_one(mongodb::bson::doc! {
                "supi": &request.supi,
                "pduSessionId": request.pdu_session_id as i32
            })
            .await
            .context("Failed to query SM context")?;

        if let Some(context) = sm_context {
            if let Err(e) = ContextTransferSource::validate_context_for_transfer(&context) {
                tracing::warn!(
                    "SM context validation failed for retrieval - SUPI: {}, Error: {}",
                    request.supi,
                    e
                );

                return Ok(SmContextRetrieveResponse {
                    supi: request.supi,
                    pdu_session_id: request.pdu_session_id,
                    sm_context_data: None,
                    result: SmContextRetrieveResult::InvalidState,
                    failure_cause: Some(e),
                });
            }

            let _transfer_cause = match request.cause {
                crate::types::SmContextRetrieveCause::InterSmfHandover => TransferCause::InterSmfHandover,
                crate::types::SmContextRetrieveCause::SmfChange => TransferCause::SmfRelocation,
                crate::types::SmContextRetrieveCause::SmfRelocation => TransferCause::SmfRelocation,
                crate::types::SmContextRetrieveCause::AmfInitiatedChange => TransferCause::NetworkOptimization,
            };

            let sm_context_data = self.prepare_context_data(&context)?;

            tracing::info!(
                "SM context retrieved successfully - SUPI: {}, PDU Session ID: {}, Context Data Size: {} bytes",
                request.supi,
                request.pdu_session_id,
                serde_json::to_string(&sm_context_data).unwrap_or_default().len()
            );

            Ok(SmContextRetrieveResponse {
                supi: request.supi,
                pdu_session_id: request.pdu_session_id,
                sm_context_data: Some(sm_context_data),
                result: SmContextRetrieveResult::Success,
                failure_cause: None,
            })
        } else {
            tracing::warn!(
                "SM context not found for retrieval - SUPI: {}, PDU Session ID: {}",
                request.supi,
                request.pdu_session_id
            );

            Ok(SmContextRetrieveResponse {
                supi: request.supi,
                pdu_session_id: request.pdu_session_id,
                sm_context_data: None,
                result: SmContextRetrieveResult::ContextNotFound,
                failure_cause: Some("SM context not found".to_string()),
            })
        }
    }

    pub async fn release_sm_context_on_transfer(
        &self,
        notification: SmContextReleaseNotification,
    ) -> Result<SmContextReleaseResponse> {
        tracing::info!(
            "AMF notified source SMF to release context - SUPI: {}, PDU Session ID: {}, Target SMF: {}, Cause: {:?}",
            notification.supi,
            notification.pdu_session_id,
            notification.target_smf_id,
            notification.release_cause
        );

        let collection: mongodb::Collection<SmContext> = self.db.collection("sm_contexts");

        let sm_context = collection
            .find_one(mongodb::bson::doc! {
                "supi": &notification.supi,
                "pduSessionId": notification.pdu_session_id as i32
            })
            .await
            .context("Failed to query SM context for release")?;

        let mut released_resources = Vec::new();

        if let Some(context) = sm_context {
            if let Some(pfcp_session_id) = context.pfcp_session_id {
                let deletion_request = crate::types::pfcp::PfcpSessionDeletionRequest {
                    user_plane_inactivity_timer: None,
                };

                if let Err(e) = self
                    .pfcp_client
                    .send_session_deletion_request(pfcp_session_id, &deletion_request)
                    .await
                {
                    tracing::warn!(
                        "Failed to delete PFCP session during AMF-coordinated release - Session ID: {}, Error: {}",
                        pfcp_session_id,
                        e
                    );
                } else {
                    released_resources.push(format!("PFCP Session: {}", pfcp_session_id));
                    tracing::info!(
                        "PFCP session deleted during AMF-coordinated release - Session ID: {}",
                        pfcp_session_id
                    );
                }
            }

            collection
                .delete_one(mongodb::bson::doc! { "id": &context.id })
                .await
                .context("Failed to delete SM context during AMF-coordinated release")?;

            released_resources.push(format!("SM Context: {}", context.id));

            tracing::info!(
                "Source SM context released successfully - Context ID: {}, SUPI: {}, PDU Session ID: {}, Released Resources: {}",
                context.id,
                notification.supi,
                notification.pdu_session_id,
                released_resources.len()
            );

            Ok(SmContextReleaseResponse {
                released: true,
                released_resources,
            })
        } else {
            tracing::warn!(
                "SM context not found for AMF-coordinated release - SUPI: {}, PDU Session ID: {}",
                notification.supi,
                notification.pdu_session_id
            );

            Ok(SmContextReleaseResponse {
                released: false,
                released_resources: Vec::new(),
            })
        }
    }

    fn prepare_context_data(&self, context: &SmContext) -> Result<SmContextData> {
        Ok(SmContextData {
            supi: context.supi.clone(),
            pdu_session_id: context.pdu_session_id,
            dnn: context.dnn.clone(),
            s_nssai: context.s_nssai.clone(),
            pdu_session_type: context.pdu_session_type.clone(),
            ssc_mode: context.ssc_mode.clone(),
            state: context.state.clone(),
            pdu_address: context.pdu_address.clone(),
            pfcp_session_id: context.pfcp_session_id,
            pcf_policy_id: context.pcf_policy_id.clone(),
            chf_charging_ref: context.chf_charging_ref.clone(),
            qos_flows: context.qos_flows.clone(),
            packet_filters: context.packet_filters.clone(),
            qos_rules: context.qos_rules.clone(),
            mtu: context.mtu,
            an_tunnel_info: context.an_tunnel_info.clone(),
            ue_location: context.ue_location.clone(),
            handover_state: context.handover_state.clone(),
            is_emergency: context.is_emergency,
            request_type: context.request_type.clone(),
            up_security_context: context.up_security_context.clone(),
            ue_security_capabilities: context.ue_security_capabilities.clone(),
            session_ambr: context.session_ambr.clone(),
            upf_address: context.upf_address.clone(),
            created_at: context.created_at,
            pcf_id: None,
            pcf_group_id: None,
            pcf_set_id: None,
            guami: None,
            serving_network: None,
            rat_type: None,
            subscription_data: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PduAddress, PduSessionType, QosFlow, SmContextState, Snssai, SscMode};
    use crate::types::amf_smf_coordination::{SmContextRetrieveCause, SmContextReleaseCause};
    use chrono::Utc;

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
                pdu_session_type: PduSessionType::Ipv4,
                ipv4_addr: Some("10.60.1.100".to_string()),
                ipv6_addr: None,
                dns_primary: Some("8.8.8.8".to_string()),
                dns_secondary: Some("8.8.4.4".to_string()),
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
    fn test_prepare_context_data() {
        let db = mongodb::Database::default();
        let pfcp_client = PfcpClient::default();
        let service = AmfSmfCoordinationService::new(db, pfcp_client, "source-smf-001".to_string());

        let context = create_test_sm_context();
        let context_data = service.prepare_context_data(&context).unwrap();

        assert_eq!(context_data.supi, context.supi);
        assert_eq!(context_data.pdu_session_id, context.pdu_session_id);
        assert_eq!(context_data.dnn, context.dnn);
        assert_eq!(context_data.qos_flows.len(), context.qos_flows.len());
    }
}
