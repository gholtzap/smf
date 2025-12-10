use crate::types::sm_context_transfer::{
    SmContextTransferRequest, SmContextTransferResponse, SmContextTransferAck,
    SmContextTransferCancel, SmContextValidator,
};
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};
use std::time::Duration;

pub struct N16Client {
    client: Client,
    source_smf_id: String,
    timeout_seconds: u64,
}

impl N16Client {
    pub fn new(source_smf_id: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
            source_smf_id,
            timeout_seconds: 30,
        }
    }

    pub fn with_timeout(source_smf_id: String, timeout_seconds: u64) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(timeout_seconds))
                .build()
                .expect("Failed to build HTTP client"),
            source_smf_id,
            timeout_seconds,
        }
    }

    pub async fn transfer_sm_context(
        &self,
        target_smf_uri: &str,
        request: SmContextTransferRequest,
    ) -> Result<SmContextTransferResponse> {
        tracing::info!(
            "Initiating SM context transfer to target SMF - Transfer ID: {}, SUPI: {}, PDU Session ID: {}, Target: {}",
            request.transfer_id,
            request.supi,
            request.pdu_session_id,
            target_smf_uri
        );

        SmContextValidator::validate_transfer_request(&request)
            .map_err(|e| anyhow::anyhow!(e))?;

        let url = format!(
            "{}/nsmf-pdusession/v1/sm-contexts/transfer",
            target_smf_uri.trim_end_matches('/')
        );

        tracing::debug!(
            "Sending transfer request to {} - Transfer ID: {}",
            url,
            request.transfer_id
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send SM context transfer request to target SMF")?;

        let status = response.status();

        match status {
            StatusCode::OK | StatusCode::CREATED => {
                let transfer_response: SmContextTransferResponse = response
                    .json()
                    .await
                    .context("Failed to parse SM context transfer response")?;

                SmContextValidator::validate_transfer_response(&transfer_response)
                    .map_err(|e| anyhow::anyhow!(e))?;

                if transfer_response.accepted {
                    tracing::info!(
                        "SM context transfer accepted by target SMF - Transfer ID: {}, Target Context Ref: {:?}",
                        transfer_response.transfer_id,
                        transfer_response.target_sm_context_ref
                    );
                } else {
                    tracing::warn!(
                        "SM context transfer rejected by target SMF - Transfer ID: {}, Cause: {:?}",
                        transfer_response.transfer_id,
                        transfer_response.cause
                    );
                }

                Ok(transfer_response)
            }
            StatusCode::BAD_REQUEST => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "SM context transfer request validation failed: {}",
                    error_body
                ))
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "Target SMF endpoint not found at {}",
                    target_smf_uri
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("Target SMF temporarily unavailable"))
            }
            StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => {
                Err(anyhow::anyhow!(
                    "SM context transfer request timed out after {} seconds",
                    self.timeout_seconds
                ))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "SM context transfer failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn send_transfer_acknowledgment(
        &self,
        target_smf_uri: &str,
        ack: SmContextTransferAck,
    ) -> Result<()> {
        tracing::info!(
            "Sending transfer acknowledgment to target SMF - Transfer ID: {}, Acknowledged: {}",
            ack.transfer_id,
            ack.acknowledged
        );

        let url = format!(
            "{}/nsmf-pdusession/v1/sm-contexts/transfer/{}/ack",
            target_smf_uri.trim_end_matches('/'),
            ack.transfer_id
        );

        let response = self
            .client
            .post(&url)
            .json(&ack)
            .send()
            .await
            .context("Failed to send transfer acknowledgment to target SMF")?;

        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                tracing::info!(
                    "Transfer acknowledgment sent successfully - Transfer ID: {}",
                    ack.transfer_id
                );
                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "Transfer ID {} not found at target SMF",
                    ack.transfer_id
                ))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Transfer acknowledgment failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn cancel_transfer(
        &self,
        target_smf_uri: &str,
        cancel: SmContextTransferCancel,
    ) -> Result<()> {
        tracing::warn!(
            "Canceling SM context transfer - Transfer ID: {}, Cause: {:?}",
            cancel.transfer_id,
            cancel.cancel_cause
        );

        let url = format!(
            "{}/nsmf-pdusession/v1/sm-contexts/transfer/{}/cancel",
            target_smf_uri.trim_end_matches('/'),
            cancel.transfer_id
        );

        let response = self
            .client
            .post(&url)
            .json(&cancel)
            .send()
            .await
            .context("Failed to send transfer cancellation to target SMF")?;

        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                tracing::info!(
                    "Transfer cancellation sent successfully - Transfer ID: {}",
                    cancel.transfer_id
                );
                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "Transfer ID {} not found at target SMF",
                    cancel.transfer_id
                ))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Transfer cancellation failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub fn get_source_smf_id(&self) -> &str {
        &self.source_smf_id
    }

    pub async fn health_check(&self, target_smf_uri: &str) -> Result<bool> {
        let url = format!(
            "{}/nsmf-pdusession/v1/health",
            target_smf_uri.trim_end_matches('/')
        );

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status() == StatusCode::OK),
            Err(_) => Ok(false),
        }
    }
}

impl Default for N16Client {
    fn default() -> Self {
        Self::new("default-smf-001".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::sm_context_transfer::{
        SmContextData, TransferCause, TransferCancelCause,
    };
    use crate::types::{PduAddress, PduSessionType, QosFlow, SmContextState, Snssai, SscMode};
    use chrono::Utc;

    fn create_test_transfer_request() -> SmContextTransferRequest {
        SmContextTransferRequest {
            supi: "imsi-123456789012345".to_string(),
            pdu_session_id: 5,
            target_smf_uri: "http://target-smf:8080".to_string(),
            source_smf_id: "source-smf-001".to_string(),
            sm_context_data: SmContextData {
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
            },
            transfer_cause: TransferCause::InterSmfHandover,
            target_amf_id: None,
            transfer_id: "xfer-12345".to_string(),
        }
    }

    #[test]
    fn test_n16_client_creation() {
        let client = N16Client::new("test-smf-001".to_string());
        assert_eq!(client.get_source_smf_id(), "test-smf-001");
        assert_eq!(client.timeout_seconds, 30);
    }

    #[test]
    fn test_n16_client_with_custom_timeout() {
        let client = N16Client::with_timeout("test-smf-001".to_string(), 60);
        assert_eq!(client.timeout_seconds, 60);
    }

    #[test]
    fn test_transfer_request_validation() {
        let request = create_test_transfer_request();
        let validation_result = SmContextValidator::validate_transfer_request(&request);
        assert!(validation_result.is_ok());
    }
}
