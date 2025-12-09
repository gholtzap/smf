use crate::types::pcf::{
    SmPolicyContextData, SmPolicyDecision, SmPolicyUpdateContextData,
};
use crate::types::nrf::ProblemDetails;
use crate::types::oauth2_request::OAuth2ClientExt;
use crate::services::oauth2_client::OAuth2TokenClient;
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};
use std::sync::Arc;

pub struct PcfClient {
    client: Client,
    oauth2_client: Option<Arc<OAuth2TokenClient>>,
}

impl PcfClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            oauth2_client: None,
        }
    }

    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    pub fn with_oauth2(mut self, oauth2_client: Arc<OAuth2TokenClient>) -> Self {
        self.oauth2_client = Some(oauth2_client);
        self
    }

    pub async fn create_sm_policy(
        &self,
        pcf_uri: &str,
        context_data: SmPolicyContextData,
    ) -> Result<(String, SmPolicyDecision)> {
        let url = format!("{}/npcf-smpolicycontrol/v1/sm-policies", pcf_uri);

        let response = self
            .client
            .post(&url)
            .json(&context_data)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("PCF".to_string()),
                "npcf-smpolicycontrol".to_string(),
            )
            .send()
            .await
            .context("Failed to send SM policy creation request to PCF")?;

        match response.status() {
            StatusCode::CREATED => {
                let policy_id = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|loc| loc.rsplit('/').next())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        tracing::warn!("Location header missing in PCF response, generating policy ID");
                        uuid::Uuid::new_v4().to_string()
                    });

                let policy_decision: SmPolicyDecision = response
                    .json()
                    .await
                    .context("Failed to parse SM policy decision from PCF")?;

                tracing::info!(
                    "Successfully created SM policy for SUPI {} with policy ID {}",
                    context_data.supi,
                    policy_id
                );

                Ok((policy_id, policy_decision))
            }
            StatusCode::BAD_REQUEST => {
                let problem: ProblemDetails = response
                    .json()
                    .await
                    .unwrap_or_else(|_| ProblemDetails {
                        problem_type: None,
                        title: Some("Bad Request".to_string()),
                        status: Some(400),
                        detail: None,
                        instance: None,
                        cause: None,
                        invalid_params: None,
                        supported_features: None,
                    });

                Err(anyhow::anyhow!(
                    "Bad request to PCF for SM policy creation: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::FORBIDDEN => {
                let problem: ProblemDetails = response
                    .json()
                    .await
                    .unwrap_or_else(|_| ProblemDetails {
                        problem_type: None,
                        title: Some("Forbidden".to_string()),
                        status: Some(403),
                        detail: None,
                        instance: None,
                        cause: None,
                        invalid_params: None,
                        supported_features: None,
                    });

                Err(anyhow::anyhow!(
                    "PCF rejected SM policy creation: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("PCF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to create SM policy at PCF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn update_sm_policy(
        &self,
        pcf_uri: &str,
        policy_id: &str,
        update_data: SmPolicyUpdateContextData,
    ) -> Result<SmPolicyDecision> {
        let url = format!(
            "{}/npcf-smpolicycontrol/v1/sm-policies/{}/update",
            pcf_uri, policy_id
        );

        let response = self
            .client
            .post(&url)
            .json(&update_data)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("PCF".to_string()),
                "npcf-smpolicycontrol".to_string(),
            )
            .send()
            .await
            .context("Failed to send SM policy update request to PCF")?;

        match response.status() {
            StatusCode::OK => {
                let policy_decision: SmPolicyDecision = response
                    .json()
                    .await
                    .context("Failed to parse updated SM policy decision from PCF")?;

                tracing::info!(
                    "Successfully updated SM policy {}",
                    policy_id
                );

                Ok(policy_decision)
            }
            StatusCode::BAD_REQUEST => {
                let problem: ProblemDetails = response
                    .json()
                    .await
                    .unwrap_or_else(|_| ProblemDetails {
                        problem_type: None,
                        title: Some("Bad Request".to_string()),
                        status: Some(400),
                        detail: None,
                        instance: None,
                        cause: None,
                        invalid_params: None,
                        supported_features: None,
                    });

                Err(anyhow::anyhow!(
                    "Bad request to PCF for SM policy update: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM policy {} not found at PCF",
                    policy_id
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("PCF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to update SM policy at PCF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn delete_sm_policy(
        &self,
        pcf_uri: &str,
        policy_id: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/npcf-smpolicycontrol/v1/sm-policies/{}/delete",
            pcf_uri, policy_id
        );

        let response = self
            .client
            .post(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("PCF".to_string()),
                "npcf-smpolicycontrol".to_string(),
            )
            .send()
            .await
            .context("Failed to send SM policy deletion request to PCF")?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => {
                tracing::info!(
                    "Successfully deleted SM policy {}",
                    policy_id
                );

                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM policy {} not found at PCF",
                    policy_id
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("PCF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to delete SM policy from PCF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn get_sm_policy(
        &self,
        pcf_uri: &str,
        policy_id: &str,
    ) -> Result<SmPolicyDecision> {
        let url = format!(
            "{}/npcf-smpolicycontrol/v1/sm-policies/{}",
            pcf_uri, policy_id
        );

        let response = self
            .client
            .get(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("PCF".to_string()),
                "npcf-smpolicycontrol".to_string(),
            )
            .send()
            .await
            .context("Failed to send SM policy retrieval request to PCF")?;

        match response.status() {
            StatusCode::OK => {
                let policy_decision: SmPolicyDecision = response
                    .json()
                    .await
                    .context("Failed to parse SM policy decision from PCF")?;

                tracing::info!(
                    "Successfully retrieved SM policy {}",
                    policy_id
                );

                Ok(policy_decision)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM policy {} not found at PCF",
                    policy_id
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("PCF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to retrieve SM policy from PCF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }
}
