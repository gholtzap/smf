use crate::types::{
    NFProfile, NfType, SearchResult, SubscriptionData,
    QueryParams,
};
use crate::types::oauth2_request::OAuth2ClientExt;
use crate::services::oauth2_client::OAuth2TokenClient;
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct NrfClient {
    client: Client,
    nrf_uri: String,
    nf_instance_id: String,
    profile: Arc<RwLock<Option<NFProfile>>>,
    oauth2_client: Option<Arc<OAuth2TokenClient>>,
}

impl NrfClient {
    pub fn new(nrf_uri: String, nf_instance_id: String) -> Self {
        Self {
            client: Client::new(),
            nrf_uri,
            nf_instance_id,
            profile: Arc::new(RwLock::new(None)),
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

    pub async fn register(&self, profile: NFProfile) -> Result<NFProfile> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri, self.nf_instance_id
        );

        let response = self
            .client
            .put(&url)
            .json(&profile)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send registration request to NRF")?;

        match response.status() {
            StatusCode::CREATED | StatusCode::OK => {
                let registered_profile: NFProfile = response
                    .json()
                    .await
                    .context("Failed to parse NRF registration response")?;

                let mut current_profile = self.profile.write().await;
                *current_profile = Some(registered_profile.clone());

                tracing::info!(
                    "Successfully registered NF instance {} with NRF",
                    self.nf_instance_id
                );

                Ok(registered_profile)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF registration failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn update(&self, profile: NFProfile) -> Result<NFProfile> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri, self.nf_instance_id
        );

        let response = self
            .client
            .patch(&url)
            .json(&profile)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send update request to NRF")?;

        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                let mut current_profile = self.profile.write().await;
                *current_profile = Some(profile.clone());

                tracing::info!(
                    "Successfully updated NF instance {} with NRF",
                    self.nf_instance_id
                );

                Ok(profile)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF update failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn deregister(&self) -> Result<()> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri, self.nf_instance_id
        );

        let response = self
            .client
            .delete(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send deregistration request to NRF")?;

        match response.status() {
            StatusCode::NO_CONTENT => {
                let mut current_profile = self.profile.write().await;
                *current_profile = None;

                tracing::info!(
                    "Successfully deregistered NF instance {} from NRF",
                    self.nf_instance_id
                );

                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF deregistration failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn get_profile(&self, nf_instance_id: &str) -> Result<NFProfile> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri, nf_instance_id
        );

        let response = self
            .client
            .get(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send get profile request to NRF")?;

        match response.status() {
            StatusCode::OK => {
                let profile: NFProfile = response
                    .json()
                    .await
                    .context("Failed to parse NRF profile response")?;

                Ok(profile)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!("NF instance {} not found in NRF", nf_instance_id))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF get profile failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn discover(
        &self,
        target_nf_type: NfType,
        query_params: Option<QueryParams>,
    ) -> Result<SearchResult> {
        let mut url = format!(
            "{}/nnrf-disc/v1/nf-instances?target-nf-type={:?}",
            self.nrf_uri, target_nf_type
        );

        if let Some(params) = query_params {
            for (key, value) in params {
                url.push_str(&format!("&{}={}", key, value));
            }
        }

        let response = self
            .client
            .get(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-disc".to_string(),
            )
            .send()
            .await
            .context("Failed to send discovery request to NRF")?;

        match response.status() {
            StatusCode::OK => {
                let search_result: SearchResult = response
                    .json()
                    .await
                    .context("Failed to parse NRF discovery response")?;

                tracing::info!(
                    "Discovered {} instances of {:?} from NRF",
                    search_result.nf_instances.len(),
                    target_nf_type
                );

                Ok(search_result)
            }
            StatusCode::NOT_FOUND => {
                Ok(SearchResult {
                    validity_period: None,
                    nf_instances: vec![],
                    search_id: None,
                    num_nf_inst_complete: Some(0),
                })
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF discovery failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn subscribe(&self, subscription: SubscriptionData) -> Result<SubscriptionData> {
        let url = format!("{}/nnrf-nfm/v1/subscriptions", self.nrf_uri);

        let response = self
            .client
            .post(&url)
            .json(&subscription)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send subscription request to NRF")?;

        match response.status() {
            StatusCode::CREATED => {
                let created_subscription: SubscriptionData = response
                    .json()
                    .await
                    .context("Failed to parse NRF subscription response")?;

                tracing::info!(
                    "Successfully created subscription with NRF: {:?}",
                    created_subscription.subscription_id
                );

                Ok(created_subscription)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF subscription failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn unsubscribe(&self, subscription_id: &str) -> Result<()> {
        let url = format!(
            "{}/nnrf-nfm/v1/subscriptions/{}",
            self.nrf_uri, subscription_id
        );

        let response = self
            .client
            .delete(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send unsubscribe request to NRF")?;

        match response.status() {
            StatusCode::NO_CONTENT => {
                tracing::info!(
                    "Successfully deleted subscription {} from NRF",
                    subscription_id
                );

                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF unsubscribe failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn heartbeat(&self) -> Result<()> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri, self.nf_instance_id
        );

        let patch_doc = serde_json::json!([
            {
                "op": "replace",
                "path": "/nfStatus",
                "value": "REGISTERED"
            }
        ]);

        let response = self
            .client
            .patch(&url)
            .json(&patch_doc)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("NRF".to_string()),
                "nnrf-nfm".to_string(),
            )
            .send()
            .await
            .context("Failed to send heartbeat to NRF")?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => {
                tracing::debug!(
                    "Heartbeat sent successfully for NF instance {}",
                    self.nf_instance_id
                );

                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "NRF heartbeat failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn get_current_profile(&self) -> Option<NFProfile> {
        self.profile.read().await.clone()
    }

    pub fn nrf_uri(&self) -> &str {
        &self.nrf_uri
    }

    pub fn nf_instance_id(&self) -> &str {
        &self.nf_instance_id
    }
}
