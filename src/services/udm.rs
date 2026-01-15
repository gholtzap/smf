use crate::types::{
    udm::{SessionManagementSubscriptionData, SdmSubscription},
    Snssai, PlmnId,
};
use crate::types::nrf::ProblemDetails;
use crate::types::oauth2_request::OAuth2ClientExt;
use crate::services::oauth2_client::OAuth2TokenClient;
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};
use std::sync::Arc;

pub struct UdmClient {
    client: Client,
    oauth2_client: Option<Arc<OAuth2TokenClient>>,
}

impl UdmClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| Client::new()),
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

    pub async fn get_sm_data(
        &self,
        udm_uri: &str,
        supi: &str,
        snssai: Option<&Snssai>,
        dnn: Option<&str>,
        plmn_id: Option<&PlmnId>,
    ) -> Result<SessionManagementSubscriptionData> {
        let mut url = format!(
            "{}/nudm-sdm/v2/{}/sm-data",
            udm_uri, supi
        );

        let mut query_params = Vec::new();

        if let Some(s) = snssai {
            let snssai_json = if let Some(sd) = &s.sd {
                serde_json::json!({
                    "sst": s.sst,
                    "sd": sd
                })
            } else {
                serde_json::json!({
                    "sst": s.sst
                })
            };
            query_params.push(format!("single-nssai={}", urlencoding::encode(&snssai_json.to_string())));
        }

        if let Some(d) = dnn {
            query_params.push(format!("dnn={}", urlencoding::encode(d)));
        }

        if let Some(p) = plmn_id {
            let plmn_json = serde_json::json!({
                "mcc": p.mcc,
                "mnc": p.mnc
            });
            query_params.push(format!("plmn-id={}", urlencoding::encode(&plmn_json.to_string())));
        }

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        let response = self
            .client
            .get(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("UDM".to_string()),
                "nudm-sdm".to_string(),
            )
            .send()
            .await
            .context("Failed to send request to UDM for SM data")?;

        match response.status() {
            StatusCode::OK => {
                let response_text = response
                    .text()
                    .await
                    .context("Failed to read response body from UDM")?;

                let sm_data_array: Vec<SessionManagementSubscriptionData> = serde_json::from_str(&response_text)
                    .map_err(|e| {
                        tracing::error!("Failed to deserialize UDM response: {}. Response was: {}", e, response_text);
                        anyhow::anyhow!("Failed to parse SM subscription data from UDM: {}", e)
                    })?;

                let sm_data = sm_data_array
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("UDM returned empty SM data array"))?;

                tracing::info!(
                    "Successfully retrieved SM subscription data for SUPI {} from UDM",
                    supi
                );

                Ok(sm_data)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM subscription data not found for SUPI {}",
                    supi
                ))
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
                    "Bad request to UDM: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDM temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to retrieve SM data from UDM with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn subscribe_sm_data(
        &self,
        udm_uri: &str,
        supi: &str,
        subscription: SdmSubscription,
    ) -> Result<SdmSubscription> {
        let url = format!(
            "{}/nudm-sdm/v2/{}/sdm-subscriptions",
            udm_uri, supi
        );

        let response = self
            .client
            .post(&url)
            .json(&subscription)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("UDM".to_string()),
                "nudm-sdm".to_string(),
            )
            .send()
            .await
            .context("Failed to send SDM subscription request to UDM")?;

        match response.status() {
            StatusCode::CREATED => {
                let created_subscription: SdmSubscription = response
                    .json()
                    .await
                    .context("Failed to parse SDM subscription response from UDM")?;

                tracing::info!(
                    "Successfully created SDM subscription for SUPI {} at UDM, subscription ID: {}",
                    supi,
                    created_subscription.subscription_id.as_ref().unwrap_or(&"N/A".to_string())
                );

                Ok(created_subscription)
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
                    "Bad request to UDM for SDM subscription: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDM temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to create SDM subscription at UDM with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn unsubscribe_sm_data(
        &self,
        udm_uri: &str,
        supi: &str,
        subscription_id: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/nudm-sdm/v2/{}/sdm-subscriptions/{}",
            udm_uri, supi, subscription_id
        );

        let response = self
            .client
            .delete(&url)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("UDM".to_string()),
                "nudm-sdm".to_string(),
            )
            .send()
            .await
            .context("Failed to send SDM unsubscribe request to UDM")?;

        match response.status() {
            StatusCode::NO_CONTENT => {
                tracing::info!(
                    "Successfully deleted SDM subscription {} for SUPI {} from UDM",
                    subscription_id,
                    supi
                );

                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SDM subscription {} not found for SUPI {}",
                    subscription_id,
                    supi
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDM temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to delete SDM subscription from UDM with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn modify_sm_subscription(
        &self,
        udm_uri: &str,
        supi: &str,
        subscription_id: &str,
        subscription: SdmSubscription,
    ) -> Result<SdmSubscription> {
        let url = format!(
            "{}/nudm-sdm/v2/{}/sdm-subscriptions/{}",
            udm_uri, supi, subscription_id
        );

        let response = self
            .client
            .put(&url)
            .json(&subscription)
            .with_oauth2_auth(
                self.oauth2_client.clone(),
                Some("UDM".to_string()),
                "nudm-sdm".to_string(),
            )
            .send()
            .await
            .context("Failed to send SDM subscription modification request to UDM")?;

        match response.status() {
            StatusCode::OK => {
                let modified_subscription: SdmSubscription = response
                    .json()
                    .await
                    .context("Failed to parse modified SDM subscription response from UDM")?;

                tracing::info!(
                    "Successfully modified SDM subscription {} for SUPI {} at UDM",
                    subscription_id,
                    supi
                );

                Ok(modified_subscription)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SDM subscription {} not found for SUPI {}",
                    subscription_id,
                    supi
                ))
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
                    "Bad request to UDM for SDM subscription modification: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDM temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to modify SDM subscription at UDM with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }
}
