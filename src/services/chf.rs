use crate::types::chf::{ChargingDataRequest, ChargingDataResponse};
use crate::types::nrf::ProblemDetails;
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};

pub struct ChfClient {
    client: Client,
}

impl ChfClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn create_charging_session(
        &self,
        chf_uri: &str,
        charging_request: ChargingDataRequest,
    ) -> Result<(String, ChargingDataResponse)> {
        let url = format!("{}/nchf-convergedcharging/v3/chargingdata", chf_uri);

        let response = self
            .client
            .post(&url)
            .json(&charging_request)
            .send()
            .await
            .context("Failed to send charging data request to CHF")?;

        match response.status() {
            StatusCode::CREATED => {
                let charging_ref = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|loc| loc.rsplit('/').next())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        tracing::warn!("Location header missing in CHF response, generating charging reference");
                        uuid::Uuid::new_v4().to_string()
                    });

                let charging_response: ChargingDataResponse = response
                    .json()
                    .await
                    .context("Failed to parse charging data response from CHF")?;

                tracing::info!(
                    "Successfully created charging session for SUPI {} with charging ref {}",
                    charging_request.subscriber_identifier,
                    charging_ref
                );

                Ok((charging_ref, charging_response))
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
                    "Bad request to CHF for charging session creation: {} - {}",
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
                    "CHF rejected charging session creation: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("CHF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to create charging session at CHF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn update_charging_session(
        &self,
        chf_uri: &str,
        charging_ref: &str,
        charging_request: ChargingDataRequest,
    ) -> Result<ChargingDataResponse> {
        let url = format!(
            "{}/nchf-convergedcharging/v3/chargingdata/{}/update",
            chf_uri, charging_ref
        );

        let response = self
            .client
            .post(&url)
            .json(&charging_request)
            .send()
            .await
            .context("Failed to send charging data update request to CHF")?;

        match response.status() {
            StatusCode::OK => {
                let charging_response: ChargingDataResponse = response
                    .json()
                    .await
                    .context("Failed to parse updated charging data response from CHF")?;

                tracing::info!(
                    "Successfully updated charging session {}",
                    charging_ref
                );

                Ok(charging_response)
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
                    "Bad request to CHF for charging session update: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "Charging session {} not found at CHF",
                    charging_ref
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("CHF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to update charging session at CHF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn release_charging_session(
        &self,
        chf_uri: &str,
        charging_ref: &str,
        charging_request: ChargingDataRequest,
    ) -> Result<()> {
        let url = format!(
            "{}/nchf-convergedcharging/v3/chargingdata/{}/release",
            chf_uri, charging_ref
        );

        let response = self
            .client
            .post(&url)
            .json(&charging_request)
            .send()
            .await
            .context("Failed to send charging data release request to CHF")?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => {
                tracing::info!(
                    "Successfully released charging session {}",
                    charging_ref
                );

                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "Charging session {} not found at CHF",
                    charging_ref
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("CHF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to release charging session from CHF with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }
}
