use crate::types::{
    udr::{SessionManagementSubscriptionData, SmfSelectionSubscriptionData},
    Snssai, PlmnId,
};
use crate::types::nrf::ProblemDetails;
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};

pub struct UdrClient {
    client: Client,
}

impl UdrClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    pub async fn get_sm_data(
        &self,
        udr_uri: &str,
        supi: &str,
        snssai: &Snssai,
        dnn: Option<&str>,
        plmn_id: Option<&PlmnId>,
    ) -> Result<SessionManagementSubscriptionData> {
        let snssai_str = if let Some(sd) = &snssai.sd {
            format!("{}-{}", snssai.sst, sd)
        } else {
            snssai.sst.to_string()
        };

        let mut url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-registrations/{}",
            udr_uri, supi, snssai_str
        );

        let mut query_params = Vec::new();

        if let Some(d) = dnn {
            query_params.push(format!("dnn={}", urlencoding::encode(d)));
        }

        if let Some(p) = plmn_id {
            let plmn_str = format!("{}-{}", p.mcc, p.mnc);
            query_params.push(format!("plmn-id={}", urlencoding::encode(&plmn_str)));
        }

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to UDR for SM data")?;

        match response.status() {
            StatusCode::OK => {
                let sm_data: SessionManagementSubscriptionData = response
                    .json()
                    .await
                    .context("Failed to parse SM subscription data from UDR")?;

                tracing::info!(
                    "Successfully retrieved SM subscription data for SUPI {} from UDR",
                    supi
                );

                Ok(sm_data)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM subscription data not found for SUPI {} in UDR",
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
                    "Bad request to UDR: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDR temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to retrieve SM data from UDR with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn create_sm_data(
        &self,
        udr_uri: &str,
        supi: &str,
        snssai: &Snssai,
        sm_data: SessionManagementSubscriptionData,
    ) -> Result<SessionManagementSubscriptionData> {
        let snssai_str = if let Some(sd) = &snssai.sd {
            format!("{}-{}", snssai.sst, sd)
        } else {
            snssai.sst.to_string()
        };

        let url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-registrations/{}",
            udr_uri, supi, snssai_str
        );

        let response = self
            .client
            .put(&url)
            .json(&sm_data)
            .send()
            .await
            .context("Failed to send SM data creation request to UDR")?;

        match response.status() {
            StatusCode::CREATED | StatusCode::OK => {
                let created_data: SessionManagementSubscriptionData = response
                    .json()
                    .await
                    .context("Failed to parse SM data creation response from UDR")?;

                tracing::info!(
                    "Successfully created SM subscription data for SUPI {} in UDR",
                    supi
                );

                Ok(created_data)
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
                    "Bad request to UDR for SM data creation: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDR temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to create SM data in UDR with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn update_sm_data(
        &self,
        udr_uri: &str,
        supi: &str,
        snssai: &Snssai,
        sm_data: SessionManagementSubscriptionData,
    ) -> Result<SessionManagementSubscriptionData> {
        let snssai_str = if let Some(sd) = &snssai.sd {
            format!("{}-{}", snssai.sst, sd)
        } else {
            snssai.sst.to_string()
        };

        let url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-registrations/{}",
            udr_uri, supi, snssai_str
        );

        let response = self
            .client
            .patch(&url)
            .json(&sm_data)
            .send()
            .await
            .context("Failed to send SM data update request to UDR")?;

        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                if response.status() == StatusCode::OK {
                    let updated_data: SessionManagementSubscriptionData = response
                        .json()
                        .await
                        .context("Failed to parse SM data update response from UDR")?;

                    tracing::info!(
                        "Successfully updated SM subscription data for SUPI {} in UDR",
                        supi
                    );

                    Ok(updated_data)
                } else {
                    tracing::info!(
                        "Successfully updated SM subscription data for SUPI {} in UDR",
                        supi
                    );

                    Ok(sm_data)
                }
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM subscription data not found for SUPI {} in UDR",
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
                    "Bad request to UDR for SM data update: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDR temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to update SM data in UDR with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn delete_sm_data(
        &self,
        udr_uri: &str,
        supi: &str,
        snssai: &Snssai,
    ) -> Result<()> {
        let snssai_str = if let Some(sd) = &snssai.sd {
            format!("{}-{}", snssai.sst, sd)
        } else {
            snssai.sst.to_string()
        };

        let url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-registrations/{}",
            udr_uri, supi, snssai_str
        );

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .context("Failed to send SM data deletion request to UDR")?;

        match response.status() {
            StatusCode::NO_CONTENT => {
                tracing::info!(
                    "Successfully deleted SM subscription data for SUPI {} from UDR",
                    supi
                );

                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SM subscription data not found for SUPI {} in UDR",
                    supi
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDR temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to delete SM data from UDR with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn get_smf_selection_data(
        &self,
        udr_uri: &str,
        supi: &str,
        plmn_id: Option<&PlmnId>,
    ) -> Result<SmfSelectionSubscriptionData> {
        let mut url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-selection-subscription-data",
            udr_uri, supi
        );

        if let Some(p) = plmn_id {
            let plmn_str = format!("{}-{}", p.mcc, p.mnc);
            url.push_str(&format!("?plmn-id={}", urlencoding::encode(&plmn_str)));
        }

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to UDR for SMF selection data")?;

        match response.status() {
            StatusCode::OK => {
                let selection_data: SmfSelectionSubscriptionData = response
                    .json()
                    .await
                    .context("Failed to parse SMF selection subscription data from UDR")?;

                tracing::info!(
                    "Successfully retrieved SMF selection subscription data for SUPI {} from UDR",
                    supi
                );

                Ok(selection_data)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!(
                    "SMF selection subscription data not found for SUPI {} in UDR",
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
                    "Bad request to UDR: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDR temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to retrieve SMF selection data from UDR with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn create_smf_selection_data(
        &self,
        udr_uri: &str,
        supi: &str,
        selection_data: SmfSelectionSubscriptionData,
    ) -> Result<SmfSelectionSubscriptionData> {
        let url = format!(
            "{}/nudr-dr/v2/subscription-data/{}/context-data/smf-selection-subscription-data",
            udr_uri, supi
        );

        let response = self
            .client
            .put(&url)
            .json(&selection_data)
            .send()
            .await
            .context("Failed to send SMF selection data creation request to UDR")?;

        match response.status() {
            StatusCode::CREATED | StatusCode::OK => {
                let created_data: SmfSelectionSubscriptionData = response
                    .json()
                    .await
                    .context("Failed to parse SMF selection data creation response from UDR")?;

                tracing::info!(
                    "Successfully created SMF selection subscription data for SUPI {} in UDR",
                    supi
                );

                Ok(created_data)
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
                    "Bad request to UDR for SMF selection data creation: {} - {}",
                    problem.title.unwrap_or_default(),
                    problem.detail.unwrap_or_default()
                ))
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("UDR temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to create SMF selection data in UDR with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }
}
