use crate::types::{
    N1N2MessageTransferRequest, N1N2MessageTransferResponse,
    UeContextTransferRequest, UeContextTransferResponse, MultipartBody,
};
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode, multipart};
use std::collections::HashMap;

pub struct AmfClient {
    client: Client,
}

impl AmfClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    pub async fn n1n2_message_transfer(
        &self,
        amf_uri: &str,
        ue_id: &str,
        request: N1N2MessageTransferRequest,
        multipart_data: Option<MultipartBody>,
    ) -> Result<N1N2MessageTransferResponse> {
        let url = format!(
            "{}/namf-comm/v1/ue-contexts/{}/n1-n2-messages",
            amf_uri, ue_id
        );

        let response = if let Some(parts) = multipart_data {
            let mut form = multipart::Form::new();

            form = form.text("jsonData", serde_json::to_string(&request)?);

            for (part_name, part) in parts {
                form = form.part(
                    part_name,
                    multipart::Part::bytes(part.data)
                        .mime_str(&part.content_type)?
                );
            }

            self.client
                .post(&url)
                .multipart(form)
                .send()
                .await
                .context("Failed to send N1N2 message transfer request to AMF")?
        } else {
            self.client
                .post(&url)
                .json(&request)
                .send()
                .await
                .context("Failed to send N1N2 message transfer request to AMF")?
        };

        match response.status() {
            StatusCode::OK | StatusCode::ACCEPTED => {
                let transfer_response: N1N2MessageTransferResponse = response
                    .json()
                    .await
                    .context("Failed to parse N1N2 message transfer response")?;

                tracing::info!(
                    "Successfully transferred N1N2 message to UE {} via AMF",
                    ue_id
                );

                Ok(transfer_response)
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                Err(anyhow::anyhow!("AMF temporarily unavailable"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "N1N2 message transfer failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn n1n2_message_transfer_status(
        &self,
        amf_uri: &str,
        ue_id: &str,
        transaction_id: &str,
    ) -> Result<N1N2MessageTransferResponse> {
        let url = format!(
            "{}/namf-comm/v1/ue-contexts/{}/n1-n2-messages/{}",
            amf_uri, ue_id, transaction_id
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send N1N2 message transfer status request to AMF")?;

        match response.status() {
            StatusCode::OK => {
                let transfer_response: N1N2MessageTransferResponse = response
                    .json()
                    .await
                    .context("Failed to parse N1N2 message transfer status response")?;

                Ok(transfer_response)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!("Transaction {} not found", transaction_id))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "N1N2 message transfer status query failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn ue_context_transfer(
        &self,
        amf_uri: &str,
        ue_id: &str,
        request: UeContextTransferRequest,
    ) -> Result<UeContextTransferResponse> {
        let url = format!(
            "{}/namf-comm/v1/ue-contexts/{}/transfer",
            amf_uri, ue_id
        );

        let response = if request.binary_data_n2_information.is_some() {
            let mut form = multipart::Form::new();

            if let Some(json_data) = &request.json_data {
                form = form.text("jsonData", serde_json::to_string(json_data)?);
            }

            if let Some(binary_data) = &request.binary_data_n2_information {
                form = form.part(
                    "binaryDataN2Information",
                    multipart::Part::bytes(binary_data.clone())
                        .mime_str("application/vnd.3gpp.ngap")?
                );
            }

            self.client
                .post(&url)
                .multipart(form)
                .send()
                .await
                .context("Failed to send UE context transfer request to AMF")?
        } else {
            self.client
                .post(&url)
                .json(&request.json_data)
                .send()
                .await
                .context("Failed to send UE context transfer request to AMF")?
        };

        match response.status() {
            StatusCode::OK => {
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if content_type.contains("multipart/related") {
                    let boundary = content_type
                        .split("boundary=")
                        .nth(1)
                        .ok_or_else(|| anyhow::anyhow!("Missing multipart boundary"))?
                        .to_string();

                    let body = response.bytes().await?;
                    let parts = parse_multipart(&body, &boundary)?;

                    let json_data = parts
                        .get("jsonData")
                        .and_then(|data| serde_json::from_slice(data).ok());

                    let binary_data = parts.get("binaryDataN2Information").cloned();

                    Ok(UeContextTransferResponse {
                        json_data,
                        binary_data_n2_information: binary_data,
                    })
                } else {
                    let json_data = response
                        .json()
                        .await
                        .context("Failed to parse UE context transfer response")?;

                    Ok(UeContextTransferResponse {
                        json_data: Some(json_data),
                        binary_data_n2_information: None,
                    })
                }
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!("UE context {} not found", ue_id))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "UE context transfer failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn ue_context_release(
        &self,
        amf_uri: &str,
        ue_id: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/namf-comm/v1/ue-contexts/{}",
            amf_uri, ue_id
        );

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .context("Failed to send UE context release request to AMF")?;

        match response.status() {
            StatusCode::NO_CONTENT => {
                tracing::info!(
                    "Successfully released UE context {} from AMF",
                    ue_id
                );

                Ok(())
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!("UE context {} not found", ue_id))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "UE context release failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    pub async fn n2_info_notify(
        &self,
        callback_uri: &str,
        n2_info: Vec<u8>,
    ) -> Result<()> {
        let response = self
            .client
            .post(callback_uri)
            .header("Content-Type", "application/vnd.3gpp.ngap")
            .body(n2_info)
            .send()
            .await
            .context("Failed to send N2 info notification")?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => {
                tracing::debug!("N2 info notification sent successfully");
                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "N2 info notification failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }
}

fn parse_multipart(body: &[u8], boundary: &str) -> Result<HashMap<String, Vec<u8>>> {
    let mut parts = HashMap::new();

    let body_str = String::from_utf8_lossy(body);
    let sections: Vec<&str> = body_str.split(&format!("--{}", boundary)).collect();

    for section in sections.iter().skip(1) {
        if section.starts_with("--") || section.trim().is_empty() {
            continue;
        }

        let parts_split: Vec<&str> = section.splitn(2, "\r\n\r\n").collect();
        if parts_split.len() != 2 {
            continue;
        }

        let headers = parts_split[0];
        let content = parts_split[1].trim_end_matches("\r\n");

        if let Some(name) = extract_part_name(headers) {
            parts.insert(name, content.as_bytes().to_vec());
        }
    }

    Ok(parts)
}

fn extract_part_name(headers: &str) -> Option<String> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("content-disposition") {
            if let Some(name_start) = line.find("name=\"") {
                let name_start = name_start + 6;
                if let Some(name_end) = line[name_start..].find('"') {
                    return Some(line[name_start..name_start + name_end].to_string());
                }
            }
        }
    }
    None
}
