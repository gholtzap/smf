use async_trait::async_trait;
use crate::types::{CertificatePurpose, CertificateProviderType, CertificateRotationRequest};

#[async_trait]
pub trait CertificateProvider: Send + Sync {
    async fn get_certificate(
        &self,
        name: &str,
        purpose: CertificatePurpose,
    ) -> anyhow::Result<CertificateRotationRequest>;

    fn provider_type(&self) -> CertificateProviderType;
}

pub struct ManualCertificateProvider {
    certificate_pem: String,
    private_key_pem: Option<String>,
    certificate_chain_pem: Option<String>,
}

impl ManualCertificateProvider {
    pub fn new(
        certificate_pem: String,
        private_key_pem: Option<String>,
        certificate_chain_pem: Option<String>,
    ) -> Self {
        Self {
            certificate_pem,
            private_key_pem,
            certificate_chain_pem,
        }
    }
}

#[async_trait]
impl CertificateProvider for ManualCertificateProvider {
    async fn get_certificate(
        &self,
        _name: &str,
        _purpose: CertificatePurpose,
    ) -> anyhow::Result<CertificateRotationRequest> {
        Ok(CertificateRotationRequest {
            certificate_pem: self.certificate_pem.clone(),
            private_key_pem: self.private_key_pem.clone(),
            certificate_chain_pem: self.certificate_chain_pem.clone(),
        })
    }

    fn provider_type(&self) -> CertificateProviderType {
        CertificateProviderType::Manual
    }
}

pub struct ExternalCertificateProvider {
    endpoint: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl ExternalCertificateProvider {
    pub fn new(endpoint: String, api_key: Option<String>) -> Self {
        Self {
            endpoint,
            api_key,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }
}

#[async_trait]
impl CertificateProvider for ExternalCertificateProvider {
    async fn get_certificate(
        &self,
        name: &str,
        purpose: CertificatePurpose,
    ) -> anyhow::Result<CertificateRotationRequest> {
        let mut request = self.client
            .post(&self.endpoint)
            .json(&serde_json::json!({
                "name": name,
                "purpose": format!("{:?}", purpose),
            }));

        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "External provider returned status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        let cert_request: CertificateRotationRequest = response.json().await?;
        Ok(cert_request)
    }

    fn provider_type(&self) -> CertificateProviderType {
        CertificateProviderType::External
    }
}

pub fn create_provider(
    provider_type: CertificateProviderType,
    config: &serde_json::Value,
) -> anyhow::Result<Box<dyn CertificateProvider>> {
    match provider_type {
        CertificateProviderType::Manual => {
            let certificate_pem = config
                .get("certificate_pem")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing certificate_pem in manual provider config"))?
                .to_string();

            let private_key_pem = config
                .get("private_key_pem")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let certificate_chain_pem = config
                .get("certificate_chain_pem")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            Ok(Box::new(ManualCertificateProvider::new(
                certificate_pem,
                private_key_pem,
                certificate_chain_pem,
            )))
        }
        CertificateProviderType::External => {
            let endpoint = config
                .get("endpoint")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing endpoint in external provider config"))?
                .to_string();

            let api_key = config
                .get("api_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            Ok(Box::new(ExternalCertificateProvider::new(endpoint, api_key)))
        }
        CertificateProviderType::Acme => {
            Err(anyhow::anyhow!("ACME provider not yet implemented"))
        }
    }
}
