use crate::types::oauth2::{AccessToken, TokenRequest, CachedToken};
use anyhow::{Result, Context};
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct OAuth2TokenClient {
    client: Client,
    token_endpoint: String,
    nf_instance_id: String,
    nf_type: Option<String>,
    token_cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    refresh_buffer_seconds: i64,
}

impl OAuth2TokenClient {
    pub fn new(
        token_endpoint: String,
        nf_instance_id: String,
        nf_type: Option<String>,
    ) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| Client::new()),
            token_endpoint,
            nf_instance_id,
            nf_type,
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            refresh_buffer_seconds: 300,
        }
    }

    pub async fn get_token(
        &self,
        target_nf_type: Option<String>,
        scope: &str,
    ) -> Result<String> {
        let cache_key = self.make_cache_key(target_nf_type.as_deref(), scope);

        {
            let cache = self.token_cache.read().await;
            if let Some(cached_token) = cache.get(&cache_key) {
                if cached_token.is_valid() && !cached_token.expires_soon(self.refresh_buffer_seconds) {
                    tracing::debug!("Using cached OAuth2 token for scope: {}", scope);
                    return Ok(cached_token.access_token.clone());
                }
            }
        }

        tracing::info!("Requesting new OAuth2 token for scope: {}", scope);
        let token = self.request_token(target_nf_type.clone(), scope).await?;

        let cached_token = CachedToken::from_access_token(token);
        let access_token = cached_token.access_token.clone();

        {
            let mut cache = self.token_cache.write().await;
            cache.insert(cache_key, cached_token);
        }

        Ok(access_token)
    }

    async fn request_token(
        &self,
        target_nf_type: Option<String>,
        scope: &str,
    ) -> Result<AccessToken> {
        let token_request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            nf_instance_id: self.nf_instance_id.clone(),
            nf_type: self.nf_type.clone(),
            target_nf_instance_id: None,
            target_nf_type: target_nf_type.clone(),
            scope: scope.to_string(),
        };

        let response = self
            .client
            .post(&self.token_endpoint)
            .form(&token_request)
            .send()
            .await
            .context("Failed to send OAuth2 token request")?;

        match response.status() {
            StatusCode::OK => {
                let access_token: AccessToken = response
                    .json()
                    .await
                    .context("Failed to parse OAuth2 token response")?;

                tracing::info!(
                    "Successfully obtained OAuth2 token (expires in {} seconds)",
                    access_token.expires_in
                );

                Ok(access_token)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow::anyhow!(
                    "OAuth2 token request failed with status {}: {}",
                    status,
                    error_body
                ))
            }
        }
    }

    fn make_cache_key(&self, target_nf_type: Option<&str>, scope: &str) -> String {
        format!(
            "{}:{}:{}",
            self.nf_instance_id,
            target_nf_type.unwrap_or("default"),
            scope
        )
    }

    pub async fn invalidate_token(&self, target_nf_type: Option<String>, scope: &str) {
        let cache_key = self.make_cache_key(target_nf_type.as_deref(), scope);
        let mut cache = self.token_cache.write().await;
        cache.remove(&cache_key);
        tracing::debug!("Invalidated cached token for scope: {}", scope);
    }

    pub async fn clear_cache(&self) {
        let mut cache = self.token_cache.write().await;
        cache.clear();
        tracing::info!("Cleared OAuth2 token cache");
    }

    pub fn with_refresh_buffer(mut self, buffer_seconds: i64) -> Self {
        self.refresh_buffer_seconds = buffer_seconds;
        self
    }
}
