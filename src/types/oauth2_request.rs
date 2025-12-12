use crate::services::oauth2_client::OAuth2TokenClient;
use anyhow::Result;
use reqwest::RequestBuilder;
use std::sync::Arc;

pub struct OAuth2RequestBuilder {
    request_builder: RequestBuilder,
    oauth2_client: Option<Arc<OAuth2TokenClient>>,
    target_nf_type: Option<String>,
    scope: Option<String>,
}

impl OAuth2RequestBuilder {
    pub fn new(request_builder: RequestBuilder) -> Self {
        Self {
            request_builder,
            oauth2_client: None,
            target_nf_type: None,
            scope: None,
        }
    }

    pub fn with_oauth2(
        mut self,
        client: Arc<OAuth2TokenClient>,
        target_nf_type: Option<String>,
        scope: String,
    ) -> Self {
        self.oauth2_client = Some(client);
        self.target_nf_type = target_nf_type;
        self.scope = Some(scope);
        self
    }

    pub async fn send(self) -> Result<reqwest::Response> {
        let request_builder = if let Some(oauth2_client) = self.oauth2_client {
            let scope = self.scope.unwrap_or_else(|| "nsmf".to_string());
            let token = oauth2_client.get_token(self.target_nf_type, &scope).await?;
            self.request_builder.bearer_auth(token)
        } else {
            self.request_builder
        };

        Ok(request_builder.send().await?)
    }
}

pub trait OAuth2ClientExt {
    fn with_oauth2_auth(
        self,
        oauth2_client: Option<Arc<OAuth2TokenClient>>,
        target_nf_type: Option<String>,
        scope: String,
    ) -> OAuth2RequestBuilder;
}

impl OAuth2ClientExt for RequestBuilder {
    fn with_oauth2_auth(
        self,
        oauth2_client: Option<Arc<OAuth2TokenClient>>,
        target_nf_type: Option<String>,
        scope: String,
    ) -> OAuth2RequestBuilder {
        let mut builder = OAuth2RequestBuilder::new(self);
        if let Some(client) = oauth2_client {
            builder = builder.with_oauth2(client, target_nf_type, scope);
        }
        builder
    }
}
