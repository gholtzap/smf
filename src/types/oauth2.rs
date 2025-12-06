use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
    pub nf_instance_id: Option<String>,
    pub nf_type: Option<String>,
}

impl TokenClaims {
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.exp
    }

    pub fn has_scope(&self, required_scope: &str) -> bool {
        self.scope
            .split_whitespace()
            .any(|s| s == required_scope)
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub claims: TokenClaims,
    pub raw_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<Vec<String>>,
    pub iss: Option<String>,
    pub nf_instance_id: Option<String>,
    pub nf_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub nf_instance_id: String,
    pub nf_type: Option<String>,
    pub target_nf_instance_id: Option<String>,
    pub target_nf_type: Option<String>,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct CachedToken {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
}

impl CachedToken {
    pub fn from_access_token(token: AccessToken) -> Self {
        let expires_at = Utc::now() + Duration::seconds(token.expires_in);
        Self {
            access_token: token.access_token,
            expires_at,
            scope: token.scope.unwrap_or_default(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    pub fn expires_soon(&self, buffer_seconds: i64) -> bool {
        let buffer_time = Utc::now() + Duration::seconds(buffer_seconds);
        buffer_time >= self.expires_at
    }
}
