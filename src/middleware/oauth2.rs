use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose};
use crate::types::oauth2::{TokenClaims, ValidatedToken};

#[derive(Debug, Clone)]
pub struct OAuth2Config {
    pub enabled: bool,
    pub issuer: String,
    pub audience: Vec<String>,
    pub required_scope: Option<String>,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            audience: Vec::new(),
            required_scope: None,
        }
    }
}

pub async fn oauth2_validation_middleware(
    config: axum::extract::State<OAuth2Config>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..];

    let validated_token = validate_token(token, &config)?;

    req.extensions_mut().insert(validated_token);

    Ok(next.run(req).await)
}

fn validate_token(token: &str, config: &OAuth2Config) -> Result<ValidatedToken, StatusCode> {
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let payload = parts[1];

    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let claims: TokenClaims = serde_json::from_slice(&decoded)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if claims.is_expired() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !config.issuer.is_empty() && claims.iss != config.issuer {
        tracing::warn!("Token issuer mismatch: expected {}, got {}", config.issuer, claims.iss);
        return Err(StatusCode::FORBIDDEN);
    }

    if !config.audience.is_empty() {
        let has_valid_audience = claims.aud.iter().any(|aud| config.audience.contains(aud));
        if !has_valid_audience {
            tracing::warn!("Token audience mismatch: expected one of {:?}, got {:?}", config.audience, claims.aud);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    if let Some(ref required_scope) = config.required_scope {
        if !claims.has_scope(required_scope) {
            tracing::warn!("Token missing required scope: {}", required_scope);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(ValidatedToken {
        claims,
        raw_token: token.to_string(),
    })
}
