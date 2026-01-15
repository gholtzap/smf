use std::env;
use crate::middleware::OAuth2Config;

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub client_ca_path: Option<String>,
    pub require_client_cert: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub mongodb_uri: String,
    pub upf_host: String,
    pub upf_port: u16,
    pub pfcp_bind_addr: String,
    pub pfcp_bind_port: u16,
    pub nrf_uri: Option<String>,
    pub pcf_uri: Option<String>,
    pub udm_uri: Option<String>,
    pub chf_uri: Option<String>,
    pub nf_instance_id: String,
    pub smf_host: String,
    pub oauth2: OAuth2Config,
    pub tls: TlsConfig,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()?;

        let mongodb_uri = env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());

        let upf_host = env::var("UPF_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        let upf_port = env::var("UPF_PORT")
            .unwrap_or_else(|_| "8805".to_string())
            .parse()?;

        let pfcp_bind_addr = env::var("PFCP_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0".to_string());

        let pfcp_bind_port = env::var("PFCP_BIND_PORT")
            .unwrap_or_else(|_| "8805".to_string())
            .parse()?;

        let nrf_uri = env::var("NRF_URI").ok();

        let pcf_uri = env::var("PCF_URI").ok();

        let udm_uri = env::var("UDM_URI").ok();

        let chf_uri = env::var("CHF_URI").ok();

        let nf_instance_id = env::var("NF_INSTANCE_ID")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        let smf_host = env::var("SMF_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        let oauth2_enabled = env::var("OAUTH2_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let oauth2_issuer = env::var("OAUTH2_ISSUER")
            .unwrap_or_else(|_| "".to_string());

        let oauth2_audience = env::var("OAUTH2_AUDIENCE")
            .unwrap_or_else(|_| "".to_string())
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        let oauth2_required_scope = env::var("OAUTH2_REQUIRED_SCOPE").ok();

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "".to_string());

        let oauth2 = OAuth2Config {
            enabled: oauth2_enabled,
            issuer: oauth2_issuer,
            audience: oauth2_audience,
            required_scope: oauth2_required_scope,
            secret_key: jwt_secret,
        };

        let tls_enabled = env::var("TLS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let tls_cert_path = env::var("TLS_CERT_PATH").ok();
        let tls_key_path = env::var("TLS_KEY_PATH").ok();
        let tls_client_cert_path = env::var("TLS_CLIENT_CERT_PATH").ok();
        let tls_client_key_path = env::var("TLS_CLIENT_KEY_PATH").ok();
        let tls_client_ca_path = env::var("TLS_CLIENT_CA_PATH").ok();
        let tls_require_client_cert = env::var("TLS_REQUIRE_CLIENT_CERT")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let tls = TlsConfig {
            enabled: tls_enabled,
            cert_path: tls_cert_path,
            key_path: tls_key_path,
            client_cert_path: tls_client_cert_path,
            client_key_path: tls_client_key_path,
            client_ca_path: tls_client_ca_path,
            require_client_cert: tls_require_client_cert,
        };

        Ok(Self {
            port,
            mongodb_uri,
            upf_host,
            upf_port,
            pfcp_bind_addr,
            pfcp_bind_port,
            nrf_uri,
            pcf_uri,
            udm_uri,
            chf_uri,
            nf_instance_id,
            smf_host,
            oauth2,
            tls,
        })
    }
}
