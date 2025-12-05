use std::env;

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
    pub nf_instance_id: String,
    pub smf_host: String,
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

        let nf_instance_id = env::var("NF_INSTANCE_ID")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        let smf_host = env::var("SMF_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        Ok(Self {
            port,
            mongodb_uri,
            upf_host,
            upf_port,
            pfcp_bind_addr,
            pfcp_bind_port,
            nrf_uri,
            pcf_uri,
            nf_instance_id,
            smf_host,
        })
    }
}
