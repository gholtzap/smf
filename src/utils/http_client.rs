use reqwest::Client;
use anyhow::Result;

pub fn build_mtls_client(
    _client_cert_path: &str,
    _client_key_path: &str,
) -> Result<Client> {
    Err(anyhow::anyhow!(
        "Client-side mTLS certificates for outbound requests require additional dependencies. \
        Configure TLS_CLIENT_CERT_PATH and TLS_CLIENT_KEY_PATH after adding the required features to Cargo.toml."
    ))
}
