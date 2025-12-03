use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub mongodb_uri: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()?;

        let mongodb_uri = env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());

        Ok(Self { port, mongodb_uri })
    }
}
