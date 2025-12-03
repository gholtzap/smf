use mongodb::{Client, Database};

pub type AppState = Database;

pub async fn init(uri: &str) -> anyhow::Result<Database> {
    let client = Client::with_uri_str(uri).await?;
    let db = client.database("smf");

    tracing::info!("Connected to MongoDB");

    Ok(db)
}
