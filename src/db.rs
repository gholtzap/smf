use mongodb::{Client, Database};
use std::sync::Arc;
use crate::services::notification::NotificationService;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub notification_service: Arc<NotificationService>,
}

pub async fn init(uri: &str) -> anyhow::Result<AppState> {
    let client = Client::with_uri_str(uri).await?;
    let db = client.database("smf");

    tracing::info!("Connected to MongoDB");

    let notification_service = Arc::new(NotificationService::new());

    Ok(AppState {
        db,
        notification_service,
    })
}
