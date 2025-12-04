mod config;
mod db;
mod handlers;
mod models;
mod types;

use axum::{Router, routing::{get, post}};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "smf=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = config::Config::from_env()?;

    let db = db::init(&config.mongodb_uri).await?;

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/nsmf-pdusession/v1/sm-contexts", post(handlers::pdu_session::create_pdu_session))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef", get(handlers::pdu_session::retrieve_pdu_session))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/modify", post(handlers::pdu_session::update_pdu_session))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/release", post(handlers::pdu_session::release_pdu_session))
        .layer(TraceLayer::new_for_http())
        .with_state(db);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Starting SMF server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
