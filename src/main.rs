mod config;
mod db;
mod handlers;
mod models;
mod services;
mod types;
mod utils;

use axum::{Router, routing::{get, post, put, delete}};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tokio::signal;

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

    let state = db::init(&config).await?;

    if let Some(ref nrf_registration) = state.nrf_registration {
        if let Err(e) = nrf_registration.register().await {
            tracing::error!("Failed to register with NRF: {}", e);
        } else {
            nrf_registration.start_heartbeat().await;
        }
    }

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/nsmf-pdusession/v1/sm-contexts", post(handlers::pdu_session::create_pdu_session))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef", get(handlers::pdu_session::retrieve_pdu_session))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/modify", post(handlers::pdu_session::update_pdu_session))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/release", post(handlers::pdu_session::release_pdu_session))
        .route("/nsmf-pdusession/v1/ue-contexts/:supi/sm-contexts", get(handlers::pdu_session::list_ue_pdu_sessions))
        .route("/nsmf-pdusession/v1/ue-contexts/:supi/sm-contexts/:pduSessionId", get(handlers::pdu_session::retrieve_pdu_session_by_supi))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/handover-required", post(handlers::pdu_session::handle_handover_required))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/handover-request-ack", post(handlers::pdu_session::handle_handover_request_ack))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/handover-notify", post(handlers::pdu_session::handle_handover_notify))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/handover-cancel", post(handlers::pdu_session::handle_handover_cancel))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/packet-filters", post(handlers::packet_filter::add_packet_filters))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/packet-filters", get(handlers::packet_filter::get_packet_filters))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/packet-filters", delete(handlers::packet_filter::remove_packet_filters))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/packet-filters/modify", post(handlers::packet_filter::modify_packet_filter))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/packet-filters/from-sdf", post(handlers::packet_filter::add_packet_filters_from_sdf))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/qos-rules", post(handlers::qos_rule::add_qos_rules))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/qos-rules", get(handlers::qos_rule::get_qos_rules))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/qos-rules", delete(handlers::qos_rule::remove_qos_rules))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/qos-rules/modify", post(handlers::qos_rule::modify_qos_rule))
        .route("/nsmf-pdusession/v1/sm-contexts/:smContextRef/qos-rules/apply", post(handlers::qos_rule::apply_qos_rules))
        .route("/nsmf-event-exposure/v1/subscriptions", post(handlers::event_exposure::create_event_subscription))
        .route("/nsmf-event-exposure/v1/subscriptions/:subscriptionId", put(handlers::event_exposure::update_event_subscription))
        .route("/nsmf-event-exposure/v1/subscriptions/:subscriptionId", delete(handlers::event_exposure::delete_event_subscription))
        .route("/nnrf-nfm/v1/nf-status-notify", post(handlers::nrf_notification::handle_nf_status_notification))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Starting SMF server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let nrf_reg_for_shutdown = state.nrf_registration.clone();

    tokio::select! {
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Shutdown signal received");
        }
    }

    if let Some(nrf_registration) = nrf_reg_for_shutdown {
        if let Err(e) = nrf_registration.deregister().await {
            tracing::error!("Failed to deregister from NRF: {}", e);
        }
    }

    tracing::info!("SMF shutdown complete");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn health_check() -> &'static str {
    "OK"
}
