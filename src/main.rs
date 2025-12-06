mod config;
mod db;
mod handlers;
mod models;
mod parsers;
mod services;
mod types;
mod utils;
mod middleware;

use axum::{Router, routing::{get, post, put, delete}, middleware as axum_middleware};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tokio::signal;
use axum_server::tls_rustls::RustlsConfig;

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

    let mut protected_routes = Router::new()
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
        .route("/nsmf-event-exposure/v1/subscriptions/:subscriptionId", delete(handlers::event_exposure::delete_event_subscription));

    if config.oauth2.enabled {
        tracing::info!("OAuth2 authentication enabled");
        let oauth2_config = config.oauth2.clone();
        protected_routes = protected_routes.route_layer(axum_middleware::from_fn_with_state(oauth2_config, middleware::oauth2_validation_middleware));
    }

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/nnrf-nfm/v1/nf-status-notify", post(handlers::nrf_notification::handle_nf_status_notification))
        .route("/namf-callback/v1/ue-contexts/:ueId/n1-n2-transfers/:transactionId/notify", post(handlers::amf_callback::handle_n1n2_transfer_status))
        .route("/namf-callback/v1/sm-contexts/:ueId/pdu-sessions/:pduSessionId/n2-notify", post(handlers::amf_callback::handle_n2_info_notify));

    let app = Router::new()
        .merge(protected_routes)
        .merge(public_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    let nrf_reg_for_shutdown = state.nrf_registration.clone();

    if config.tls.enabled {
        let cert_path = config.tls.cert_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS enabled but TLS_CERT_PATH not set"))?;
        let key_path = config.tls.key_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS enabled but TLS_KEY_PATH not set"))?;

        tracing::info!("Starting SMF server with TLS on https://{}", addr);
        let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

        tokio::select! {
            result = axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service()) => {
                if let Err(e) = result {
                    tracing::error!("Server error: {}", e);
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("Shutdown signal received");
            }
        }
    } else {
        tracing::info!("Starting SMF server on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;

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
