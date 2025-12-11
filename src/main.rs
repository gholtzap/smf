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
use rustls::{ServerConfig, RootCertStore};
use rustls::server::WebPkiClientVerifier;
use std::sync::Arc;
use std::io::BufReader;
use rustls_pemfile::{certs, pkcs8_private_keys};

async fn build_mtls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
    require_client_cert: bool,
) -> anyhow::Result<RustlsConfig> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;
    let ca_file = std::fs::File::open(client_ca_path)?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);
    let mut ca_reader = BufReader::new(ca_file);

    let cert_chain: Vec<rustls::pki_types::CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    let mut keys = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()?;

    if keys.is_empty() {
        return Err(anyhow::anyhow!("No private keys found in key file"));
    }

    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0));

    let mut root_cert_store = RootCertStore::empty();
    let ca_certs: Vec<rustls::pki_types::CertificateDer> = certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()?;

    for cert in ca_certs {
        root_cert_store.add(cert)?;
    }

    let client_verifier = if require_client_cert {
        WebPkiClientVerifier::builder(Arc::new(root_cert_store))
            .build()?
    } else {
        WebPkiClientVerifier::builder(Arc::new(root_cert_store))
            .build()?
    };

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

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
        .route("/nsmf-pdusession/v1/sm-contexts/transfer", post(handlers::pdu_session::receive_context_transfer))
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
        .route("/admin/certificates/:name/:purpose/rotate", post(handlers::certificate_rotation::rotate_certificate))
        .route("/admin/certificates/rotations/rollback", post(handlers::certificate_rotation::rollback_certificate_rotation))
        .route("/admin/certificates/rotations/history", get(handlers::certificate_rotation::get_rotation_history))
        .route("/admin/certificates/auto-rotation/configs", post(handlers::certificate_auto_rotation::create_auto_rotation_config))
        .route("/admin/certificates/auto-rotation/configs", get(handlers::certificate_auto_rotation::list_auto_rotation_configs))
        .route("/admin/certificates/auto-rotation/configs/:config_id", get(handlers::certificate_auto_rotation::get_auto_rotation_config))
        .route("/admin/certificates/auto-rotation/configs/:config_id", put(handlers::certificate_auto_rotation::update_auto_rotation_config))
        .route("/admin/certificates/auto-rotation/configs/:config_id", delete(handlers::certificate_auto_rotation::delete_auto_rotation_config))
        .route("/admin/certificates/auto-rotation/configs/:config_id/status", get(handlers::certificate_auto_rotation::get_auto_rotation_status))
        .route("/admin/certificates/auto-rotation/configs/:config_id/attempts", get(handlers::certificate_auto_rotation::get_config_attempts))
        .route("/admin/certificates/auto-rotation/attempts", get(handlers::certificate_auto_rotation::get_recent_attempts))
        .route("/admin/certificates/audit-logs", get(handlers::certificate_audit::query_audit_logs))
        .route("/admin/certificates/audit-logs/summary", get(handlers::certificate_audit::get_audit_summary))
        .route("/admin/certificates/usage-records", get(handlers::certificate_audit::query_usage_records))
        .route("/admin/certificates/usage-records/summary", get(handlers::certificate_audit::get_usage_summary))
        .route("/admin/crls", get(handlers::crl::list_crls))
        .route("/admin/crls/fetch", post(handlers::crl::fetch_crl))
        .route("/admin/crls/expired", get(handlers::crl::list_expired_crls))
        .route("/admin/crls/needs-refresh", get(handlers::crl::list_crls_needs_refresh))
        .route("/admin/crls/:id", get(handlers::crl::get_crl))
        .route("/admin/crls/:id", delete(handlers::crl::delete_crl))
        .route("/admin/crls/check-revocation/:serial_number/:issuer", get(handlers::crl::check_revocation))
        .route("/admin/crls/fetch-attempts", get(handlers::crl::get_fetch_attempts))
        .route("/admin/ocsp/check", post(handlers::ocsp::check_certificate))
        .route("/admin/ocsp/cache", get(handlers::ocsp::list_cache))
        .route("/admin/ocsp/cache/expired", get(handlers::ocsp::list_expired_cache))
        .route("/admin/ocsp/cache/:id", delete(handlers::ocsp::delete_cache_entry))
        .route("/admin/ocsp/cache/clear", post(handlers::ocsp::clear_cache))
        .route("/admin/ocsp/cache/expired/delete", post(handlers::ocsp::delete_expired_cache));

    if config.oauth2.enabled {
        tracing::info!("OAuth2 authentication enabled");
        let oauth2_config = config.oauth2.clone();
        protected_routes = protected_routes.route_layer(axum_middleware::from_fn_with_state(oauth2_config, middleware::oauth2_validation_middleware));
    }

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/nnrf-nfm/v1/nf-status-notify", post(handlers::nrf_notification::handle_nf_status_notification))
        .route("/namf-callback/v1/ue-contexts/:ueId/n1-n2-transfers/:transactionId/notify", post(handlers::amf_callback::handle_n1n2_transfer_status))
        .route("/namf-callback/v1/sm-contexts/:ueId/pdu-sessions/:pduSessionId/n2-notify", post(handlers::amf_callback::handle_n2_info_notify))
        .route("/nsmf-pdusession/v1/sm-contexts/retrieve", post(handlers::amf_smf_coordination::retrieve_sm_context_for_amf))
        .route("/nsmf-pdusession/v1/sm-contexts/release-notify", post(handlers::amf_smf_coordination::release_sm_context_on_transfer));

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

        let tls_config = if let Some(client_ca_path) = config.tls.client_ca_path.as_ref() {
            tracing::info!("Starting SMF server with mTLS on https://{}", addr);
            tracing::info!("Client certificate verification enabled (required: {})", config.tls.require_client_cert);
            build_mtls_config(cert_path, key_path, client_ca_path, config.tls.require_client_cert).await?
        } else {
            tracing::info!("Starting SMF server with TLS on https://{}", addr);
            RustlsConfig::from_pem_file(cert_path, key_path).await?
        };

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
