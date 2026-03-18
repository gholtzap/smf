use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{Collection, bson::doc};
use uuid::Uuid;
use chrono::Utc;
use crate::db::AppState;
use crate::types::{AppError, NsmfEventExposure, StoredEventSubscription};

pub async fn create_event_subscription(
    State(state): State<AppState>,
    Json(payload): Json<NsmfEventExposure>,
) -> Result<Response, AppError> {
    if payload.event_subs.is_empty() {
        return Err(AppError::ValidationError(
            "eventSubs must contain at least one event subscription".to_string(),
        ));
    }

    if payload.notif_uri.is_empty() {
        return Err(AppError::ValidationError(
            "notifUri is required".to_string(),
        ));
    }

    if payload.notif_id.is_empty() {
        return Err(AppError::ValidationError(
            "notifId is required".to_string(),
        ));
    }

    let collection: Collection<StoredEventSubscription> =
        state.db.collection("event_subscriptions");

    let subscription_id = Uuid::new_v4().to_string();

    let stored = StoredEventSubscription {
        id: subscription_id.clone(),
        event_subs: payload.event_subs,
        notif_uri: payload.notif_uri,
        notif_id: payload.notif_id,
        supi: payload.supi,
        gpsi: payload.gpsi,
        any_ue_ind: payload.any_ue_ind,
        group_id: payload.group_id,
        pdu_se_id: payload.pdu_se_id,
        dnn: payload.dnn,
        snssai: payload.snssai,
        nf_id: payload.nf_id,
        dnai: payload.dnai,
        supported_features: payload.supported_features,
        expiry: payload.expiry,
        max_report_nbr: payload.max_report_nbr,
        alt_notif_ipv4_addrs: payload.alt_notif_ipv4_addrs,
        alt_notif_ipv6_addrs: payload.alt_notif_ipv6_addrs,
        alt_notif_fqdns: payload.alt_notif_fqdns,
        created_at: Utc::now(),
    };

    collection
        .insert_one(&stored)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response_body = stored.to_nsmf_event_exposure();

    let location = format!(
        "/nsmf-event-exposure/v1/subscriptions/{}",
        subscription_id
    );

    tracing::info!(
        sub_id = %subscription_id,
        notif_uri = %response_body.notif_uri,
        "Created event subscription"
    );

    let mut headers = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(&location) {
        headers.insert("Location", val);
    }

    Ok((StatusCode::CREATED, headers, Json(response_body)).into_response())
}

pub async fn get_event_subscription(
    State(state): State<AppState>,
    Path(subscription_id): Path<String>,
) -> Result<Json<NsmfEventExposure>, AppError> {
    let collection: Collection<StoredEventSubscription> =
        state.db.collection("event_subscriptions");

    let stored = collection
        .find_one(doc! { "_id": &subscription_id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| {
            AppError::NotFound(format!("Subscription {} not found", subscription_id))
        })?;

    Ok(Json(stored.to_nsmf_event_exposure()))
}

pub async fn update_event_subscription(
    State(state): State<AppState>,
    Path(subscription_id): Path<String>,
    Json(payload): Json<NsmfEventExposure>,
) -> Result<Json<NsmfEventExposure>, AppError> {
    if payload.event_subs.is_empty() {
        return Err(AppError::ValidationError(
            "eventSubs must contain at least one event subscription".to_string(),
        ));
    }

    if payload.notif_uri.is_empty() {
        return Err(AppError::ValidationError(
            "notifUri is required".to_string(),
        ));
    }

    if payload.notif_id.is_empty() {
        return Err(AppError::ValidationError(
            "notifId is required".to_string(),
        ));
    }

    let collection: Collection<StoredEventSubscription> =
        state.db.collection("event_subscriptions");

    let existing = collection
        .find_one(doc! { "_id": &subscription_id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| {
            AppError::NotFound(format!("Subscription {} not found", subscription_id))
        })?;

    let updated = StoredEventSubscription {
        id: subscription_id.clone(),
        event_subs: payload.event_subs,
        notif_uri: payload.notif_uri,
        notif_id: payload.notif_id,
        supi: payload.supi,
        gpsi: payload.gpsi,
        any_ue_ind: payload.any_ue_ind,
        group_id: payload.group_id,
        pdu_se_id: payload.pdu_se_id,
        dnn: payload.dnn,
        snssai: payload.snssai,
        nf_id: payload.nf_id,
        dnai: payload.dnai,
        supported_features: payload.supported_features,
        expiry: payload.expiry,
        max_report_nbr: payload.max_report_nbr,
        alt_notif_ipv4_addrs: payload.alt_notif_ipv4_addrs,
        alt_notif_ipv6_addrs: payload.alt_notif_ipv6_addrs,
        alt_notif_fqdns: payload.alt_notif_fqdns,
        created_at: existing.created_at,
    };

    collection
        .replace_one(doc! { "_id": &subscription_id }, &updated)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        sub_id = %subscription_id,
        notif_uri = %updated.notif_uri,
        "Updated event subscription"
    );

    Ok(Json(updated.to_nsmf_event_exposure()))
}

pub async fn delete_event_subscription(
    State(state): State<AppState>,
    Path(subscription_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let collection: Collection<StoredEventSubscription> =
        state.db.collection("event_subscriptions");

    let result = collection
        .delete_one(doc! { "_id": &subscription_id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if result.deleted_count == 0 {
        return Err(AppError::NotFound(format!(
            "Subscription {} not found",
            subscription_id
        )));
    }

    tracing::info!(sub_id = %subscription_id, "Deleted event subscription");

    Ok(StatusCode::NO_CONTENT)
}
