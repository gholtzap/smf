use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{Collection, bson::doc};
use uuid::Uuid;
use chrono::Utc;
use crate::db::AppState;
use crate::types::{EventSubscription, EventSubscriptionCreatedData, StoredEventSubscription};

pub async fn create_event_subscription(
    State(db): State<AppState>,
    Json(payload): Json<EventSubscription>,
) -> Result<Json<EventSubscriptionCreatedData>, AppError> {
    let collection: Collection<StoredEventSubscription> = db.collection("event_subscriptions");

    let subscription_id = Uuid::new_v4().to_string();

    let stored_subscription = StoredEventSubscription {
        id: subscription_id.clone(),
        event_list: payload.event_list.clone(),
        event_notif_uri: payload.event_notif_uri.clone(),
        notif_id: payload.notif_id.clone(),
        supi: payload.supi.clone(),
        group_id: payload.group_id.clone(),
        gpsi: payload.gpsi.clone(),
        dnn: payload.dnn.clone(),
        snssai: payload.snssai.clone(),
        pdu_session_id: payload.pdu_session_id,
        created_at: Utc::now(),
    };

    collection
        .insert_one(&stored_subscription)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response = EventSubscriptionCreatedData {
        subscription_id: subscription_id.clone(),
        event_list: payload.event_list,
        event_notif_uri: payload.event_notif_uri,
        notif_id: payload.notif_id,
        supi: payload.supi,
    };

    tracing::info!(
        "Created event subscription: {}, Notification URI: {}",
        subscription_id,
        response.event_notif_uri
    );

    Ok(Json(response))
}

pub async fn update_event_subscription(
    State(db): State<AppState>,
    Path(subscription_id): Path<String>,
    Json(payload): Json<EventSubscription>,
) -> Result<Json<EventSubscriptionCreatedData>, AppError> {
    let collection: Collection<StoredEventSubscription> = db.collection("event_subscriptions");

    let existing = collection
        .find_one(doc! { "_id": &subscription_id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if existing.is_none() {
        return Err(AppError::NotFound(format!("Subscription {} not found", subscription_id)));
    }

    let updated_subscription = StoredEventSubscription {
        id: subscription_id.clone(),
        event_list: payload.event_list.clone(),
        event_notif_uri: payload.event_notif_uri.clone(),
        notif_id: payload.notif_id.clone(),
        supi: payload.supi.clone(),
        group_id: payload.group_id.clone(),
        gpsi: payload.gpsi.clone(),
        dnn: payload.dnn.clone(),
        snssai: payload.snssai.clone(),
        pdu_session_id: payload.pdu_session_id,
        created_at: existing.unwrap().created_at,
    };

    collection
        .replace_one(doc! { "_id": &subscription_id }, &updated_subscription)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response = EventSubscriptionCreatedData {
        subscription_id: subscription_id.clone(),
        event_list: payload.event_list,
        event_notif_uri: payload.event_notif_uri,
        notif_id: payload.notif_id,
        supi: payload.supi,
    };

    tracing::info!(
        "Updated event subscription: {}, Notification URI: {}",
        subscription_id,
        response.event_notif_uri
    );

    Ok(Json(response))
}

pub async fn delete_event_subscription(
    State(db): State<AppState>,
    Path(subscription_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let collection: Collection<StoredEventSubscription> = db.collection("event_subscriptions");

    let result = collection
        .delete_one(doc! { "_id": &subscription_id })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if result.deleted_count == 0 {
        return Err(AppError::NotFound(format!("Subscription {} not found", subscription_id)));
    }

    tracing::info!("Deleted event subscription: {}", subscription_id);

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug)]
pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    NotFound(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (status, message).into_response()
    }
}
