use mongodb::{Collection, Database, bson::doc};
use chrono::Utc;
use crate::types::{EventType, EventNotification, EventReport, StoredEventSubscription, PduSessionEventInfo, Cause};

pub struct NotificationService {
    http_client: reqwest::Client,
}

impl NotificationService {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub async fn notify_pdu_session_event(
        &self,
        db: &Database,
        event_type: EventType,
        supi: &str,
        pdu_session_id: u8,
        dnn: Option<String>,
        snssai: Option<crate::types::Snssai>,
        ue_ipv4_addr: Option<String>,
        ue_ipv6_prefix: Option<String>,
        sm_context_ref: Option<String>,
        cause: Option<Cause>,
    ) {
        let subscriptions = self.find_matching_subscriptions(
            db,
            &event_type,
            Some(supi),
            pdu_session_id,
            dnn.as_deref(),
            snssai.as_ref(),
        ).await;

        for subscription in subscriptions {
            let event_report = EventReport {
                event: event_type.clone(),
                time_stamp: Utc::now(),
                supi: Some(supi.to_string()),
                gpsi: subscription.gpsi.clone(),
                pdu_session_id: Some(pdu_session_id),
                dnn: dnn.clone(),
                snssai: snssai.clone(),
                ue_ipv4_addr: ue_ipv4_addr.clone(),
                ue_ipv6_prefix: ue_ipv6_prefix.clone(),
                pdu_ses_info: Some(PduSessionEventInfo {
                    cause: cause.clone(),
                    sm_context_ref: sm_context_ref.clone(),
                }),
            };

            let notification = EventNotification {
                notif_id: subscription.notif_id.clone().unwrap_or_else(|| subscription.id.clone()),
                event_notifs: vec![event_report],
            };

            self.send_notification(&subscription.event_notif_uri, &notification).await;
        }
    }

    async fn find_matching_subscriptions(
        &self,
        db: &Database,
        event_type: &EventType,
        supi: Option<&str>,
        _pdu_session_id: u8,
        _dnn: Option<&str>,
        _snssai: Option<&crate::types::Snssai>,
    ) -> Vec<StoredEventSubscription> {
        let collection: Collection<StoredEventSubscription> = db.collection("event_subscriptions");

        let event_bson = mongodb::bson::to_bson(event_type).unwrap_or(mongodb::bson::Bson::Null);

        let mut filter = doc! {
            "event_list": { "$in": [event_bson] }
        };

        if let Some(supi_val) = supi {
            filter.insert("$or", vec![
                doc! { "supi": { "$exists": false } },
                doc! { "supi": supi_val },
            ]);
        }

        match collection.find(filter).await {
            Ok(cursor) => {
                use futures::stream::TryStreamExt;
                cursor.try_collect().await.unwrap_or_default()
            }
            Err(e) => {
                tracing::error!("Failed to query event subscriptions: {}", e);
                vec![]
            }
        }
    }

    async fn send_notification(&self, uri: &str, notification: &EventNotification) {
        match self.http_client
            .post(uri)
            .json(notification)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    tracing::info!("Event notification sent to {}: {:?}", uri, notification.notif_id);
                } else {
                    tracing::warn!(
                        "Event notification to {} failed with status: {}",
                        uri,
                        response.status()
                    );
                }
            }
            Err(e) => {
                tracing::error!("Failed to send event notification to {}: {}", uri, e);
            }
        }
    }
}
