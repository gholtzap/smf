use mongodb::{Collection, Database, bson::doc};
use chrono::Utc;
use crate::types::{SmfEvent, NsmfEventExposureNotification, EventNotification, StoredEventSubscription, PduSessionInfo, PduSessionStatus, EventIpAddr};

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
        event: SmfEvent,
        supi: &str,
        pdu_session_id: u8,
        dnn: Option<String>,
        snssai: Option<crate::types::Snssai>,
        ue_ipv4_addr: Option<String>,
        ue_ipv6_prefix: Option<String>,
        sm_context_ref: Option<String>,
        pdu_sess_status: Option<PduSessionStatus>,
    ) {
        let subscriptions = self.find_matching_subscriptions(
            db,
            &event,
            Some(supi),
            pdu_session_id,
            dnn.as_deref(),
            snssai.as_ref(),
        ).await;

        for subscription in subscriptions {
            let ue_ip = if ue_ipv4_addr.is_some() || ue_ipv6_prefix.is_some() {
                Some(EventIpAddr {
                    ipv4_addr: ue_ipv4_addr.clone(),
                    ipv6_addr: None,
                    ipv6_prefix: ue_ipv6_prefix.clone(),
                })
            } else {
                None
            };

            let event_notif = EventNotification {
                event: event.clone(),
                time_stamp: Utc::now(),
                supi: Some(supi.to_string()),
                gpsi: subscription.gpsi.clone(),
                pdu_se_id: Some(pdu_session_id),
                dnn: dnn.clone(),
                snssai: snssai.clone(),
                ue_ip_addr: ue_ip,
                pdu_sess_info: Some(PduSessionInfo {
                    pdu_sess_status: pdu_sess_status.clone(),
                    sm_context_ref: sm_context_ref.clone(),
                }),
            };

            let notification = NsmfEventExposureNotification {
                notif_id: subscription.notif_id.clone(),
                event_notifs: vec![event_notif],
            };

            self.send_notification(&subscription.notif_uri, &notification).await;
        }
    }

    async fn find_matching_subscriptions(
        &self,
        db: &Database,
        event: &SmfEvent,
        supi: Option<&str>,
        _pdu_session_id: u8,
        _dnn: Option<&str>,
        _snssai: Option<&crate::types::Snssai>,
    ) -> Vec<StoredEventSubscription> {
        let collection: Collection<StoredEventSubscription> = db.collection("event_subscriptions");

        let event_bson = mongodb::bson::to_bson(event).unwrap_or(mongodb::bson::Bson::Null);

        let mut filter = doc! {
            "eventSubs.event": event_bson
        };

        if let Some(supi_val) = supi {
            filter.insert("$or", vec![
                doc! { "supi": { "$exists": false } },
                doc! { "supi": mongodb::bson::Bson::Null },
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

    async fn send_notification(&self, uri: &str, notification: &NsmfEventExposureNotification) {
        match self.http_client
            .post(uri)
            .json(notification)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    tracing::info!(notif_uri = %uri, notif_id = %notification.notif_id, "Event notification sent");
                } else {
                    tracing::warn!(
                        notif_uri = %uri,
                        status = %response.status(),
                        "Event notification failed"
                    );
                }
            }
            Err(e) => {
                tracing::error!(notif_uri = %uri, error = %e, "Failed to send event notification");
            }
        }
    }
}
