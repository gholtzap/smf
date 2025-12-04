use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSubscription {
    pub event_list: Vec<EventType>,
    pub event_notif_uri: String,
    pub notif_id: Option<String>,
    pub supi: Option<String>,
    pub group_id: Option<String>,
    pub gpsi: Option<String>,
    pub dnn: Option<String>,
    pub snssai: Option<super::Snssai>,
    pub pdu_session_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    AcTypChange,
    UpPathChange,
    PduSesRelease,
    PlmnChange,
    UeIpChange,
    UeIpv6PrefixChange,
    DdnFailure,
    CommFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscriptionCreatedData {
    pub subscription_id: String,
    #[serde(rename = "eventList")]
    pub event_list: Vec<EventType>,
    #[serde(rename = "eventNotifUri")]
    pub event_notif_uri: String,
    #[serde(rename = "notifId")]
    pub notif_id: Option<String>,
    pub supi: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEventSubscription {
    #[serde(rename = "_id")]
    pub id: String,
    pub event_list: Vec<EventType>,
    pub event_notif_uri: String,
    pub notif_id: Option<String>,
    pub supi: Option<String>,
    pub group_id: Option<String>,
    pub gpsi: Option<String>,
    pub dnn: Option<String>,
    pub snssai: Option<super::Snssai>,
    pub pdu_session_id: Option<u8>,
    pub created_at: DateTime<Utc>,
}
