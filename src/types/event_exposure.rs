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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventNotification {
    pub notif_id: String,
    pub event_notifs: Vec<EventReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventReport {
    pub event: EventType,
    pub time_stamp: DateTime<Utc>,
    pub supi: Option<String>,
    pub gpsi: Option<String>,
    pub pdu_session_id: Option<u8>,
    pub dnn: Option<String>,
    pub snssai: Option<super::Snssai>,
    pub ue_ipv4_addr: Option<String>,
    pub ue_ipv6_prefix: Option<String>,
    pub pdu_ses_info: Option<PduSessionEventInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionEventInfo {
    pub cause: Option<Cause>,
    pub sm_context_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Cause {
    RegularDeactivation,
    UeRequestedPduSessionDisconnection,
    NetworkInitiatedDeactivation,
    ReactivationRequested,
    DnnCongestion,
    SnssaiCongestion,
}
