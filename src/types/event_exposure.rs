use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmfEvent {
    #[serde(rename = "AC_TY_CH")]
    AcTyCh,
    #[serde(rename = "UP_PATH_CH")]
    UpPathCh,
    #[serde(rename = "PDU_SES_REL")]
    PduSesRel,
    #[serde(rename = "PLMN_CH")]
    PlmnCh,
    #[serde(rename = "UE_IP_CH")]
    UeIpCh,
    #[serde(rename = "RAT_TY_CH")]
    RatTyCh,
    #[serde(rename = "DDDS")]
    Ddds,
    #[serde(rename = "COMM_FAIL")]
    CommFail,
    #[serde(rename = "PDU_SES_EST")]
    PduSesEst,
    #[serde(rename = "QFI_ALLOC")]
    QfiAlloc,
    #[serde(rename = "QOS_MON")]
    QosMon,
    #[serde(rename = "SMCC_EXP")]
    SmccExp,
    #[serde(rename = "DISPERSION")]
    Dispersion,
    #[serde(rename = "RED_TRANS_EXP")]
    RedTransExp,
    #[serde(rename = "WLAN_INFO")]
    WlanInfo,
    #[serde(rename = "UPF_INFO")]
    UpfInfo,
    #[serde(rename = "UP_STATUS_INFO")]
    UpStatusInfo,
    #[serde(rename = "SATB_CH")]
    SatbCh,
    #[serde(rename = "TRAFFIC_CORRELATION")]
    TrafficCorrelation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSubscription {
    pub event: SmfEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnai_chg_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NsmfEventExposure {
    pub event_subs: Vec<EventSubscription>,
    pub notif_uri: String,
    pub notif_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpsi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_ue_ind: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_se_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snssai: Option<super::Snssai>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nf_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnai: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_report_nbr: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_notif_ipv4_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_notif_ipv6_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_notif_fqdns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredEventSubscription {
    #[serde(rename = "_id")]
    pub id: String,
    pub event_subs: Vec<EventSubscription>,
    pub notif_uri: String,
    pub notif_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpsi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_ue_ind: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_se_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snssai: Option<super::Snssai>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nf_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnai: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_report_nbr: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_notif_ipv4_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_notif_ipv6_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_notif_fqdns: Option<Vec<String>>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
}

impl StoredEventSubscription {
    pub fn to_nsmf_event_exposure(&self) -> NsmfEventExposure {
        NsmfEventExposure {
            event_subs: self.event_subs.clone(),
            notif_uri: self.notif_uri.clone(),
            notif_id: self.notif_id.clone(),
            supi: self.supi.clone(),
            gpsi: self.gpsi.clone(),
            any_ue_ind: self.any_ue_ind,
            group_id: self.group_id.clone(),
            pdu_se_id: self.pdu_se_id,
            dnn: self.dnn.clone(),
            snssai: self.snssai.clone(),
            sub_id: Some(self.id.clone()),
            nf_id: self.nf_id.clone(),
            dnai: self.dnai.clone(),
            supported_features: self.supported_features.clone(),
            expiry: self.expiry,
            max_report_nbr: self.max_report_nbr,
            alt_notif_ipv4_addrs: self.alt_notif_ipv4_addrs.clone(),
            alt_notif_ipv6_addrs: self.alt_notif_ipv6_addrs.clone(),
            alt_notif_fqdns: self.alt_notif_fqdns.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NsmfEventExposureNotification {
    pub notif_id: String,
    pub event_notifs: Vec<EventNotification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventNotification {
    pub event: SmfEvent,
    pub time_stamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpsi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_se_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snssai: Option<super::Snssai>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_ip_addr: Option<EventIpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_sess_info: Option<PduSessionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventIpAddr {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_sess_status: Option<PduSessionStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sm_context_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PduSessionStatus {
    #[serde(rename = "ACTIVATED")]
    Activated,
    #[serde(rename = "DEACTIVATED")]
    Deactivated,
    #[serde(rename = "RELEASED")]
    Released,
}
