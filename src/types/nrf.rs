use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::{PlmnId, Snssai};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NfType {
    Nrf,
    Udm,
    Amf,
    Smf,
    Ausf,
    Nef,
    Pcf,
    Smsf,
    Nssf,
    Udr,
    Lmf,
    Gmlc,
    #[serde(rename = "5G_EIR")]
    FiveGEir,
    Sepp,
    Upf,
    N3iwf,
    Af,
    Udsf,
    Bsf,
    Chf,
    Nwdaf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NfStatus {
    Registered,
    Suspended,
    Undiscoverable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFProfile {
    pub nf_instance_id: String,
    pub nf_type: NfType,
    pub nf_status: NfStatus,
    pub plmn_list: Vec<PlmnId>,
    pub s_nssai_list: Option<Vec<Snssai>>,
    pub nsi_list: Option<Vec<String>>,
    pub fqdn: Option<String>,
    pub ipv4_addresses: Option<Vec<String>>,
    pub ipv6_addresses: Option<Vec<String>>,
    pub allowed_plmns: Option<Vec<PlmnId>>,
    pub allowed_nf_types: Option<Vec<NfType>>,
    pub allowed_nf_domains: Option<Vec<String>>,
    pub allowed_nssais: Option<Vec<Snssai>>,
    pub priority: Option<u16>,
    pub capacity: Option<u16>,
    pub load: Option<u16>,
    pub locality: Option<String>,
    pub nf_services: Option<Vec<NFService>>,
    pub smf_info: Option<SmfInfo>,
    pub heart_beat_timer: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFService {
    pub service_instance_id: String,
    pub service_name: String,
    pub versions: Vec<NFServiceVersion>,
    pub scheme: String,
    pub nf_service_status: NfServiceStatus,
    pub fqdn: Option<String>,
    pub ipv4_addresses: Option<Vec<String>>,
    pub ipv6_addresses: Option<Vec<String>>,
    pub api_prefix: Option<String>,
    pub default_notification_subscriptions: Option<Vec<DefaultNotificationSubscription>>,
    pub allowed_plmns: Option<Vec<PlmnId>>,
    pub allowed_nf_types: Option<Vec<NfType>>,
    pub allowed_nf_domains: Option<Vec<String>>,
    pub allowed_nssais: Option<Vec<Snssai>>,
    pub priority: Option<u16>,
    pub capacity: Option<u16>,
    pub load: Option<u16>,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFServiceVersion {
    pub api_version_in_uri: String,
    pub api_full_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NfServiceStatus {
    Registered,
    Suspended,
    Undiscoverable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultNotificationSubscription {
    pub notification_type: String,
    pub callback_uri: String,
    pub n1_message_class: Option<String>,
    pub n2_information_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmfInfo {
    pub s_nssai_smf_info_list: Vec<SnssaiSmfInfoItem>,
    pub tai_list: Option<Vec<Tai>>,
    pub tai_range_list: Option<Vec<TaiRange>>,
    pub pgw_fqdn: Option<String>,
    pub access_type: Option<Vec<AccessType>>,
    pub priority: Option<u16>,
    pub vsmf_support_ind: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnssaiSmfInfoItem {
    pub s_nssai: Snssai,
    pub dnn_smf_info_list: Vec<DnnSmfInfoItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnnSmfInfoItem {
    pub dnn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tai {
    pub plmn_id: PlmnId,
    pub tac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaiRange {
    pub plmn_id: PlmnId,
    pub tac_range_list: Vec<TacRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TacRange {
    pub start: String,
    pub end: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessType {
    #[serde(rename = "3GPP_ACCESS")]
    ThreeGppAccess,
    NonThreeGppAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub validity_period: Option<u32>,
    pub nf_instances: Vec<NFProfile>,
    pub search_id: Option<String>,
    pub num_nf_inst_complete: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionData {
    pub nf_status_notification_uri: String,
    pub req_nf_instance_id: Option<String>,
    pub subscription_id: Option<String>,
    pub validity_time: Option<String>,
    pub req_notif_events: Option<Vec<NotificationEventType>>,
    pub plmn_id: Option<PlmnId>,
    pub nf_type: Option<NfType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationEventType {
    NfRegistered,
    NfDeregistered,
    NfProfileChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationData {
    pub event: NotificationEventType,
    pub nf_instance_uri: String,
    pub nf_profile: Option<NFProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: Option<String>,
    pub title: Option<String>,
    pub status: Option<u16>,
    pub detail: Option<String>,
    pub instance: Option<String>,
    pub cause: Option<String>,
    pub invalid_params: Option<Vec<InvalidParam>>,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidParam {
    pub param: String,
    pub reason: Option<String>,
}

pub type QueryParams = HashMap<String, String>;
