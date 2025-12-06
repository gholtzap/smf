use serde::{Deserialize, Serialize};
use crate::types::{Snssai, PlmnId, PduSessionType};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionManagementSubscriptionData {
    pub single_nssai: Snssai,
    pub dnn_configurations: Option<std::collections::HashMap<String, UdrDnnConfiguration>>,
    pub internal_group_identifier: Option<Vec<String>>,
    pub shared_vn_group_data_ids: Option<std::collections::HashMap<String, String>>,
    pub shared_dnn_configurations_id: Option<String>,
    pub odb_packet_services: Option<OdbPacketServices>,
    pub trace_data: Option<TraceData>,
    pub shared_trace_data_id: Option<String>,
    pub expected_ue_behaviour_list: Option<std::collections::HashMap<String, ExpectedUeBehaviour>>,
    pub suggested_packet_num_dl_list: Option<std::collections::HashMap<String, SuggestedPacketNumDl>>,
    #[serde(rename = "3gppChargingCharacteristics")]
    pub three_gpp_charging_characteristics: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrDnnConfiguration {
    pub pdu_session_types: PduSessionTypes,
    pub ssc_modes: UdrSscModes,
    pub iwk_eps_ind: Option<bool>,
    #[serde(rename = "5gQosProfile")]
    pub five_g_qos_profile: Option<SubscribedDefaultQos>,
    pub session_ambr: Option<UdrAmbr>,
    #[serde(rename = "3gppChargingCharacteristics")]
    pub three_gpp_charging_characteristics: Option<String>,
    pub static_ip_address: Option<Vec<IpAddress>>,
    pub up_security: Option<UpSecurity>,
    pub pdu_session_continuity_ind: Option<PduSessionContinuityInd>,
    pub nidd_nef_id: Option<String>,
    pub nidd_info: Option<NiddInformation>,
    pub redundant_session_allowed: Option<bool>,
    pub acs_info: Option<AcsInfo>,
    pub ipv4_frame_route_list: Option<Vec<FrameRouteInfo>>,
    pub ipv6_frame_route_list: Option<Vec<FrameRouteInfo>>,
    pub atsss_allowed: Option<bool>,
    pub secondary_auth: Option<bool>,
    pub dn_aaa_ip_address_allocation: Option<bool>,
    pub ip_address_allocation_type: Option<IpAddressAllocationType>,
    pub eas_discovery_authorized: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionTypes {
    pub default_session_type: PduSessionType,
    pub allowed_session_types: Option<Vec<PduSessionType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrSscModes {
    pub default_ssc_mode: UdrSscMode,
    pub allowed_ssc_modes: Option<Vec<UdrSscMode>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UdrSscMode {
    #[serde(rename = "SSC_MODE_1")]
    SscMode1,
    #[serde(rename = "SSC_MODE_2")]
    SscMode2,
    #[serde(rename = "SSC_MODE_3")]
    SscMode3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribedDefaultQos {
    #[serde(rename = "5qi")]
    pub five_qi: i32,
    pub arp: UdrArp,
    pub priority_level: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrArp {
    pub priority_level: i32,
    pub preempt_cap: PreemptCap,
    pub preempt_vuln: PreemptVuln,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreemptCap {
    MayPreempt,
    NotPreempt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreemptVuln {
    Preemptable,
    NotPreemptable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrAmbr {
    pub uplink: String,
    pub downlink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAddress {
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub ipv6_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpSecurity {
    pub up_integr: UpIntegrity,
    pub up_confid: UpConfidentiality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpIntegrity {
    Required,
    Preferred,
    NotNeeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpConfidentiality {
    Required,
    Preferred,
    NotNeeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PduSessionContinuityInd {
    Activate,
    Deactivate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NiddInformation {
    pub af_id: String,
    pub gpsi: Option<String>,
    pub external_group_id: Option<String>,
    pub validity_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcsInfo {
    pub acs_url: String,
    pub acs_ipv4_addr: Option<String>,
    pub acs_ipv6_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameRouteInfo {
    pub ipv4_mask: Option<String>,
    pub ipv6_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IpAddressAllocationType {
    Static,
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OdbPacketServices {
    AllPacketServicesBarred,
    RoamerAccessToHplmnApBarred,
    RoamerAccessToVplmnApBarred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceData {
    pub trace_ref: String,
    pub trace_depth: TraceDepth,
    pub ne_type_list: String,
    pub event_list: String,
    pub collection_entity_ipv4_addr: Option<String>,
    pub collection_entity_ipv6_addr: Option<String>,
    pub interface_list: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceDepth {
    Minimum,
    Medium,
    Maximum,
    MinimumWithoutVendorSpecificExtension,
    MediumWithoutVendorSpecificExtension,
    MaximumWithoutVendorSpecificExtension,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedUeBehaviour {
    pub af_instance_id: String,
    pub reference_id: i32,
    pub stationary_indication: Option<StationaryIndication>,
    pub communication_duration_time: Option<i32>,
    pub periodic_time: Option<i32>,
    pub scheduled_communication_time: Option<ScheduledCommunicationTime>,
    pub scheduled_communication_type: Option<ScheduledCommunicationType>,
    pub expected_umts: Option<Vec<ExpectedUmts>>,
    pub traffic_profile: Option<TrafficProfile>,
    pub battery_indication: Option<BatteryIndication>,
    pub validity_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StationaryIndication {
    Stationary,
    Mobile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledCommunicationTime {
    pub days_of_week: Option<Vec<i32>>,
    pub time_of_day_start: Option<String>,
    pub time_of_day_end: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScheduledCommunicationType {
    DownlinkOnly,
    UplinkOnly,
    BidirectionalData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedUmts {
    pub location_info: LocationInfo,
    pub duration: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationInfo {
    pub nw_area_info: Option<NetworkAreaInfo>,
    pub geo_area_list: Option<Vec<GeographicArea>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAreaInfo {
    pub ecgis: Option<Vec<UdrEcgi>>,
    pub ncgis: Option<Vec<UdrNcgi>>,
    pub g_ran_node_ids: Option<Vec<GlobalRanNodeId>>,
    pub tais: Option<Vec<UdrTai>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrEcgi {
    pub plmn_id: PlmnId,
    pub eutra_cell_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrNcgi {
    pub plmn_id: PlmnId,
    pub nr_cell_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalRanNodeId {
    pub plmn_id: PlmnId,
    pub n3_iwf_id: Option<String>,
    pub g_nb_id: Option<GNbId>,
    pub nge_nb_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GNbId {
    pub bit_length: i32,
    pub g_nb_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrTai {
    pub plmn_id: PlmnId,
    pub tac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeographicArea {
    pub shape: SupportedGadShapes,
    pub point: Option<GeographicalCoordinates>,
    pub uncertainty: Option<f64>,
    pub uncertainty_ellipse: Option<UncertaintyEllipse>,
    pub confidence: Option<i32>,
    pub inner_radius: Option<i32>,
    pub uncertainty_radius: Option<f32>,
    pub offset_angle: Option<i32>,
    pub included_angle: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportedGadShapes {
    Point,
    PointUncertaintyCircle,
    PointUncertaintyEllipse,
    Polygon,
    PointAltitude,
    PointAltitudeUncertainty,
    EllipsoidArc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeographicalCoordinates {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UncertaintyEllipse {
    pub semi_major: f32,
    pub semi_minor: f32,
    pub orientation: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrafficProfile {
    SingleTransUl,
    SingleTransDl,
    DualTransUlFirst,
    DualTransDlFirst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatteryIndication {
    pub battery_ind: bool,
    pub replaceable_ind: Option<bool>,
    pub rechargeable_ind: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestedPacketNumDl {
    pub suggested_packet_num_dl: i32,
    pub validity_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmfSelectionSubscriptionData {
    pub supported_features: Option<String>,
    pub subscribed_snssai_infos: Option<std::collections::HashMap<String, SnssaiInfo>>,
    pub shared_snssai_infos_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnssaiInfo {
    pub dnn_infos: Vec<DnnInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnnInfo {
    pub dnn: String,
    pub default_dnn_indicator: Option<bool>,
    pub lbo_roaming_allowed: Option<bool>,
    pub iwk_eps_ind: Option<bool>,
    pub smf_list: Option<Vec<String>>,
    pub same_smf_ind: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdrQueryParams {
    pub plmn_id: Option<PlmnId>,
    pub supported_features: Option<String>,
}
