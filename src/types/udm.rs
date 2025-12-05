use serde::{Deserialize, Serialize};
use super::{Snssai, PlmnId};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionManagementSubscriptionData {
    pub single_nssai: Snssai,
    pub dnn_configurations: Option<DnnConfigurations>,
    pub internal_group_identifier: Option<Vec<String>>,
    pub shared_vn_group_data_ids: Option<Vec<String>>,
    pub shared_dnn_configurations_id: Option<String>,
    pub odb_packet_services: Option<OdbPacketServices>,
    pub trace_data: Option<TraceData>,
    pub shared_trace_data_id: Option<String>,
    pub expected_ue_behaviour_list: Option<Vec<ExpectedUeBehaviour>>,
    pub suggested_packet_num_dl_list: Option<Vec<SuggestedPacketNumDl>>,
    #[serde(rename = "3gppChargingCharacteristics")]
    pub charging_characteristics_3gpp: Option<String>,
}

pub type DnnConfigurations = std::collections::HashMap<String, UdmDnnConfiguration>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdmDnnConfiguration {
    pub pdu_session_types: PduSessionTypes,
    pub ssc_modes: SscModes,
    pub iwk_eps_ind: Option<bool>,
    #[serde(rename = "5gQosProfile")]
    pub qos_profile_5g: Option<SubscribedDefaultQos>,
    pub session_ambr: Option<Ambr>,
    #[serde(rename = "3gppChargingCharacteristics")]
    pub charging_characteristics_3gpp: Option<String>,
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
    pub ip_address_allocation_type: Option<IpAddressAllocationtype>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionTypes {
    pub default_session_type: PduSessionType,
    pub allowed_session_types: Option<Vec<PduSessionType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PduSessionType {
    Ipv4,
    Ipv6,
    Ipv4v6,
    Unstructured,
    Ethernet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SscModes {
    pub default_ssc_mode: SscMode,
    pub allowed_ssc_modes: Option<Vec<SscMode>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SscMode {
    SscMode1,
    SscMode2,
    SscMode3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribedDefaultQos {
    #[serde(rename = "5qi")]
    pub qos_identifier_5: u8,
    pub arp: Option<Arp>,
    pub priority_level: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Arp {
    pub priority_level: u8,
    pub preempt_cap: PreemptionCapability,
    pub preempt_vuln: PreemptionVulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreemptionCapability {
    NotPreempt,
    MayPreempt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreemptionVulnerability {
    NotPreemptable,
    Preemptable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ambr {
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
    pub ext_group_id: Option<String>,
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
pub enum IpAddressAllocationtype {
    StaticOnly,
    DynamicOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OdbPacketServices {
    AllPacketServices,
    RoamerAccessToHplmnAp,
    RoamerAccessToVplmnAp,
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
    pub reference_id: u32,
    pub stationary_indication: Option<StationaryIndication>,
    pub communication_duration_time: Option<u32>,
    pub periodic_time: Option<u32>,
    pub scheduled_communication_time: Option<ScheduledCommunicationTime>,
    pub scheduled_communication_type: Option<ScheduledCommunicationType>,
    pub expected_umts: Option<Vec<LocationArea>>,
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
    pub days_of_week: Option<Vec<u8>>,
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
pub struct LocationArea {
    pub geographic_areas: Option<Vec<GeographicArea>>,
    pub civic_addresses: Option<Vec<CivicAddress>>,
    pub nw_area_info: Option<NetworkAreaInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeographicArea {
    pub shape: SupportedGadShapes,
    pub point: Option<GeographicalCoordinates>,
    pub uncertainty: Option<f32>,
    pub uncertainty_ellipse: Option<UncertaintyEllipse>,
    pub confidence: Option<u8>,
    pub inner_radius: Option<u32>,
    pub uncertainty_radius: Option<f32>,
    pub offset_angle: Option<u16>,
    pub included_angle: Option<u16>,
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
    pub lon: f64,
    pub lat: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UncertaintyEllipse {
    pub semi_major: f32,
    pub semi_minor: f32,
    pub orientation_major: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CivicAddress {
    pub country: Option<String>,
    pub a1: Option<String>,
    pub a2: Option<String>,
    pub a3: Option<String>,
    pub a4: Option<String>,
    pub a5: Option<String>,
    pub a6: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAreaInfo {
    pub ecgis: Option<Vec<Ecgi>>,
    pub ncgis: Option<Vec<Ncgi>>,
    pub g_ran_node_ids: Option<Vec<GlobalRanNodeId>>,
    pub tais: Option<Vec<UdmTai>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ecgi {
    pub plmn_id: PlmnId,
    pub eutra_cell_id: String,
    pub nid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ncgi {
    pub plmn_id: PlmnId,
    pub nr_cell_id: String,
    pub nid: Option<String>,
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
    pub bit_length: u8,
    pub g_nb_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdmTai {
    pub plmn_id: PlmnId,
    pub tac: String,
    pub nid: Option<String>,
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
    pub af_instance_id: String,
    pub reference_id: u32,
    pub suggested_packet_num_dl: u16,
    pub validity_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdmSubscription {
    pub nf_instance_id: String,
    pub implicit_unsubscribe: Option<bool>,
    pub expires: Option<String>,
    pub callback_reference: String,
    pub monitored_resource_uris: Vec<String>,
    pub single_nssai: Option<Snssai>,
    pub dnn: Option<String>,
    pub subscription_id: Option<String>,
    pub plmn_id: Option<PlmnId>,
    pub immediate_report: Option<bool>,
    pub report: Option<SubscriptionDataSets>,
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionDataSets {
    pub sm_data: Option<Vec<SessionManagementSubscriptionData>>,
    pub am_data: Option<AccessAndMobilitySubscriptionData>,
    pub smf_sel_data: Option<SmfSelectionSubscriptionData>,
    pub ue_context_in_smf_data: Option<UeContextInSmfData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessAndMobilitySubscriptionData {
    pub gpsis: Option<Vec<String>>,
    pub internal_group_ids: Option<Vec<String>>,
    pub shared_vn_group_data_ids: Option<Vec<String>>,
    pub subscribed_ue_ambr: Option<Ambr>,
    pub nssai: Option<Nssai>,
    pub rat_restrictions: Option<Vec<RatType>>,
    pub forbidden_areas: Option<Vec<Area>>,
    pub service_area_restriction: Option<ServiceAreaRestriction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Nssai {
    pub default_single_nssais: Vec<Snssai>,
    pub single_nssais: Option<Vec<Snssai>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RatType {
    NrV2x,
    Nr,
    EutraV2x,
    Eutra,
    Wlan,
    VirtualRat,
    Nbiot,
    WirelineWireguard,
    Wireline,
    WirelineBba,
    WirelineCable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Area {
    pub tacs: Option<Vec<String>>,
    pub area_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAreaRestriction {
    pub restriction_type: RestrictionType,
    pub areas: Option<Vec<Area>>,
    pub max_num_of_tas: Option<u32>,
    pub max_num_of_tas_for_not_allowed_areas: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestrictionType {
    AllowedAreas,
    NotAllowedAreas,
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
    pub ladnIndicator: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeContextInSmfData {
    pub pdu_sessions: Option<std::collections::HashMap<String, PduSession>>,
    pub pg_w_info: Option<PgwInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSession {
    pub pdu_session_id: u8,
    pub dnn: String,
    pub smf_instance_id: String,
    pub plmn_id: Option<PlmnId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PgwInfo {
    pub dnn: String,
    pub pgw_fqdn: String,
    pub pgw_ip_addr: Option<IpAddress>,
}

