use serde::{Deserialize, Serialize};
use super::{Snssai, PlmnId, Tai};
use std::collections::HashMap;

pub use super::udm::Ambr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyContextData {
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub slice_info: Snssai,
    pub notification_uri: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address_prefix: Option<String>,
    pub ip_domain: Option<String>,
    pub subs_sess_ambr: Option<Ambr>,
    pub auth_prof_index: Option<String>,
    pub subs_def_qos: Option<SubscribedDefaultQos>,
    pub num_of_pack_filter: Option<u32>,
    pub online: Option<bool>,
    pub offline: Option<bool>,
    pub access_type: Option<AccessType>,
    pub rat_type: Option<RatType>,
    pub servingNetwork: Option<PlmnId>,
    pub user_location_info: Option<UserLocation>,
    pub ue_time_zone: Option<String>,
    pub pei: Option<String>,
    pub ipv4_frame_route_list: Option<Vec<String>>,
    pub ipv6_frame_route_list: Option<Vec<String>>,
    pub supp_feat: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyUpdateContextData {
    pub rep_policy_ctrl_req_triggers: Option<Vec<PolicyControlRequestTrigger>>,
    pub acc_net_ch_ids: Option<Vec<AccNetChId>>,
    pub access_type: Option<AccessType>,
    pub rat_type: Option<RatType>,
    pub add_access_info: Option<AdditionalAccessInfo>,
    pub rel_access_info: Option<AdditionalAccessInfo>,
    pub serving_network: Option<PlmnId>,
    pub user_location_info: Option<UserLocation>,
    pub ue_time_zone: Option<String>,
    pub rel_ipv4_address: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address_prefix: Option<String>,
    pub ip_domain: Option<String>,
    pub rel_ipv6_address_prefix: Option<String>,
    pub add_ipv6_addr_prefixes: Option<String>,
    pub add_rel_ipv6_addr_prefixes: Option<String>,
    pub rel_ue_mac: Option<String>,
    pub ue_mac: Option<String>,
    pub subs_sess_ambr: Option<Ambr>,
    pub auth_prof_index: Option<String>,
    pub subs_def_qos: Option<SubscribedDefaultQos>,
    pub num_of_pack_filter: Option<u32>,
    pub acc_usage_reports: Option<Vec<AccumulatedUsage>>,
    pub app_detection_infos: Option<Vec<AppDetectionInfo>>,
    pub rule_reports: Option<Vec<RuleReport>>,
    pub sess_rule_reports: Option<Vec<SessionRuleReport>>,
    pub qos_flow_usage: Option<Vec<QosFlowUsage>>,
    pub qnc_reports: Option<Vec<QosNotificationControlInfo>>,
    pub user_location_info_time: Option<String>,
    pub rep_pra_infos: Option<Vec<PresenceInfo>>,
    pub ue_init_res_req: Option<UeInitiatedResourceRequest>,
    pub ref_qos_indication: Option<bool>,
    pub qos_mon_reports: Option<Vec<QosMonitoringReport>>,
    pub sm_policy_notify_correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmPolicyDecision {
    pub sess_rules: Option<HashMap<String, SessionRule>>,
    pub pcc_rules: Option<HashMap<String, PccRule>>,
    pub pcscf_rest_indication: Option<bool>,
    pub qos_decs: Option<HashMap<String, QosData>>,
    pub chg_decs: Option<HashMap<String, ChargingData>>,
    pub charging_info: Option<ChargingInformation>,
    pub traff_cont_decs: Option<HashMap<String, TrafficControlData>>,
    pub um_decs: Option<HashMap<String, UsageMonitoringData>>,
    pub qos_chars: Option<HashMap<String, QosCharacteristics>>,
    pub qos_mon_decs: Option<HashMap<String, QosMonitoringDecision>>,
    pub reflective_qos_timer: Option<u32>,
    pub conds: Option<HashMap<String, ConditionData>>,
    pub revalidation_time: Option<String>,
    pub offline: Option<bool>,
    pub online: Option<bool>,
    pub policy_ctrl_req_triggers: Option<Vec<PolicyControlRequestTrigger>>,
    pub last_req_rule_data: Option<Vec<RequestedRuleData>>,
    pub last_req_usage_data: Option<RequestedUsageData>,
    pub pra_infos: Option<HashMap<String, PresenceInfoRm>>,
    pub ipv4_index: Option<u32>,
    pub ipv6_index: Option<u32>,
    pub supp_feat: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PccRule {
    pub flow_infos: Option<Vec<FlowInformation>>,
    pub app_id: Option<String>,
    pub app_descriptor: Option<AppDescriptor>,
    pub cont_ver: Option<u32>,
    pub pcc_rule_id: String,
    pub precedence: Option<u32>,
    pub af_sig_protocol: Option<AfSigProtocol>,
    pub app_reloc: Option<bool>,
    pub ref_qos_data: Option<Vec<String>>,
    pub ref_tc_data: Option<Vec<String>>,
    pub ref_chg_data: Option<Vec<String>>,
    pub ref_um_data: Option<Vec<String>>,
    pub ref_qos_mon: Option<Vec<String>>,
    pub ref_alt_qos_params: Option<Vec<String>>,
    pub ref_cond_data: Option<String>,
    pub rule_status: Option<RuleStatus>,
    pub qos_flow_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRule {
    pub auth_sess_ambr: Option<Ambr>,
    pub auth_def_qos: Option<AuthorizedDefaultQos>,
    pub sess_rule_id: String,
    pub ref_um_data: Option<String>,
    pub ref_cond_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosData {
    pub qos_id: String,
    #[serde(rename = "5qi")]
    pub qos_identifier_5: Option<u8>,
    pub maxbr_ul: Option<String>,
    pub maxbr_dl: Option<String>,
    pub gbr_ul: Option<String>,
    pub gbr_dl: Option<String>,
    pub arp: Option<Arp>,
    pub qnc: Option<bool>,
    pub priority_level: Option<u8>,
    pub aver_window: Option<u32>,
    pub max_data_burst_vol: Option<u32>,
    pub reflective_qos: Option<bool>,
    pub sharing_key_dl: Option<String>,
    pub sharing_key_ul: Option<String>,
    pub max_packet_loss_rate_dl: Option<u16>,
    pub max_packet_loss_rate_ul: Option<u16>,
    pub def_qos_flow_indication: Option<bool>,
    pub ext_max_data_burst_vol: Option<u32>,
    pub packet_delay_budget: Option<u32>,
    pub packet_error_rate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingData {
    pub chg_id: String,
    pub metering_method: Option<MeteringMethod>,
    pub online: Option<bool>,
    pub offline: Option<bool>,
    pub sdf_handl: Option<bool>,
    pub rating_group: Option<u32>,
    pub reporting_level: Option<ReportingLevel>,
    pub service_id: Option<u32>,
    pub sponsor_id: Option<String>,
    pub app_svc_prov_id: Option<String>,
    pub afl_charg_id: Option<String>,
    pub flow_charging_type: Option<FlowChargingType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingInformation {
    pub primary_ccf: Option<Vec<String>>,
    pub secondary_ccf: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficControlData {
    pub tc_id: String,
    pub flow_status: Option<FlowStatus>,
    pub redirect_info: Option<RedirectInformation>,
    pub mute_notif: Option<bool>,
    pub traff_steering_pol_id_dl: Option<String>,
    pub traff_steering_pol_id_ul: Option<String>,
    pub route_to_locs: Option<Vec<RouteToLocation>>,
    pub up_path_chg_event: Option<UpPathChgEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageMonitoringData {
    pub um_id: String,
    pub volume_threshold: Option<u64>,
    pub volume_threshold_uplink: Option<u64>,
    pub volume_threshold_downlink: Option<u64>,
    pub time_threshold: Option<u32>,
    pub monitoring_time: Option<String>,
    pub next_vol_threshold: Option<u64>,
    pub next_vol_threshold_uplink: Option<u64>,
    pub next_vol_threshold_downlink: Option<u64>,
    pub next_time_threshold: Option<u32>,
    pub inactivity_time: Option<u32>,
    pub expiry_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosCharacteristics {
    #[serde(rename = "5qi")]
    pub qos_identifier_5: Option<u8>,
    pub resource_type: Option<QosResourceType>,
    pub priority_level: Option<u8>,
    pub packet_delay_budget: Option<u32>,
    pub packet_error_rate: Option<String>,
    pub averaging_window: Option<u32>,
    pub max_data_burst_vol: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosMonitoringDecision {
    pub qm_id: String,
    pub rep_freqs: Option<Vec<ReportingFrequency>>,
    pub rep_thresh_dl: Option<u32>,
    pub rep_thresh_ul: Option<u32>,
    pub rep_thresh_rp: Option<u32>,
    pub wait_time: Option<u32>,
    pub rep_period: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowInformation {
    pub flow_description: Option<String>,
    pub eth_flow_description: Option<EthFlowDescription>,
    pub pack_filt_id: Option<String>,
    pub packet_filter_usage: Option<bool>,
    pub tos_traffic_class: Option<String>,
    pub spi: Option<String>,
    pub flow_label: Option<String>,
    pub flow_direction: Option<PcfFlowDirection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthFlowDescription {
    pub dest_mac_addr: Option<String>,
    pub eth_type: String,
    pub f_desc: Option<String>,
    pub f_dir: Option<PcfFlowDirection>,
    pub source_mac_addr: Option<String>,
    pub vlan_tags: Option<Vec<String>>,
    pub src_mac_addr_end: Option<String>,
    pub dest_mac_addr_end: Option<String>,
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
pub struct AuthorizedDefaultQos {
    #[serde(rename = "5qi")]
    pub qos_identifier_5: u8,
    pub arp: Option<Arp>,
    pub priority_level: Option<u8>,
    pub aver_window: Option<u32>,
    pub max_data_burst_vol: Option<u32>,
    pub maxbr_ul: Option<String>,
    pub maxbr_dl: Option<String>,
    pub gbr_ul: Option<String>,
    pub gbr_dl: Option<String>,
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessType {
    Gpe3gppAccess,
    NonGpe3gppAccess,
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyControlRequestTrigger {
    PlmnCh,
    ResModReq,
    AcTyChange,
    UeLoc,
    UseTimCh,
    PraChange,
    SessAmbrCh,
    QosNotif,
    NoCredit,
    RevalidTimeout,
    IpCanChange,
    QosFlowAdd,
    QosFlowDel,
    QosFlowMod,
    MacChange,
    UnanticiExc,
    ResAllExc,
    DefQosChange,
    SePolCh,
    ResReleReq,
    SuccResAlloc,
    UmChange,
    QncChange,
    AppDetection,
    AccessTypeNotify,
    RanNasRelChange,
    TsnBriManChange,
    TsnQosChange,
    SatChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowStatus {
    Enabled,
    Disabled,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PcfFlowDirection {
    Downlink,
    Uplink,
    Bidirectional,
    Unspecified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeteringMethod {
    Duration,
    Volume,
    DurationVolume,
    Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportingLevel {
    ServiceIdLevel,
    RatingGroupLevel,
    SponsoredConnectivityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowChargingType {
    OnlineOnly,
    OfflineOnly,
    OnlineOffline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QosResourceType {
    NonGbr,
    NonCriticalGbr,
    CriticalGbr,
    DelayCapableGbr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportingFrequency {
    SessionRelease,
    ServiceDataFlowRelease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AfSigProtocol {
    NoInfo,
    Sip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLocation {
    pub eutra_location: Option<EutraLocation>,
    pub nr_location: Option<NrLocation>,
    pub n3ga_location: Option<N3gaLocation>,
    pub utra_location: Option<UtraLocation>,
    pub gera_location: Option<GeraLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EutraLocation {
    pub tai: Tai,
    pub ecgi: Ecgi,
    pub ignore_ecgi: Option<bool>,
    pub age_of_location_information: Option<u32>,
    pub ue_location_timestamp: Option<String>,
    pub geographical_information: Option<String>,
    pub geodetic_information: Option<String>,
    pub global_ngenb_id: Option<GlobalRanNodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NrLocation {
    pub tai: Tai,
    pub ncgi: Ncgi,
    pub ignore_ncgi: Option<bool>,
    pub age_of_location_information: Option<u32>,
    pub ue_location_timestamp: Option<String>,
    pub geographical_information: Option<String>,
    pub geodetic_information: Option<String>,
    pub global_gnb_id: Option<GlobalRanNodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N3gaLocation {
    pub n3gpp_tai: Option<Tai>,
    pub n3_iwf_id: Option<String>,
    pub ue_ipv4_addr: Option<String>,
    pub ue_ipv6_addr: Option<String>,
    pub port_number: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UtraLocation {
    pub tai: Option<Tai>,
    pub ecgi: Option<Ecgi>,
    pub rai: Option<String>,
    pub sai: Option<String>,
    pub lai: Option<String>,
    pub age_of_location_information: Option<u32>,
    pub ue_location_timestamp: Option<String>,
    pub geographical_information: Option<String>,
    pub geodetic_information: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeraLocation {
    pub location_number: Option<String>,
    pub cgi: Option<String>,
    pub rai: Option<String>,
    pub sai: Option<String>,
    pub lai: Option<String>,
    pub vlr_number: Option<String>,
    pub msc_number: Option<String>,
    pub age_of_location_information: Option<u32>,
    pub ue_location_timestamp: Option<String>,
    pub geographical_information: Option<String>,
    pub geodetic_information: Option<String>,
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
pub struct RedirectInformation {
    pub redirect_enabled: Option<bool>,
    pub redirect_address_type: Option<RedirectAddressType>,
    pub redirect_server_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedirectAddressType {
    Ipv4Addr,
    Ipv6Addr,
    Url,
    SipUri,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteToLocation {
    pub dnai: String,
    pub route_info: Option<RouteInformation>,
    pub route_prof_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteInformation {
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub port_number: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpPathChgEvent {
    pub notification_uri: String,
    pub notif_correct_id: Option<String>,
    pub dnai_chg_type: Option<DnaiChangeType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnaiChangeType {
    Early,
    EarlyLate,
    Late,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionData {
    pub cond_id: String,
    pub activation_time: Option<String>,
    pub deactivation_time: Option<String>,
    pub access_type: Option<AccessType>,
    pub rat_type: Option<RatType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedRuleData {
    pub ref_pcc_rule_ids: Vec<String>,
    pub req_data: Vec<RequestedRuleDataType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedRuleDataType {
    ChId,
    MsTimeZone,
    UserLoc,
    ResRel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedUsageData {
    pub ref_um_ids: Vec<String>,
    pub all_um_ids: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceInfoRm {
    pub pra_id: Option<String>,
    pub additional_pra_id: Option<String>,
    pub presence_state: Option<PresenceState>,
    pub tracking_area_list: Option<Vec<Tai>>,
    pub ecgi_list: Option<Vec<Ecgi>>,
    pub ncgi_list: Option<Vec<Ncgi>>,
    pub global_ran_node_id_list: Option<Vec<GlobalRanNodeId>>,
    pub globale_nb_id_list: Option<Vec<GlobalRanNodeId>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PresenceState {
    InArea,
    OutOfArea,
    Unknown,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccNetChId {
    pub acc_net_cha_ref: u32,
    pub ref_pcc_rule_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalAccessInfo {
    pub access_type: AccessType,
    pub rat_type: Option<RatType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccumulatedUsage {
    pub duration: Option<u32>,
    pub total_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDetectionInfo {
    pub app_id: String,
    pub instance_id: Option<String>,
    pub sdf_descriptions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleReport {
    pub pcc_rule_ids: Vec<String>,
    pub rule_status: RuleStatus,
    pub cont_vers: Option<Vec<u32>>,
    pub failure_code: Option<FailureCode>,
    pub fin_unit_act: Option<FinalUnitAction>,
    pub ran_nas_rel_causes: Option<Vec<RanNasRelCause>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureCode {
    UnknownRuleId,
    RatingGroupError,
    ServiceIdError,
    GwPcefMalfunction,
    ResourcesLimitation,
    MaxNrBearer,
    UnknownBearerId,
    MissingBearerId,
    MissingFlowInfo,
    ResourceAllocationFailure,
    UnsuccessfulQosValidation,
    IncorrectFlowInfo,
    PsToCsHandover,
    TdfApplicationIdError,
    NoBearer,
    FilterRestrictions,
    AnGwFailed,
    MissingRedirectServerAddress,
    CmEndUserServiceDenied,
    CmCreditControlNotApplicable,
    CmAuthorizationRejected,
    CmUserUnknown,
    CmRatingFailed,
    MwFlowBlocked,
    UnauthorizedSponsorId,
    UnavailableSponsorId,
    UnauthorizedSponsoredDataConnectivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinalUnitAction {
    Terminate,
    Redirect,
    RestrictAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RanNasRelCause {
    pub ran_cause: Option<RanCause>,
    pub nas_cause: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RanCause {
    pub ng_ap_cause: Option<NgApCause>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NgApCause {
    pub group: u8,
    pub value: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRuleReport {
    pub rule_ids: Vec<String>,
    pub rule_status: RuleStatus,
    pub sess_rule_failure_code: Option<SessionRuleFailureCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionRuleFailureCode {
    UnknownRuleId,
    NoBearerBound,
    MissingFlowInfo,
    UnsuccessfulQosValidation,
    UnauthorizedSponsorId,
    UnavailableSponsorId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowUsage {
    pub qfi: u8,
    pub start_ts: Option<String>,
    pub end_ts: Option<String>,
    pub downlink_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosNotificationControlInfo {
    pub notif_type: QosNotifType,
    pub flows: Option<Vec<QosFlowUsage>>,
    pub alt_qos_param_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QosNotifType {
    Guaranteed,
    NotGuaranteed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceInfo {
    pub pra_id: String,
    pub additional_pra_id: Option<String>,
    pub presence_state: Option<PresenceState>,
    pub tracking_area_list: Option<Vec<Tai>>,
    pub ecgi_list: Option<Vec<Ecgi>>,
    pub ncgi_list: Option<Vec<Ncgi>>,
    pub global_ran_node_id_list: Option<Vec<GlobalRanNodeId>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UeInitiatedResourceRequest {
    pub pcc_rule_id: Option<String>,
    pub rule_op: RuleOperation,
    pub precedence: Option<u32>,
    pub req_qos: Option<RequestedQos>,
    pub pack_filt_info: Option<Vec<PacketFilterInfo>>,
    pub req_alternative_qos_params: Option<Vec<AlternativeQosProfile>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleOperation {
    CreatePccRule,
    DeletePccRule,
    ModifyPccRuleAndAddPackFilt,
    ModifyPccRuleAndReplacePackFilt,
    ModifyPccRuleAndDeletePackFilt,
    ModifyPccRuleWithoutModifyPackFilt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedQos {
    #[serde(rename = "5qi")]
    pub qos_identifier_5: Option<u8>,
    pub gbr_ul: Option<String>,
    pub gbr_dl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketFilterInfo {
    pub pack_filt_id: String,
    pub pack_filt_cont: Option<String>,
    pub tos_traffic_class: Option<String>,
    pub spi: Option<String>,
    pub flow_label: Option<String>,
    pub flow_direction: Option<PcfFlowDirection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlternativeQosProfile {
    pub alt_qos_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosMonitoringReport {
    pub ref_pcc_rule_ids: Vec<String>,
    pub ul_delays: Option<Vec<u32>>,
    pub dl_delays: Option<Vec<u32>>,
    pub rt_delays: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDescriptor {
    pub app_id: String,
    pub app_desc: String,
}
