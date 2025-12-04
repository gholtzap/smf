use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionEstablishmentRequest {
    pub node_id: NodeId,
    pub f_seid: FSeid,
    pub create_pdr: Vec<CreatePdr>,
    pub create_far: Vec<CreateFar>,
    pub create_qer: Option<Vec<CreateQer>>,
    pub create_urr: Option<Vec<CreateUrr>>,
    pub pdn_type: Option<PdnType>,
    pub user_plane_inactivity_timer: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionEstablishmentResponse {
    pub node_id: NodeId,
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
    pub f_seid: Option<FSeid>,
    pub created_pdr: Option<Vec<CreatedPdr>>,
    pub load_control_information: Option<LoadControlInformation>,
    pub overload_control_information: Option<OverloadControlInformation>,
    pub failed_rule_id: Option<FailedRuleId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionModificationRequest {
    pub f_seid: Option<FSeid>,
    pub remove_pdr: Option<Vec<RemovePdr>>,
    pub remove_far: Option<Vec<RemoveFar>>,
    pub remove_qer: Option<Vec<RemoveQer>>,
    pub remove_urr: Option<Vec<RemoveUrr>>,
    pub create_pdr: Option<Vec<CreatePdr>>,
    pub create_far: Option<Vec<CreateFar>>,
    pub create_qer: Option<Vec<CreateQer>>,
    pub create_urr: Option<Vec<CreateUrr>>,
    pub update_pdr: Option<Vec<UpdatePdr>>,
    pub update_far: Option<Vec<UpdateFar>>,
    pub update_qer: Option<Vec<UpdateQer>>,
    pub update_urr: Option<Vec<UpdateUrr>>,
    pub query_urr: Option<Vec<QueryUrr>>,
    pub pfcp_session_retention_information: Option<PfcpSessionRetentionInformation>,
    pub user_plane_inactivity_timer: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionModificationResponse {
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
    pub created_pdr: Option<Vec<CreatedPdr>>,
    pub load_control_information: Option<LoadControlInformation>,
    pub overload_control_information: Option<OverloadControlInformation>,
    pub usage_report: Option<Vec<UsageReport>>,
    pub failed_rule_id: Option<FailedRuleId>,
    pub additional_usage_reports_information: Option<AdditionalUsageReportsInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionDeletionRequest {
    pub user_plane_inactivity_timer: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionDeletionResponse {
    pub cause: PfcpCause,
    pub offending_ie: Option<u16>,
    pub load_control_information: Option<LoadControlInformation>,
    pub overload_control_information: Option<OverloadControlInformation>,
    pub usage_report: Option<Vec<UsageReport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeId {
    pub node_id_type: NodeIdType,
    pub node_id_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeIdType {
    Ipv4Address,
    Ipv6Address,
    Fqdn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSeid {
    pub seid: u64,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePdr {
    pub pdr_id: u16,
    pub precedence: u32,
    pub pdi: Pdi,
    pub outer_header_removal: Option<OuterHeaderRemoval>,
    pub far_id: u32,
    pub qer_id: Option<Vec<u32>>,
    pub urr_id: Option<Vec<u32>>,
    pub activation_time: Option<u64>,
    pub deactivation_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pdi {
    pub source_interface: SourceInterface,
    pub local_f_teid: Option<FTeid>,
    pub network_instance: Option<String>,
    pub ue_ip_address: Option<UeIpAddress>,
    pub sdf_filter: Option<Vec<SdfFilter>>,
    pub application_id: Option<String>,
    pub ethernet_pdu_session_information: Option<EthernetPduSessionInformation>,
    pub framed_route: Option<Vec<String>>,
    pub framed_routing: Option<u32>,
    pub framed_ipv6_route: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceInterface {
    Access,
    Core,
    SgiLanN6Lan,
    CpFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FTeid {
    pub teid: u32,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub choose_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UeIpAddress {
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_prefix_length: Option<u8>,
    pub is_destination: bool,
    pub is_source: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdfFilter {
    pub flow_description: Option<String>,
    pub tos_traffic_class: Option<u16>,
    pub security_parameter_index: Option<u32>,
    pub flow_label: Option<u32>,
    pub sdf_filter_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetPduSessionInformation {
    pub ethi: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterHeaderRemoval {
    pub outer_header_removal_description: OuterHeaderRemovalDescription,
    pub gtpu_extension_header_deletion: Option<GtpuExtensionHeaderDeletion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OuterHeaderRemovalDescription {
    GtpUUdpIpv4,
    GtpUUdpIpv6,
    UdpIpv4,
    UdpIpv6,
    Ipv4,
    Ipv6,
    GtpUUdpIp,
    VlanSTag,
    STagAndCTag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpuExtensionHeaderDeletion {
    pub pdu_session_container: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFar {
    pub far_id: u32,
    pub apply_action: ApplyAction,
    pub forwarding_parameters: Option<ForwardingParameters>,
    pub duplicating_parameters: Option<DuplicatingParameters>,
    pub bar_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyAction {
    pub drop: bool,
    pub forw: bool,
    pub buff: bool,
    pub nocp: bool,
    pub dupl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingParameters {
    pub destination_interface: DestinationInterface,
    pub network_instance: Option<String>,
    pub redirect_information: Option<RedirectInformation>,
    pub outer_header_creation: Option<OuterHeaderCreation>,
    pub transport_level_marking: Option<u16>,
    pub forwarding_policy: Option<String>,
    pub header_enrichment: Option<HeaderEnrichment>,
    pub traffic_endpoint_id: Option<u8>,
    pub proxying: Option<Proxying>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestinationInterface {
    Access,
    Core,
    SgiLanN6Lan,
    CpFunction,
    LiFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectInformation {
    pub redirect_address_type: RedirectAddressType,
    pub redirect_server_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedirectAddressType {
    Ipv4Address,
    Ipv6Address,
    Url,
    SipUri,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterHeaderCreation {
    pub outer_header_creation_description: OuterHeaderCreationDescription,
    pub teid: Option<u32>,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub port_number: Option<u16>,
    pub ctag: Option<u16>,
    pub stag: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OuterHeaderCreationDescription {
    GtpUUdpIpv4,
    GtpUUdpIpv6,
    UdpIpv4,
    UdpIpv6,
    Ipv4,
    Ipv6,
    CTagAndSTag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderEnrichment {
    pub header_type: HeaderType,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeaderType {
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxying {
    pub arp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicatingParameters {
    pub destination_interface: DestinationInterface,
    pub outer_header_creation: Option<OuterHeaderCreation>,
    pub transport_level_marking: Option<u16>,
    pub forwarding_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateQer {
    pub qer_id: u32,
    pub qer_correlation_id: Option<u32>,
    pub gate_status: GateStatus,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
    pub packet_rate: Option<PacketRate>,
    pub dl_flow_level_marking: Option<DlFlowLevelMarking>,
    pub qos_flow_identifier: Option<u8>,
    pub reflective_qos: Option<ReflectiveQos>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateStatus {
    pub ul_gate: GateState,
    pub dl_gate: GateState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateState {
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mbr {
    pub ul_mbr: u64,
    pub dl_mbr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gbr {
    pub ul_gbr: u64,
    pub dl_gbr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRate {
    pub ul_time_unit: TimeUnit,
    pub max_ul_packet_rate: u16,
    pub dl_time_unit: TimeUnit,
    pub max_dl_packet_rate: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeUnit {
    Minute,
    SixMinutes,
    Hour,
    Day,
    Week,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlFlowLevelMarking {
    pub tos_traffic_class: u16,
    pub service_class_indicator: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectiveQos {
    pub rqi: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUrr {
    pub urr_id: u32,
    pub measurement_method: MeasurementMethod,
    pub reporting_triggers: ReportingTriggers,
    pub measurement_period: Option<u32>,
    pub volume_threshold: Option<VolumeThreshold>,
    pub volume_quota: Option<VolumeQuota>,
    pub time_threshold: Option<u32>,
    pub time_quota: Option<u32>,
    pub quota_holding_time: Option<u32>,
    pub dropped_dl_traffic_threshold: Option<DroppedDlTrafficThreshold>,
    pub monitoring_time: Option<u64>,
    pub subsequent_volume_threshold: Option<VolumeThreshold>,
    pub subsequent_time_threshold: Option<u32>,
    pub inactivity_detection_time: Option<u32>,
    pub linked_urr_id: Option<Vec<u32>>,
    pub measurement_information: Option<MeasurementInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementMethod {
    pub durat: bool,
    pub volum: bool,
    pub event: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingTriggers {
    pub periodic_reporting: bool,
    pub volume_threshold: bool,
    pub time_threshold: bool,
    pub quota_holding_time: bool,
    pub start_of_traffic: bool,
    pub stop_of_traffic: bool,
    pub dropped_dl_traffic_threshold: bool,
    pub volume_quota: bool,
    pub time_quota: bool,
    pub envelope_closure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeThreshold {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeQuota {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedDlTrafficThreshold {
    pub downlink_packets: Option<u64>,
    pub downlink_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementInformation {
    pub mbqe: bool,
    pub inam: bool,
    pub radi: bool,
    pub istm: bool,
    pub mnop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedPdr {
    pub pdr_id: u16,
    pub local_f_teid: Option<FTeid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadControlInformation {
    pub load_control_sequence_number: u32,
    pub load_metric: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverloadControlInformation {
    pub overload_control_sequence_number: u32,
    pub overload_reduction_metric: u8,
    pub period_of_validity: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedRuleId {
    pub rule_id_type: RuleIdType,
    pub rule_id_value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleIdType {
    Pdr,
    Far,
    Qer,
    Urr,
    Bar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePdr {
    pub pdr_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveFar {
    pub far_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveQer {
    pub qer_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveUrr {
    pub urr_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePdr {
    pub pdr_id: u16,
    pub precedence: Option<u32>,
    pub pdi: Option<Pdi>,
    pub outer_header_removal: Option<OuterHeaderRemoval>,
    pub far_id: Option<u32>,
    pub qer_id: Option<Vec<u32>>,
    pub urr_id: Option<Vec<u32>>,
    pub activation_time: Option<u64>,
    pub deactivation_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFar {
    pub far_id: u32,
    pub apply_action: Option<ApplyAction>,
    pub forwarding_parameters: Option<ForwardingParameters>,
    pub duplicating_parameters: Option<DuplicatingParameters>,
    pub bar_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateQer {
    pub qer_id: u32,
    pub qer_correlation_id: Option<u32>,
    pub gate_status: Option<GateStatus>,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
    pub packet_rate: Option<PacketRate>,
    pub dl_flow_level_marking: Option<DlFlowLevelMarking>,
    pub qos_flow_identifier: Option<u8>,
    pub reflective_qos: Option<ReflectiveQos>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUrr {
    pub urr_id: u32,
    pub measurement_method: Option<MeasurementMethod>,
    pub reporting_triggers: Option<ReportingTriggers>,
    pub measurement_period: Option<u32>,
    pub volume_threshold: Option<VolumeThreshold>,
    pub volume_quota: Option<VolumeQuota>,
    pub time_threshold: Option<u32>,
    pub time_quota: Option<u32>,
    pub quota_holding_time: Option<u32>,
    pub dropped_dl_traffic_threshold: Option<DroppedDlTrafficThreshold>,
    pub monitoring_time: Option<u64>,
    pub subsequent_volume_threshold: Option<VolumeThreshold>,
    pub subsequent_time_threshold: Option<u32>,
    pub inactivity_detection_time: Option<u32>,
    pub linked_urr_id: Option<Vec<u32>>,
    pub measurement_information: Option<MeasurementInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryUrr {
    pub urr_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpSessionRetentionInformation {
    pub cp_pfcp_entity_ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    pub urr_id: u32,
    pub ur_seqn: u32,
    pub usage_report_trigger: UsageReportTrigger,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub volume_measurement: Option<VolumeMeasurement>,
    pub duration_measurement: Option<u32>,
    pub time_of_first_packet: Option<u64>,
    pub time_of_last_packet: Option<u64>,
    pub usage_information: Option<UsageInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReportTrigger {
    pub periodic_reporting: bool,
    pub volume_threshold: bool,
    pub time_threshold: bool,
    pub quota_holding_time: bool,
    pub start_of_traffic: bool,
    pub stop_of_traffic: bool,
    pub dropped_dl_traffic_threshold: bool,
    pub volume_quota: bool,
    pub time_quota: bool,
    pub envelope_closure: bool,
    pub termination_report: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMeasurement {
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageInformation {
    pub before: bool,
    pub after: bool,
    pub quvti: bool,
    pub ube: bool,
    pub uae: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalUsageReportsInformation {
    pub auri: bool,
    pub number_of_additional_usage_reports: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PfcpCause {
    Reserved,
    RequestAccepted,
    RequestRejected,
    SessionContextNotFound,
    MandatoryIeMissing,
    ConditionalIeMissing,
    InvalidLength,
    MandatoryIeIncorrect,
    InvalidForwardingPolicy,
    InvalidFTeidAllocationOption,
    NoEstablishedPfcpAssociation,
    RuleDeletionFailure,
    PfcpEntityInCongestion,
    NoResourcesAvailable,
    ServiceNotSupported,
    SystemFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PdnType {
    Ipv4,
    Ipv6,
    Ipv4v6,
    NonIp,
    Ethernet,
}
