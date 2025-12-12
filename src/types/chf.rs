use serde::{Deserialize, Serialize};
use super::PlmnId;
use std::collections::HashMap;

pub use super::udm::Ambr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataRequest {
    pub subscriber_identifier: String,
    pub nf_consumer_identification: NfIdentification,
    pub invocation_time_stamp: String,
    pub invocation_sequence_number: u32,
    pub one_time_event: Option<bool>,
    pub one_time_event_type: Option<OneTimeEventType>,
    pub notify_uri: Option<String>,
    pub multipleunit_usage: Option<Vec<MultipleUnitUsage>>,
    pub triggers: Option<Vec<Trigger>>,
    pub pdu_session_charging_information: Option<PduSessionChargingInformation>,
    pub roaming_qbc_information: Option<RoamingQbcInformation>,
    pub tenant_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargingDataResponse {
    pub invocation_time_stamp: String,
    pub invocation_sequence_number: u32,
    pub invocation_result: Option<InvocationResult>,
    pub session_failure_indication: Option<SessionFailureIndication>,
    pub multipleunit_information: Option<Vec<MultipleUnitInformation>>,
    pub triggers: Option<Vec<Trigger>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfIdentification {
    pub nf_name: String,
    pub nf_ip_v4_address: Option<String>,
    pub nf_ip_v6_address: Option<String>,
    pub nf_plmn_id: Option<PlmnId>,
    pub nf_fqdn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultipleUnitUsage {
    pub rating_group: u32,
    pub requested_unit: Option<RequestedUnit>,
    pub used_unit_container: Option<Vec<UsedUnitContainer>>,
    pub upfid: Option<String>,
    pub multihomedpdu_address: Option<PduAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedUnit {
    pub time: Option<u32>,
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
    pub service_specific_units: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsedUnitContainer {
    pub service_id: Option<u32>,
    pub triggers: Option<Vec<Trigger>>,
    pub trigger_timestamp: Option<String>,
    pub time: Option<u32>,
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
    pub service_specific_units: Option<u64>,
    pub event_time_stamps: Option<Vec<String>>,
    pub local_sequence_number: u32,
    pub pdu_container_information: Option<PduContainerInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduContainerInformation {
    pub time_of_first_usage: Option<String>,
    pub time_of_last_usage: Option<String>,
    pub qos_information: Option<QosInformation>,
    pub qos_characteristics: Option<QosCharacteristics>,
    pub af_correlation_information: Option<String>,
    pub user_location_information: Option<UserLocationInfo>,
    pub uetimezone: Option<String>,
    pub rat_type: Option<RatType>,
    pub serving_node_id: Option<Vec<ServingNetworkFunctionId>>,
    pub presence_reporting_area_information: Option<HashMap<String, PresenceInfo>>,
    #[serde(rename = "3gppPSDataOffStatus")]
    pub ps_data_off_status: Option<String>,
    pub sponsor_identity: Option<String>,
    pub application_service_provider_identity: Option<String>,
    pub charging_rule_base_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosInformation {
    #[serde(rename = "5qi")]
    pub qos_identifier_5: Option<u8>,
    pub maximum_bit_rate_uplink: Option<String>,
    pub maximum_bit_rate_downlink: Option<String>,
    pub guaranteed_bit_rate_uplink: Option<String>,
    pub guaranteed_bit_rate_downlink: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosCharacteristics {
    #[serde(rename = "5qi")]
    pub qos_identifier_5: u8,
    pub resource_type: Option<QosResourceType>,
    pub priority_level: Option<u8>,
    pub packet_delay_budget: Option<u32>,
    pub packet_error_rate: Option<String>,
    pub averaging_window: Option<u32>,
    pub maximum_data_burst_volume: Option<u32>,
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
#[serde(rename_all = "camelCase")]
pub struct UserLocationInfo {
    pub eutra_location: Option<EutraLocation>,
    pub nr_location: Option<NrLocation>,
    pub n3ga_location: Option<N3gaLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EutraLocation {
    pub tai: Tai,
    pub ecgi: Ecgi,
    pub age_of_location_information: Option<u32>,
    pub ue_location_timestamp: Option<String>,
    pub geographical_information: Option<String>,
    pub geodetic_information: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NrLocation {
    pub tai: Tai,
    pub ncgi: Ncgi,
    pub age_of_location_information: Option<u32>,
    pub ue_location_timestamp: Option<String>,
    pub geographical_information: Option<String>,
    pub geodetic_information: Option<String>,
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
pub struct Tai {
    pub plmn_id: PlmnId,
    pub tac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ecgi {
    pub plmn_id: PlmnId,
    pub eutra_cell_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ncgi {
    pub plmn_id: PlmnId,
    pub nr_cell_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServingNetworkFunctionId {
    pub serving_network_function_name: Option<String>,
    pub serving_network_function_instance_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceInfo {
    pub pra_id: String,
    pub presence_state: Option<PresenceState>,
    pub tracking_area_list: Option<Vec<Tai>>,
    pub ecgi_list: Option<Vec<Ecgi>>,
    pub ncgi_list: Option<Vec<Ncgi>>,
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
pub struct MultipleUnitInformation {
    pub result_code: Option<ResultCode>,
    pub rating_group: u32,
    pub granted_unit: Option<GrantedUnit>,
    pub triggers: Option<Vec<Trigger>>,
    pub validity_time: Option<u32>,
    pub quota_holding_time: Option<u32>,
    pub final_unit_indication: Option<FinalUnitIndication>,
    pub time_quota_mechanism: Option<TimeQuotaMechanism>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantedUnit {
    pub tariff_time_change: Option<String>,
    pub time: Option<u32>,
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub downlink_volume: Option<u64>,
    pub service_specific_units: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalUnitIndication {
    pub final_unit_action: FinalUnitAction,
    pub restriction_filter_rule: Option<Vec<String>>,
    pub filter_id: Option<Vec<String>>,
    pub redirect_server: Option<RedirectServer>,
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
pub struct RedirectServer {
    pub redirect_address_type: RedirectAddressType,
    pub redirect_server_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RedirectAddressType {
    Ipv4Address,
    Ipv6Address,
    Url,
    SipUri,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeQuotaMechanism {
    pub time_quota_type: TimeQuotaType,
    pub base_time_interval: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimeQuotaType {
    DiscreteTimeperiod,
    ContinuousTimeperiod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionChargingInformation {
    pub charging_id: Option<u32>,
    pub home_provided_charging_id: Option<u32>,
    pub user_information: Option<UserInformation>,
    pub user_location_info: Option<UserLocationInfo>,
    pub user_location_time: Option<String>,
    pub pres_reporting_area_info: Option<HashMap<String, PresenceInfo>>,
    #[serde(rename = "3gppPSDataOffStatus")]
    pub ps_data_off_status: Option<String>,
    pub uetimezone: Option<String>,
    pub rat_type: Option<RatType>,
    pub serving_node_id: Option<Vec<ServingNetworkFunctionId>>,
    pub serving_network_function_id: Option<ServingNetworkFunctionId>,
    pub pdu_session_information: PduSessionInformation,
    pub unit_count_inactivity_timer: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInformation {
    pub served_gpsi: Option<String>,
    pub served_pei: Option<String>,
    pub unauthenticated_flag: Option<bool>,
    pub roamer_in_out: Option<RoamerInOut>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RoamerInOut {
    InBound,
    OutBound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionInformation {
    pub network_slice_instance_id: Option<String>,
    pub pdu_session_id: u8,
    pub pdu_type: PduSessionType,
    pub ssc_mode: SscMode,
    pub hplmn_pdu_session_id: Option<u8>,
    pub authorized_qos_information: Option<QosInformation>,
    pub authorized_session_ambr: Option<Ambr>,
    pub pdu_address: Option<PduAddress>,
    pub serving_cn_plmn_id: Option<PlmnId>,
    pub dnn_id: Option<String>,
    pub dnn_selection_mode: Option<DnnSelectionMode>,
    pub charging_characteristics: Option<String>,
    pub charging_characteristics_selection_mode: Option<ChargingCharacteristicsSelectionMode>,
    pub start_time: Option<String>,
    pub stop_time: Option<String>,
    #[serde(rename = "3gppPSDataOffStatus")]
    pub ps_data_off_status: Option<String>,
    pub session_stop_indicator: Option<bool>,
    pub pdu_session_pair_id: Option<u8>,
    pub dnai_list: Option<Vec<String>>,
    pub redundant_pdu_session_information: Option<RedundantPduSessionInformation>,
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SscMode {
    SscMode1,
    SscMode2,
    SscMode3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduAddress {
    pub pdu_ipv4_address: Option<String>,
    pub pdu_ipv6_address_with_prefix: Option<String>,
    pub ipv4_dynamic_address_flag: Option<bool>,
    pub ipv6_dynamic_prefix_flag: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnnSelectionMode {
    Verified,
    UeProvidedNotVerified,
    NetworkProvided,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChargingCharacteristicsSelectionMode {
    HomeDefault,
    RoamingDefault,
    VisitingDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedundantPduSessionInformation {
    pub rsn: Option<u8>,
    pub pdu_session_pair_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoamingQbcInformation {
    pub multipleqfi_container: Option<Vec<MultipleQfiContainer>>,
    pub uetimezone: Option<String>,
    pub qbc_transmission_policy: Option<QbcTransmissionPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultipleQfiContainer {
    pub triggers: Option<Vec<Trigger>>,
    pub trigger_timestamp: Option<String>,
    pub time: Option<u32>,
    pub total_volume: Option<u64>,
    pub uplink_volume: Option<u64>,
    pub local_sequence_number: u32,
    pub qfi_container_information: Option<QfiContainerInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QfiContainerInformation {
    pub qfi: u8,
    pub time_of_first_usage: Option<String>,
    pub time_of_last_usage: Option<String>,
    pub qos_information: Option<QosInformation>,
    pub qos_characteristics: Option<QosCharacteristics>,
    pub user_location_information: Option<UserLocationInfo>,
    pub uetimezone: Option<String>,
    pub presence_reporting_area_information: Option<HashMap<String, PresenceInfo>>,
    pub rat_type: Option<RatType>,
    #[serde(rename = "3gppPSDataOffStatus")]
    pub ps_data_off_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QbcTransmissionPolicy {
    pub qbc_transfer_service_class: Option<QbcTransferServiceClass>,
    pub qbc_transfer_policy: Option<Vec<QbcTransferPolicy>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbcTransferServiceClass {
    ServiceClass1,
    ServiceClass2,
    ServiceClass3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbcTransferPolicy {
    Immediate,
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Trigger {
    MaxNumberOfChangesInChargingConditions,
    VolumeLimit,
    TimeLimit,
    PlmnChange,
    UserLocationChange,
    RatChange,
    SessionAmbr,
    QosChange,
    TariffTimeChange,
    MaxNumberOfChangesInChargingconditions,
    Validity,
    ChangedQfi,
    ChangeOfUePresenceInPresenceReportingArea,
    StartOfServiceDataFlow,
    StopOfServiceDataFlow,
    #[serde(rename = "3GPP_PS_DATA_OFF")]
    PsDataOff,
    UeTimezoneChange,
    ServingNodePlmnChange,
    OtherRatUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultCode {
    Success,
    EndUserServiceDenied,
    CreditControlNotApplicable,
    CreditLimitReached,
    AuthorizationRejected,
    UserUnknown,
    RatingFailed,
    OutOfCredit,
    QuotaLimitReached,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvocationResult {
    Success,
    PartialSuccess,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionFailureIndication {
    UnavailableRatingGroup,
    UnknownRatingGroup,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OneTimeEventType {
    Iec,
    Pec,
}
