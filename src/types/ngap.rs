use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Criticality {
    Reject,
    Ignore,
    Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Optional,
    Conditional,
    Mandatory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolIE<T> {
    pub id: u32,
    pub criticality: Criticality,
    pub value: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtpTunnel {
    pub transport_layer_address: Vec<u8>,
    pub gtp_teid: Vec<u8>,
}

impl GtpTunnel {
    pub fn get_ip_address(&self) -> Option<String> {
        if self.transport_layer_address.len() == 4 {
            Some(format!("{}.{}.{}.{}",
                self.transport_layer_address[0],
                self.transport_layer_address[1],
                self.transport_layer_address[2],
                self.transport_layer_address[3]))
        } else if self.transport_layer_address.len() == 16 {
            let parts: Vec<String> = self.transport_layer_address
                .chunks(2)
                .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk.get(1).unwrap_or(&0)))
                .collect();
            Some(parts.join(":"))
        } else {
            None
        }
    }

    pub fn get_teid(&self) -> Option<u32> {
        if self.gtp_teid.len() == 4 {
            Some(u32::from_be_bytes([
                self.gtp_teid[0],
                self.gtp_teid[1],
                self.gtp_teid[2],
                self.gtp_teid[3],
            ]))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowLevelQosParameters {
    pub qos_characteristics: QosCharacteristics,
    pub allocation_and_retention_priority: AllocationAndRetentionPriority,
    pub gbr_qos_flow_information: Option<GbrQosFlowInformation>,
    pub reflective_qos_attribute: Option<ReflectiveQosAttribute>,
    pub additional_qos_flow_information: Option<AdditionalQosFlowInformation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QosCharacteristics {
    NonDynamic5qi(NonDynamic5qiDescriptor),
    Dynamic5qi(Dynamic5qiDescriptor),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonDynamic5qiDescriptor {
    pub five_qi: u8,
    pub priority_level: Option<u8>,
    pub averaging_window: Option<u32>,
    pub maximum_data_burst_volume: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dynamic5qiDescriptor {
    pub priority_level: u8,
    pub packet_delay_budget: u32,
    pub packet_error_rate: PacketErrorRate,
    pub averaging_window: Option<u32>,
    pub maximum_data_burst_volume: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketErrorRate {
    pub per_scalar: u8,
    pub per_exponent: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationAndRetentionPriority {
    pub priority_level: u8,
    pub pre_emption_capability: PreEmptionCapability,
    pub pre_emption_vulnerability: PreEmptionVulnerability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreEmptionCapability {
    ShallNotTriggerPreEmption,
    MayTriggerPreEmption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreEmptionVulnerability {
    NotPreEmptable,
    PreEmptable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GbrQosFlowInformation {
    pub maximum_flow_bit_rate_dl: u64,
    pub maximum_flow_bit_rate_ul: u64,
    pub guaranteed_flow_bit_rate_dl: u64,
    pub guaranteed_flow_bit_rate_ul: u64,
    pub notification_control: Option<NotificationControl>,
    pub maximum_packet_loss_rate_dl: Option<u16>,
    pub maximum_packet_loss_rate_ul: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationControl {
    NotificationRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReflectiveQosAttribute {
    SubjectTo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdditionalQosFlowInformation {
    MoreLikely,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLocationInformation {
    pub nr_cgi: Option<NrCgi>,
    pub tai: Option<NgapTai>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrCgi {
    pub plmn_identity: PlmnIdentity,
    pub nr_cell_identity: NrCellIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlmnIdentity {
    pub mcc: String,
    pub mnc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrCellIdentity {
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgapTai {
    pub plmn_identity: PlmnIdentity,
    pub tac: NgapTac,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgapTac {
    pub value: Vec<u8>,
}

impl NgapTac {
    pub fn to_u32(&self) -> Option<u32> {
        if self.value.len() == 3 {
            Some(u32::from_be_bytes([0, self.value[0], self.value[1], self.value[2]]))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowSetupRequestItem {
    pub qos_flow_identifier: u8,
    pub qos_flow_level_qos_parameters: QosFlowLevelQosParameters,
    pub e_rab_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowWithCauseItem {
    pub qos_flow_identifier: u8,
    pub cause: NgapCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NgapCause {
    RadioNetwork(RadioNetworkCause),
    Transport(TransportCause),
    Nas(NasCause),
    Protocol(ProtocolCause),
    Misc(MiscCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadioNetworkCause {
    UnspecifiedRadioNetworkCause,
    TxnrelocoverallExpiry,
    SuccessfulHandover,
    ReleaseDueToNgranGeneratedReason,
    ReleaseDueToFiveGcGeneratedReason,
    HandoverCancelled,
    PartialHandover,
    HoFailureInTarget5GCNgranNode,
    HoTargetNotAllowed,
    TngrelocoverallExpiry,
    TngrelocprepExpiry,
    CellNotAvailable,
    UnknownTargetId,
    NoRadioResourcesAvailableInTargetCell,
    UnknownLocalUeNgapId,
    InconsistentRemoteUeNgapId,
    HandoverDesirableForRadioReason,
    TimeCriticalHandover,
    ResourceOptimisationHandover,
    ReduceLoadInServingCell,
    UserInactivity,
    RadioConnectionWithUeLost,
    RadioResourcesNotAvailable,
    InvalidQosCombination,
    FailureInRadioInterfaceProcedure,
    InteractionWithOtherProcedure,
    UnknownPduSessionId,
    UeRrcConnectionReestablishmentFailure,
    MultipleSessionsNotSupported,
    UeContextReestFailure,
    NgIntraSystemHandoverTriggered,
    NgInterSystemHandoverTriggered,
    XnHandoverTriggered,
    NotSupported5qiValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportCause {
    TransportResourceUnavailable,
    UnspecifiedTransportCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NasCause {
    NormalRelease,
    AuthenticationFailure,
    Deregister,
    UnspecifiedNasCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolCause {
    TransferSyntaxError,
    AbstractSyntaxErrorReject,
    AbstractSyntaxErrorIgnoreAndNotify,
    MessageNotCompatibleWithReceiverState,
    SemanticError,
    AbstractSyntaxErrorFalselyConstructedMessage,
    UnspecifiedProtocolCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MiscCause {
    ControlProcessingOverload,
    NotEnoughUserPlaneProcessingResources,
    HardwareFailure,
    OmIntervention,
    UnknownPlmn,
    UnspecifiedMiscCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PduSessionResourceSetupResponseTransfer {
    pub dl_qos_flow_per_tnl_information: QosFlowPerTnlInformation,
    pub additional_dl_qos_flow_per_tnl_information: Option<Vec<QosFlowPerTnlInformation>>,
    pub security_result: Option<SecurityResult>,
    pub qos_flow_failed_to_setup_list: Option<Vec<QosFlowWithCauseItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowPerTnlInformation {
    pub up_transport_layer_information: GtpTunnel,
    pub associated_qos_flow_list: Vec<AssociatedQosFlowItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociatedQosFlowItem {
    pub qos_flow_identifier: u8,
    pub qos_flow_mapping_indication: Option<QosFlowMappingIndication>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QosFlowMappingIndication {
    Ul,
    Dl,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityResult {
    pub integrity_protection_result: IntegrityProtectionResult,
    pub confidentiality_protection_result: ConfidentialityProtectionResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityProtectionResult {
    Performed,
    NotPerformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidentialityProtectionResult {
    Performed,
    NotPerformed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSwitchRequestTransfer {
    pub dl_ngu_up_tnl_information: GtpTunnel,
    pub dl_ngu_tnl_information_reused: Option<DlNguTnlInformationReused>,
    pub user_plane_security_information: Option<UserPlaneSecurityInformation>,
    pub qos_flow_accepted_list: Option<Vec<QosFlowAcceptedItem>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlNguTnlInformationReused {
    True,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserPlaneSecurityInformation {
    pub security_result: SecurityResult,
    pub security_indication: SecurityIndication,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityIndication {
    pub integrity_protection_indication: IntegrityProtectionIndication,
    pub confidentiality_protection_indication: ConfidentialityProtectionIndication,
    pub maximum_integrity_protected_data_rate_ul: Option<MaximumIntegrityProtectedDataRate>,
    pub maximum_integrity_protected_data_rate_dl: Option<MaximumIntegrityProtectedDataRate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityProtectionIndication {
    Required,
    Preferred,
    NotNeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidentialityProtectionIndication {
    Required,
    Preferred,
    NotNeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaximumIntegrityProtectedDataRate {
    Bitrate64kbs,
    MaximumUeRate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QosFlowAcceptedItem {
    pub qos_flow_identifier: u8,
}
