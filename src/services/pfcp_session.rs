use crate::services::pfcp::{PfcpClient, PfcpClientInner};
use crate::types::pfcp::*;
use crate::types::{QosFlow, QosFlowType};
use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub struct PfcpSessionManager;

impl PfcpSessionManager {
    fn create_qer_from_qos_flow(qos_flow: &QosFlow) -> CreateQer {
        let (gbr, mbr) = match &qos_flow.qos_flow_type {
            QosFlowType::GBR | QosFlowType::DelayGBR => {
                let gbr = qos_flow.gfbr.as_ref().map(|gfbr| Gbr {
                    ul_gbr: gfbr.uplink,
                    dl_gbr: gfbr.downlink,
                });
                let mbr = qos_flow.mfbr.as_ref().map(|mfbr| Mbr {
                    ul_mbr: mfbr.uplink,
                    dl_mbr: mfbr.downlink,
                });
                (gbr, mbr)
            }
            QosFlowType::NonGBR => (None, None),
        };

        CreateQer {
            qer_id: qos_flow.qfi as u32,
            qer_correlation_id: None,
            gate_status: GateStatus {
                ul_gate: GateState::Open,
                dl_gate: GateState::Open,
            },
            mbr,
            gbr,
            packet_rate: None,
            dl_flow_level_marking: None,
            qos_flow_identifier: Some(qos_flow.qfi),
            reflective_qos: None,
        }
    }

    pub async fn establish_session(
        pfcp_client: &PfcpClient,
        seid: u64,
        ue_ipv4: Ipv4Addr,
        upf_ipv4: Ipv4Addr,
        qos_flows: &[QosFlow],
    ) -> Result<PfcpSessionEstablishmentResponse> {
        let node_id = NodeId {
            node_id_type: NodeIdType::Ipv4Address,
            node_id_value: pfcp_client.local_address()?.ip().to_string(),
        };

        let f_seid = FSeid {
            seid,
            ipv4_address: Some(pfcp_client.local_address()?.ip().to_string().parse()?),
            ipv6_address: None,
        };

        let pdr_id = 1u16;
        let far_id_ul = 1u32;
        let far_id_dl = 2u32;

        let qer_ids: Vec<u32> = if !qos_flows.is_empty() {
            qos_flows.iter().map(|qf| qf.qfi as u32).collect()
        } else {
            vec![]
        };

        let pdr_ul = CreatePdr {
            pdr_id,
            precedence: 100,
            pdi: Pdi {
                source_interface: SourceInterface::Access,
                local_f_teid: Some(FTeid {
                    teid: seid as u32,
                    ipv4_address: Some(upf_ipv4),
                    ipv6_address: None,
                    choose_id: None,
                }),
                network_instance: Some("internet".to_string()),
                ue_ip_address: Some(UeIpAddress {
                    ipv4_address: Some(ue_ipv4),
                    ipv6_address: None,
                    ipv6_prefix_length: None,
                    is_destination: false,
                    is_source: true,
                }),
                sdf_filter: None,
                application_id: None,
                ethernet_pdu_session_information: None,
                framed_route: None,
                framed_routing: None,
                framed_ipv6_route: None,
            },
            outer_header_removal: Some(OuterHeaderRemoval {
                outer_header_removal_description: OuterHeaderRemovalDescription::GtpUUdpIpv4,
                gtpu_extension_header_deletion: None,
            }),
            far_id: far_id_ul,
            qer_id: if !qer_ids.is_empty() { Some(qer_ids.clone()) } else { None },
            urr_id: None,
            activation_time: None,
            deactivation_time: None,
        };

        let pdr_dl = CreatePdr {
            pdr_id: pdr_id + 1,
            precedence: 100,
            pdi: Pdi {
                source_interface: SourceInterface::Core,
                local_f_teid: None,
                network_instance: Some("internet".to_string()),
                ue_ip_address: Some(UeIpAddress {
                    ipv4_address: Some(ue_ipv4),
                    ipv6_address: None,
                    ipv6_prefix_length: None,
                    is_destination: true,
                    is_source: false,
                }),
                sdf_filter: None,
                application_id: None,
                ethernet_pdu_session_information: None,
                framed_route: None,
                framed_routing: None,
                framed_ipv6_route: None,
            },
            outer_header_removal: None,
            far_id: far_id_dl,
            qer_id: if !qer_ids.is_empty() { Some(qer_ids) } else { None },
            urr_id: None,
            activation_time: None,
            deactivation_time: None,
        };

        let far_ul = CreateFar {
            far_id: far_id_ul,
            apply_action: ApplyAction {
                drop: false,
                forw: true,
                buff: false,
                nocp: false,
                dupl: false,
            },
            forwarding_parameters: Some(ForwardingParameters {
                destination_interface: DestinationInterface::Core,
                network_instance: Some("internet".to_string()),
                redirect_information: None,
                outer_header_creation: None,
                transport_level_marking: None,
                forwarding_policy: None,
                header_enrichment: None,
                traffic_endpoint_id: None,
                proxying: None,
            }),
            duplicating_parameters: None,
            bar_id: None,
        };

        let far_dl = CreateFar {
            far_id: far_id_dl,
            apply_action: ApplyAction {
                drop: false,
                forw: true,
                buff: false,
                nocp: false,
                dupl: false,
            },
            forwarding_parameters: Some(ForwardingParameters {
                destination_interface: DestinationInterface::Access,
                network_instance: Some("internet".to_string()),
                redirect_information: None,
                outer_header_creation: Some(OuterHeaderCreation {
                    outer_header_creation_description: OuterHeaderCreationDescription::GtpUUdpIpv4,
                    teid: Some(seid as u32),
                    ipv4_address: Some(upf_ipv4),
                    ipv6_address: None,
                    port_number: None,
                    ctag: None,
                    stag: None,
                }),
                transport_level_marking: None,
                forwarding_policy: None,
                header_enrichment: None,
                traffic_endpoint_id: None,
                proxying: None,
            }),
            duplicating_parameters: None,
            bar_id: None,
        };

        let create_qer = if !qos_flows.is_empty() {
            Some(qos_flows.iter().map(|qf| Self::create_qer_from_qos_flow(qf)).collect())
        } else {
            None
        };

        let request = PfcpSessionEstablishmentRequest {
            node_id,
            f_seid,
            create_pdr: vec![pdr_ul, pdr_dl],
            create_far: vec![far_ul, far_dl],
            create_qer,
            create_urr: None,
            pdn_type: Some(PdnType::Ipv4),
            user_plane_inactivity_timer: Some(300),
        };

        pfcp_client.send_session_establishment_request(seid, &request).await?;

        info!("Sent PFCP Session Establishment Request for SEID: {}", seid);

        let response = pfcp_client
            .receive_message_with_timeout(std::time::Duration::from_secs(5))
            .await?;

        let establishment_response = PfcpClientInner::decode_session_establishment_response(&response.payload)?;

        match establishment_response.cause {
            PfcpCause::RequestAccepted => {
                info!("PFCP Session established successfully for SEID: {}", seid);
                Ok(establishment_response)
            }
            _ => {
                warn!("PFCP Session establishment failed: {:?}", establishment_response.cause);
                Err(anyhow!("PFCP Session establishment failed: {:?}", establishment_response.cause))
            }
        }
    }

    pub async fn modify_session(
        pfcp_client: &PfcpClient,
        seid: u64,
        ue_ipv4: Option<Ipv4Addr>,
        add_qos_flows: Option<&[QosFlow]>,
        remove_qfis: Option<&[u8]>,
    ) -> Result<PfcpSessionModificationResponse> {
        let mut request = PfcpSessionModificationRequest {
            f_seid: None,
            remove_pdr: None,
            remove_far: None,
            remove_qer: None,
            remove_urr: None,
            create_pdr: None,
            create_far: None,
            create_qer: None,
            create_urr: None,
            update_pdr: None,
            update_far: None,
            update_qer: None,
            update_urr: None,
            query_urr: None,
            pfcp_session_retention_information: None,
            user_plane_inactivity_timer: Some(300),
        };

        if let Some(new_ip) = ue_ipv4 {
            let update_pdr = UpdatePdr {
                pdr_id: 1,
                precedence: None,
                pdi: Some(Pdi {
                    source_interface: SourceInterface::Access,
                    local_f_teid: None,
                    network_instance: Some("internet".to_string()),
                    ue_ip_address: Some(UeIpAddress {
                        ipv4_address: Some(new_ip),
                        ipv6_address: None,
                        ipv6_prefix_length: None,
                        is_destination: false,
                        is_source: true,
                    }),
                    sdf_filter: None,
                    application_id: None,
                    ethernet_pdu_session_information: None,
                    framed_route: None,
                    framed_routing: None,
                    framed_ipv6_route: None,
                }),
                outer_header_removal: None,
                far_id: None,
                qer_id: None,
                urr_id: None,
                activation_time: None,
                deactivation_time: None,
            };
            request.update_pdr = Some(vec![update_pdr]);
        }

        if let Some(qos_flows) = add_qos_flows {
            if !qos_flows.is_empty() {
                request.create_qer = Some(qos_flows.iter().map(|qf| Self::create_qer_from_qos_flow(qf)).collect());
            }
        }

        if let Some(qfis) = remove_qfis {
            if !qfis.is_empty() {
                request.remove_qer = Some(qfis.iter().map(|&qfi| RemoveQer { qer_id: qfi as u32 }).collect());
            }
        }

        pfcp_client.send_session_modification_request(seid, &request).await?;

        info!("Sent PFCP Session Modification Request for SEID: {}", seid);

        let response = pfcp_client
            .receive_message_with_timeout(std::time::Duration::from_secs(5))
            .await?;

        let modification_response = PfcpClientInner::decode_session_modification_response(&response.payload)?;

        match modification_response.cause {
            PfcpCause::RequestAccepted => {
                info!("PFCP Session modified successfully for SEID: {}", seid);
                Ok(modification_response)
            }
            _ => {
                warn!("PFCP Session modification failed: {:?}", modification_response.cause);
                Err(anyhow!("PFCP Session modification failed: {:?}", modification_response.cause))
            }
        }
    }

    pub async fn modify_session_for_handover(
        pfcp_client: &PfcpClient,
        seid: u64,
        new_an_ipv4: Ipv4Addr,
        new_an_teid: &str,
    ) -> Result<PfcpSessionModificationResponse> {
        let teid = u32::from_str_radix(new_an_teid, 16)
            .map_err(|e| anyhow!("Invalid TEID format: {}", e))?;

        let update_far = UpdateFar {
            far_id: 2,
            apply_action: Some(ApplyAction {
                drop: false,
                forw: true,
                buff: false,
                nocp: false,
                dupl: false,
            }),
            update_forwarding_parameters: Some(UpdateForwardingParameters {
                destination_interface: Some(DestinationInterface::Access),
                network_instance: Some("internet".to_string()),
                redirect_information: None,
                outer_header_creation: Some(OuterHeaderCreation {
                    outer_header_creation_description: OuterHeaderCreationDescription::GtpUUdpIpv4,
                    teid: Some(teid),
                    ipv4_address: Some(new_an_ipv4),
                    ipv6_address: None,
                    port_number: None,
                    ctag: None,
                    stag: None,
                }),
                transport_level_marking: None,
                forwarding_policy: None,
                header_enrichment: None,
                traffic_endpoint_id: None,
                proxying: None,
            }),
            update_duplicating_parameters: None,
            bar_id: None,
        };

        let request = PfcpSessionModificationRequest {
            f_seid: None,
            remove_pdr: None,
            remove_far: None,
            remove_qer: None,
            remove_urr: None,
            create_pdr: None,
            create_far: None,
            create_qer: None,
            create_urr: None,
            update_pdr: None,
            update_far: Some(vec![update_far]),
            update_qer: None,
            update_urr: None,
            query_urr: None,
            pfcp_session_retention_information: None,
            user_plane_inactivity_timer: Some(300),
        };

        pfcp_client.send_session_modification_request(seid, &request).await?;

        info!(
            "Sent PFCP Session Modification Request for handover - SEID: {}, New AN: {}, TEID: {}",
            seid, new_an_ipv4, new_an_teid
        );

        let response = pfcp_client
            .receive_message_with_timeout(std::time::Duration::from_secs(5))
            .await?;

        let modification_response = PfcpClientInner::decode_session_modification_response(&response.payload)?;

        match modification_response.cause {
            PfcpCause::RequestAccepted => {
                info!("PFCP Session modified successfully for handover - SEID: {}", seid);
                Ok(modification_response)
            }
            _ => {
                warn!("PFCP Session modification for handover failed: {:?}", modification_response.cause);
                Err(anyhow!("PFCP Session modification for handover failed: {:?}", modification_response.cause))
            }
        }
    }

    pub async fn delete_session(
        pfcp_client: &PfcpClient,
        seid: u64,
    ) -> Result<PfcpSessionDeletionResponse> {
        let request = PfcpSessionDeletionRequest {
            user_plane_inactivity_timer: None,
        };

        pfcp_client.send_session_deletion_request(seid, &request).await?;

        info!("Sent PFCP Session Deletion Request for SEID: {}", seid);

        let response = pfcp_client
            .receive_message_with_timeout(std::time::Duration::from_secs(5))
            .await?;

        let deletion_response = PfcpClientInner::decode_session_deletion_response(&response.payload)?;

        match deletion_response.cause {
            PfcpCause::RequestAccepted => {
                info!("PFCP Session deleted successfully for SEID: {}", seid);
                Ok(deletion_response)
            }
            _ => {
                warn!("PFCP Session deletion failed: {:?}", deletion_response.cause);
                Err(anyhow!("PFCP Session deletion failed: {:?}", deletion_response.cause))
            }
        }
    }

    pub fn generate_seid(sm_context_id: &str, pdu_session_id: u8) -> u64 {
        let hash = sm_context_id.bytes().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });
        (hash & 0x0000_FFFF_FFFF_FF00) | (pdu_session_id as u64)
    }
}
