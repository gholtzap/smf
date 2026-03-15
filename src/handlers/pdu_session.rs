use axum::{
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{bson::doc, Collection};
use futures::TryStreamExt;
use base64::{Engine as _, engine::general_purpose};
use crate::db::AppState;
use crate::models::{Ambr, PduSessionCreateData, PduSessionCreatedData, SmContextReleaseData, SmContextStatusNotification, SmContextStatusInfo, ResourceStatus, PduSessionUpdateData, PduSessionUpdatedData, SmContext, N2SmInfoType, RequestType, UpCnxState, TunnelInfo};
use crate::types::{AppError, N2SmInfo, N2InfoContent, NgapIeType, NasParser, NasMessageType, NasQosRule, NasQosFlowDescription, QosFlowOperationCode, GsmCause, SmContextState, RefToBinaryData, PduAddress, PduSessionType, QosFlow, SscMode, HoState, SmContextRetrieveData, SmContextRetrievedData};
use crate::models::QosFlowItem;
use crate::services::pfcp_session::PfcpSessionManager;
use crate::services::ipam::IpamService;
use crate::services::qos_flow::QosFlowManager;
use crate::services::handover::HandoverService;
use crate::services::qos_flow_mapping::QosFlowMappingService;
use crate::services::ssc_behavior::SscBehaviorService;
use crate::services::ssc_mode2::SscMode2Service;
use crate::services::ssc_mode3::SscMode3Service;
use crate::services::emergency::EmergencyService;
use crate::services::up_security_selection::UpSecuritySelector;
use crate::services::up_security_config::UpSecurityConfigService;
use crate::services::ambr_enforcement::AmbrEnforcementService;
use crate::types::up_security::UeSecurityCapabilities;
use crate::types::ue_context::{SmContextSummary, SmContextListQuery, validate_supi, validate_pdu_session_id};
use std::sync::Arc;

pub async fn create_pdu_session(
    State(state): State<AppState>,
    Json(payload): Json<PduSessionCreateData>,
) -> Result<Response, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    EmergencyService::validate_emergency_request(
        &payload.request_type,
        &payload.dnn,
        payload.unauthenticated_supi,
    )
    .map_err(AppError::ValidationError)?;

    let is_emergency = EmergencyService::is_emergency_request(&payload.request_type);
    if is_emergency {
        tracing::info!(
            "Emergency PDU session request detected for SUPI: {}, DNN: {}, Request Type: {:?}",
            payload.supi,
            payload.dnn,
            payload.request_type
        );
    }

    let slice_config = state
        .slice_selector
        .validate_snssai(&payload.s_nssai)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "S-NSSAI validated for SUPI: {}, Slice: {} (SST: {}, SD: {:?})",
        payload.supi,
        slice_config.slice_name,
        payload.s_nssai.sst,
        payload.s_nssai.sd
    );

    let dnn_config = state
        .dnn_selector
        .validate_dnn(&payload.dnn)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "DNN validated for SUPI: {}, DNN: {}, Description: {}",
        payload.supi,
        dnn_config.dnn,
        dnn_config.description
    );

    let (subscriber_5qi, subscriber_ambr, subscriber_ssc_modes, subscriber_pdu_types) = if let Some(ref udm_client) = state.udm_client {
        let udm_uri = std::env::var("UDM_URI").unwrap_or_default();

        match udm_client.get_sm_data(
            &udm_uri,
            &payload.supi,
            Some(&payload.s_nssai),
            Some(&payload.dnn),
            None,
        ).await {
            Ok(sm_data) => {
                tracing::info!(
                    "Retrieved SM subscription data from UDM for SUPI: {}",
                    payload.supi
                );

                if let Some(ref dnn_configs) = sm_data.dnn_configurations {
                    if let Some(dnn_config) = dnn_configs.get(&payload.dnn as &str) {
                        tracing::info!(
                            "Subscriber authorized for DNN: {} with SSC mode: {:?}",
                            payload.dnn,
                            dnn_config.ssc_modes.default_ssc_mode
                        );

                        let sub_5qi = dnn_config.qos_profile_5g.as_ref().map(|qos| qos.qos_identifier_5);
                        let sub_ambr = dnn_config.session_ambr.clone();
                        let sub_ssc_modes = dnn_config.ssc_modes.allowed_ssc_modes.as_ref().map(|modes| {
                            modes.iter().map(|m| SscMode::from(m.clone())).collect::<Vec<SscMode>>()
                        });

                        let sub_pdu_types = Some(dnn_config.pdu_session_types.clone());

                        (sub_5qi, sub_ambr, sub_ssc_modes, sub_pdu_types)
                    } else {
                        tracing::warn!(
                            "DNN {} not found in subscriber's UDM data for SUPI: {}, using defaults",
                            payload.dnn,
                            payload.supi
                        );
                        (None, None, None, None)
                    }
                } else {
                    tracing::warn!(
                        "No DNN configurations found in UDM data for SUPI: {}, using defaults",
                        payload.supi
                    );
                    (None, None, None, None)
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to retrieve SM data from UDM for SUPI: {}: {}, continuing with defaults",
                    payload.supi,
                    e
                );
                (None, None, None, None)
            }
        }
    } else {
        tracing::debug!("UDM client not available, skipping subscriber validation");
        (None, None, None, None)
    };

    let existing = collection
        .find_one(doc! { "supi": &payload.supi, "pdu_session_id": payload.pdu_session_id as i32 })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let is_existing_request = matches!(
        payload.request_type,
        Some(RequestType::ExistingPduSession) | Some(RequestType::ExistingEmergencyPduSession)
    );

    if let Some(ref existing_ctx) = existing {
        if is_existing_request {
            tracing::info!(
                "ExistingPduSession request for SUPI: {}, PDU Session ID: {} - releasing old session before re-establishment",
                payload.supi,
                payload.pdu_session_id
            );

            if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, existing_ctx.pfcp_session_id) {
                if let Err(e) = PfcpSessionManager::delete_session(pfcp_client, seid).await {
                    tracing::warn!("Failed to delete old PFCP session {}: {}", seid, e);
                }
            }

            IpamService::release_ip(&state.db, &existing_ctx.id).await.ok();

            collection
                .delete_one(doc! { "_id": &existing_ctx.id })
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;
        } else {
            return Err(AppError::ValidationError(format!(
                "PDU Session already exists for SUPI {} with PDU Session ID {}",
                payload.supi, payload.pdu_session_id
            )));
        }
    }

    if matches!(payload.ho_state, Some(HoState::Preparing)) {
        return handle_inter_smf_handover_create(state, payload, collection).await;
    }

    let mut sm_context = SmContext::new(&payload);

    if let Some(ref sub_pdu_types) = subscriber_pdu_types {
        let requested = &sm_context.pdu_session_type;
        let allowed = sub_pdu_types.allowed_session_types.as_ref();

        let is_allowed = match allowed {
            Some(types) => types.iter().any(|t| match (t, requested) {
                (crate::types::udm::PduSessionType::Ipv4, PduSessionType::Ipv4) => true,
                (crate::types::udm::PduSessionType::Ipv6, PduSessionType::Ipv6) => true,
                (crate::types::udm::PduSessionType::Ipv4v6, PduSessionType::Ipv4v6) => true,
                (crate::types::udm::PduSessionType::Ipv4v6, PduSessionType::Ipv4) => true,
                (crate::types::udm::PduSessionType::Ipv4v6, PduSessionType::Ipv6) => true,
                (crate::types::udm::PduSessionType::Unstructured, PduSessionType::Unstructured) => true,
                (crate::types::udm::PduSessionType::Ethernet, PduSessionType::Ethernet) => true,
                _ => false,
            }),
            None => true,
        };

        if !is_allowed {
            let default_type = match sub_pdu_types.default_session_type {
                crate::types::udm::PduSessionType::Ipv4 => PduSessionType::Ipv4,
                crate::types::udm::PduSessionType::Ipv6 => PduSessionType::Ipv6,
                crate::types::udm::PduSessionType::Ipv4v6 => PduSessionType::Ipv4v6,
                crate::types::udm::PduSessionType::Unstructured => PduSessionType::Unstructured,
                crate::types::udm::PduSessionType::Ethernet => PduSessionType::Ethernet,
            };
            tracing::info!(
                "Requested PDU session type {:?} not allowed for SUPI: {}, falling back to default {:?}",
                requested,
                payload.supi,
                default_type
            );
            sm_context.pdu_session_type = default_type;
        }
    }

    let selected_ssc_mode = state.ssc_selector.select_ssc_mode(
        payload.ssc_mode.as_deref(),
        subscriber_ssc_modes.as_deref(),
        None,
    ).map_err(AppError::ValidationError)?;

    sm_context.ssc_mode = selected_ssc_mode;
    tracing::info!(
        "Selected SSC mode: {} for SUPI: {}",
        selected_ssc_mode.as_str(),
        payload.supi
    );

    let ue_capabilities = if let Some(ref n1_sm_msg) = payload.n1_sm_msg {
        tracing::debug!(
            "Parsing N1 SM message for SUPI: {} to extract UE security capabilities",
            payload.supi
        );

        let n1_data = general_purpose::STANDARD.decode(&n1_sm_msg.content_id).unwrap_or_default();

        if !n1_data.is_empty() {
            match NasParser::parse_pdu_session_establishment_request(&n1_data) {
                Ok(nas_request) => {
                    if let Some(caps) = nas_request.ue_security_capabilities {
                        tracing::info!(
                            "Extracted UE security capabilities from N1 message for SUPI: {} - NR Enc: {:?}, NR Int: {:?}",
                            payload.supi,
                            caps.nr_encryption_algorithms,
                            caps.nr_integrity_algorithms
                        );
                        caps
                    } else {
                        tracing::warn!(
                            "N1 message parsed but no UE security capabilities found for SUPI: {}, using defaults",
                            payload.supi
                        );
                        UeSecurityCapabilities::default()
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse N1 SM message for SUPI: {}: {}, using default UE capabilities",
                        payload.supi,
                        e
                    );
                    UeSecurityCapabilities::default()
                }
            }
        } else {
            tracing::warn!(
                "N1 SM message present but empty for SUPI: {}, using default UE capabilities",
                payload.supi
            );
            UeSecurityCapabilities::default()
        }
    } else {
        tracing::debug!(
            "No N1 SM message provided for SUPI: {}, using default UE capabilities",
            payload.supi
        );
        UeSecurityCapabilities::default()
    };
    let network_policy = if sm_context.is_emergency {
        UpSecurityConfigService::get_policy_for_emergency()
    } else {
        UpSecurityConfigService::get_policy_for_slice(
            payload.s_nssai.sst,
            payload.s_nssai.sd.as_deref()
        )
    };

    sm_context.ue_security_capabilities = Some(ue_capabilities.clone());

    match UpSecuritySelector::select_algorithms(&ue_capabilities, &network_policy) {
        Ok(up_security_context) => {
            sm_context.up_security_context = Some(up_security_context.clone());
            tracing::info!(
                "UP security algorithms selected for SUPI: {} - Integrity: {:?} (activated: {}), Ciphering: {:?} (activated: {})",
                payload.supi,
                up_security_context.integrity_protection_algorithm,
                up_security_context.integrity_protection_activated,
                up_security_context.ciphering_algorithm,
                up_security_context.confidentiality_protection_activated
            );
        }
        Err(e) => {
            tracing::warn!(
                "Failed to select UP security algorithms for SUPI: {}: {}, continuing without UP security",
                payload.supi,
                e
            );
        }
    }

    let default_5qi = if sm_context.is_emergency {
        let emergency_5qi = EmergencyService::get_emergency_priority_5qi();
        tracing::info!(
            "Emergency session: applying high-priority 5QI {} for SUPI: {}",
            emergency_5qi,
            payload.supi
        );
        emergency_5qi
    } else {
        subscriber_5qi
            .or(dnn_config.default_5qi)
            .or(slice_config.default_5qi)
            .unwrap_or(9)
    };

    let qos_flow = state
        .slice_qos_policy_service
        .create_qos_flow_with_5qi(&payload.s_nssai, 1, default_5qi);

    sm_context.qos_flows = vec![qos_flow.clone()];
    tracing::debug!(
        "Applied slice-specific QoS flow with 5QI: {}, priority: {}, for DNN: {}, Slice: {}",
        qos_flow.five_qi,
        qos_flow.priority_level,
        dnn_config.dnn,
        slice_config.slice_name
    );

    let ip_pool_name = &dnn_config.ip_pool_name;
    let ip_allocation = IpamService::allocate_ip(
        &state.db,
        ip_pool_name,
        &sm_context.id,
        &payload.supi,
        &sm_context.pdu_session_type,
    )
    .await
    .map_err(|e| AppError::ValidationError(format!("IP allocation failed: {}", e)))?;

    let (ipv4_addr, ipv6_addr) = match sm_context.pdu_session_type {
        PduSessionType::Ipv4 => (Some(ip_allocation.ip_address.clone()), None),
        PduSessionType::Ipv6 => (None, ip_allocation.ipv6_prefix.clone()),
        PduSessionType::Ipv4v6 => (Some(ip_allocation.ip_address.clone()), ip_allocation.ipv6_prefix.clone()),
        _ => (None, None),
    };

    sm_context.pdu_address = Some(PduAddress {
        pdu_session_type: sm_context.pdu_session_type.clone(),
        ipv4_addr: ipv4_addr.clone(),
        ipv6_addr: ipv6_addr.clone(),
        dns_primary: ip_allocation.dns_primary.clone(),
        dns_secondary: ip_allocation.dns_secondary.clone(),
    });

    SscBehaviorService::validate_ip_allocation_for_mode(
        &sm_context.ssc_mode,
        sm_context.pdu_address.as_ref(),
    ).map_err(AppError::ValidationError)?;

    if sm_context.ssc_mode == SscMode::Mode1 {
        tracing::info!(
            "SSC Mode 1 PDU session created: IP address will be preserved during mobility for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
            payload.supi,
            ipv4_addr,
            ipv6_addr
        );
    }

    sm_context.mtu = ip_allocation.mtu.or(dnn_config.mtu);

    sm_context.session_ambr = Some(if let Some(ref sub_ambr) = subscriber_ambr {
        Ambr {
            uplink: sub_ambr.uplink.clone(),
            downlink: sub_ambr.downlink.clone(),
        }
    } else {
        Ambr {
            uplink: dnn_config.default_session_ambr_uplink.clone(),
            downlink: dnn_config.default_session_ambr_downlink.clone(),
        }
    });

    AmbrEnforcementService::log_ambr_enforcement(
        &payload.supi,
        payload.pdu_session_id,
        &sm_context.session_ambr,
        "PDU session creation",
    );

    let ue_ipv4 = if !ip_allocation.ip_address.is_empty() {
        Some(ip_allocation.ip_address.parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid UE IPv4 address: {}", e))
        })?)
    } else {
        None
    };

    if let Some(ref pcf_client) = state.pcf_client {
        let pcf_uri = std::env::var("PCF_URI").unwrap_or_default();

        let notification_uri = format!(
            "http://{}:{}/npcf-callback/v1/sm-policy-notify/{}",
            std::env::var("SMF_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()),
            sm_context.id
        );

        let context_data = crate::types::pcf::SmPolicyContextData {
            supi: payload.supi.clone(),
            pdu_session_id: payload.pdu_session_id,
            dnn: payload.dnn.clone(),
            slice_info: payload.s_nssai.clone(),
            notification_uri,
            ipv4_address: ipv4_addr.clone(),
            ipv6_address_prefix: ipv6_addr.clone(),
            ip_domain: None,
            subs_sess_ambr: None,
            auth_prof_index: None,
            subs_def_qos: None,
            num_of_pack_filter: None,
            online: Some(true),
            offline: Some(false),
            access_type: Some(crate::types::pcf::AccessType::Gpe3gppAccess),
            rat_type: Some(crate::types::pcf::RatType::Nr),
            servingNetwork: None,
            user_location_info: None,
            ue_time_zone: None,
            pei: None,
            ipv4_frame_route_list: None,
            ipv6_frame_route_list: None,
            supp_feat: None,
        };

        match pcf_client.create_sm_policy(&pcf_uri, context_data).await {
            Ok((policy_id, policy_decision)) => {
                sm_context.pcf_policy_id = Some(policy_id.clone());
                tracing::info!(
                    "SM policy created for SUPI: {}, Policy ID: {}",
                    payload.supi,
                    policy_id
                );

                if let Some(ref sess_rules) = policy_decision.sess_rules {
                    tracing::debug!("Received {} session rules from PCF", sess_rules.len());
                }

                if let Some(ref pcc_rules) = policy_decision.pcc_rules {
                    tracing::debug!("Received {} PCC rules from PCF", pcc_rules.len());
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create SM policy for SUPI: {}: {}, continuing without PCF policy",
                    payload.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PCF client not available, skipping SM policy creation");
    }

    if let Some(ref chf_client) = state.chf_client {
        let chf_uri = std::env::var("CHF_URI").unwrap_or_default();

        let nf_identification = crate::types::chf::NfIdentification {
            nf_name: format!("SMF-{}", std::env::var("NF_INSTANCE_ID").unwrap_or_else(|_| "unknown".to_string())),
            nf_ip_v4_address: Some(std::env::var("SMF_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())),
            nf_ip_v6_address: None,
            nf_plmn_id: None,
            nf_fqdn: None,
        };

        let pdu_session_info = crate::types::chf::PduSessionInformation {
            network_slice_instance_id: None,
            pdu_session_id: payload.pdu_session_id,
            pdu_type: match &sm_context.pdu_session_type {
                crate::types::PduSessionType::Ipv4 => crate::types::chf::PduSessionType::Ipv4,
                crate::types::PduSessionType::Ipv6 => crate::types::chf::PduSessionType::Ipv6,
                crate::types::PduSessionType::Ipv4v6 => crate::types::chf::PduSessionType::Ipv4v6,
                crate::types::PduSessionType::Ethernet => crate::types::chf::PduSessionType::Ethernet,
                crate::types::PduSessionType::Unstructured => crate::types::chf::PduSessionType::Unstructured,
            },
            ssc_mode: match sm_context.ssc_mode {
                SscMode::Mode1 => crate::types::chf::SscMode::SscMode1,
                SscMode::Mode2 => crate::types::chf::SscMode::SscMode2,
                SscMode::Mode3 => crate::types::chf::SscMode::SscMode3,
            },
            hplmn_pdu_session_id: None,
            authorized_qos_information: None,
            authorized_session_ambr: None,
            pdu_address: Some(crate::types::chf::PduAddress {
                pdu_ipv4_address: ipv4_addr.clone(),
                pdu_ipv6_address_with_prefix: ipv6_addr.clone(),
                ipv4_dynamic_address_flag: Some(true),
                ipv6_dynamic_prefix_flag: Some(true),
            }),
            serving_cn_plmn_id: None,
            dnn_id: Some(payload.dnn.clone()),
            dnn_selection_mode: Some(crate::types::chf::DnnSelectionMode::Verified),
            charging_characteristics: None,
            charging_characteristics_selection_mode: None,
            start_time: Some(chrono::Utc::now().to_rfc3339()),
            stop_time: None,
            ps_data_off_status: None,
            session_stop_indicator: None,
            pdu_session_pair_id: None,
            dnai_list: None,
            redundant_pdu_session_information: None,
        };

        let pdu_session_charging_info = crate::types::chf::PduSessionChargingInformation {
            charging_id: None,
            home_provided_charging_id: None,
            user_information: None,
            user_location_info: None,
            user_location_time: None,
            pres_reporting_area_info: None,
            ps_data_off_status: None,
            uetimezone: None,
            rat_type: Some(crate::types::chf::RatType::Nr),
            serving_node_id: None,
            serving_network_function_id: None,
            pdu_session_information: pdu_session_info,
            unit_count_inactivity_timer: None,
        };

        let charging_request = crate::types::chf::ChargingDataRequest {
            subscriber_identifier: payload.supi.clone(),
            nf_consumer_identification: nf_identification,
            invocation_time_stamp: chrono::Utc::now().to_rfc3339(),
            invocation_sequence_number: 0,
            one_time_event: Some(false),
            one_time_event_type: None,
            notify_uri: None,
            multipleunit_usage: None,
            triggers: None,
            pdu_session_charging_information: Some(pdu_session_charging_info),
            roaming_qbc_information: None,
            tenant_identifier: None,
        };

        match chf_client.create_charging_session(&chf_uri, charging_request).await {
            Ok((charging_ref, _charging_response)) => {
                sm_context.chf_charging_ref = Some(charging_ref.clone());
                tracing::info!(
                    "Charging session created for SUPI: {}, Charging Ref: {}",
                    payload.supi,
                    charging_ref
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create charging session for SUPI: {}: {}, continuing without charging",
                    payload.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("CHF client not available, skipping charging session creation");
    }

    let selected_upf_result = state.upf_selection_service.select_upf(&crate::types::UpfSelectionCriteria {
        ue_location: sm_context.ue_location.clone(),
        s_nssai: sm_context.s_nssai.clone(),
        dnn: sm_context.dnn.clone(),
        current_upf_address: None,
    }).await;

    match selected_upf_result {
        Ok(selection_result) => {
            sm_context.upf_address = Some(selection_result.selected_upf.address.clone());
            tracing::info!(
                "Selected UPF {} for PDU session (SUPI: {}, PDU Session ID: {}, score: {})",
                selection_result.selected_upf.address,
                payload.supi,
                payload.pdu_session_id,
                selection_result.score
            );
        }
        Err(e) => {
            tracing::warn!(
                "UPF selection failed for SUPI: {}: {}, falling back to default UPF",
                payload.supi,
                e
            );
            if let Some(ref pfcp_client) = state.pfcp_client {
                sm_context.upf_address = Some(pfcp_client.upf_address().to_string());
            }
        }
    }

    let mut upf_teid: Option<u32> = None;
    let mut upf_addr: Option<std::net::Ipv4Addr> = None;

    if let Some(ref pfcp_client) = state.pfcp_client {
        let seid = PfcpSessionManager::generate_seid(&sm_context.id, payload.pdu_session_id);

        let upf_ipv4 = pfcp_client.upf_address().ip().to_string().parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid UPF IPv4 address: {}", e))
        })?;

        if let Some(ue_ipv4_addr) = ue_ipv4 {
            match PfcpSessionManager::establish_session(
                pfcp_client,
                seid,
                ue_ipv4_addr,
                upf_ipv4,
                &sm_context.qos_flows,
                sm_context.up_security_context.as_ref(),
            ).await {
            Ok(pfcp_response) => {
                sm_context.pfcp_session_id = Some(seid);
                sm_context.state = crate::types::SmContextState::Active;
                tracing::info!(
                    "PFCP Session established for SUPI: {}, SEID: {}, State: Active",
                    payload.supi,
                    seid
                );

                if let Some(ref created_pdrs) = pfcp_response.created_pdr {
                    for created_pdr in created_pdrs {
                        if let Some(ref f_teid) = created_pdr.local_f_teid {
                            upf_teid = Some(f_teid.teid);
                            upf_addr = f_teid.ipv4_address;
                            tracing::info!(
                                "Extracted UPF F-TEID from Created PDR: TEID={}, IP={:?}",
                                f_teid.teid,
                                f_teid.ipv4_address
                            );
                            break;
                        }
                    }
                }

                if upf_teid.is_none() {
                    upf_teid = Some(seid as u32);
                    upf_addr = Some(upf_ipv4);
                    tracing::info!(
                        "UPF did not return Created PDR, using SEID as TEID: TEID={}, IP={}",
                        seid as u32,
                        upf_ipv4
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to establish PFCP session for SUPI: {}: {}, State remains: ActivePending",
                    payload.supi,
                    e
                );
            }
        }
        } else {
            sm_context.state = crate::types::SmContextState::Active;
            tracing::debug!("IPv6-only PDU session, PFCP IPv6 support pending, State: Active");
        }
    } else {
        sm_context.state = crate::types::SmContextState::Active;
        tracing::debug!("PFCP client not available, skipping PFCP session establishment, State: Active");
    }

    if let Some(teid) = upf_teid {
        sm_context.upf_teid = Some(teid);
    }
    if let Some(addr) = upf_addr {
        sm_context.upf_tunnel_ipv4 = Some(addr.to_string());
    }

    if let Err(e) = collection.insert_one(&sm_context).await {
        tracing::error!("DB insert failed for SUPI: {}, cleaning up allocated resources", payload.supi);
        IpamService::release_ip(&state.db, &sm_context.id).await.ok();
        if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
            PfcpSessionManager::delete_session(pfcp_client, seid).await.ok();
        }
        return Err(AppError::DatabaseError(e.to_string()));
    }

    let pdu_session_type_value = match sm_context.pdu_session_type {
        PduSessionType::Ipv4 => 1,
        PduSessionType::Ipv6 => 2,
        PduSessionType::Ipv4v6 => 3,
        _ => 1,
    };

    let ssc_mode_value = match sm_context.ssc_mode {
        SscMode::Mode1 => 1,
        SscMode::Mode2 => 2,
        SscMode::Mode3 => 3,
    };

    let (integrity_required, confidentiality_required) = sm_context.up_security_context
        .as_ref()
        .map(|ctx| (ctx.integrity_protection_activated, ctx.confidentiality_protection_activated))
        .unwrap_or((false, false));

    let n1_ipv4 = sm_context.pdu_address.as_ref()
        .and_then(|addr| addr.ipv4_addr.as_deref());
    let n1_ipv6 = sm_context.pdu_address.as_ref()
        .and_then(|addr| addr.ipv6_addr.as_deref());

    let ambr_dl_kbps = sm_context.session_ambr.as_ref()
        .and_then(|ambr| crate::services::ambr_enforcement::AmbrEnforcementService::parse_ambr_bitrate(&ambr.downlink).ok())
        .map(|bps| bps / 1000)
        .unwrap_or(100_000);
    let ambr_ul_kbps = sm_context.session_ambr.as_ref()
        .and_then(|ambr| crate::services::ambr_enforcement::AmbrEnforcementService::parse_ambr_bitrate(&ambr.uplink).ok())
        .map(|bps| bps / 1000)
        .unwrap_or(50_000);

    let default_qfi = sm_context.qos_flows.first().map(|f| f.qfi).unwrap_or(1);

    let nas_accept_msg = NasParser::build_pdu_session_establishment_accept(
        payload.pdu_session_id,
        1,
        pdu_session_type_value,
        ssc_mode_value,
        integrity_required,
        confidentiality_required,
        n1_ipv4,
        n1_ipv6,
        ambr_dl_kbps,
        ambr_ul_kbps,
        default_qfi,
    );

    tracing::info!(
        "N1 SM message hex ({} bytes): {}",
        nas_accept_msg.len(),
        nas_accept_msg.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    let encoded = general_purpose::STANDARD.encode(&nas_accept_msg);

    let n1_sm_info_to_ue = Some(crate::types::RefToBinaryData {
        content_id: encoded.clone(),
    });

    let n1_sm_msg_simple = n1_sm_info_to_ue.as_ref().map(|info| info.content_id.clone());

    let (upf_tunnel_info_data, qos_flow_list_data, session_ambr_dl_data, session_ambr_ul_data) =
        if let (Some(teid), Some(addr)) = (upf_teid, upf_addr) {
            let session_ambr_dl = sm_context.session_ambr.as_ref()
                .and_then(|ambr| ambr.downlink.parse::<u64>().ok())
                .unwrap_or(100_000_000);

            let session_ambr_ul = sm_context.session_ambr.as_ref()
                .and_then(|ambr| ambr.uplink.parse::<u64>().ok())
                .unwrap_or(50_000_000);

            let qos_flows: Vec<crate::models::QosFlowInfo> = sm_context.qos_flows.iter()
                .map(|flow| crate::models::QosFlowInfo { qfi: flow.qfi })
                .collect();

            tracing::info!(
                "Providing structured session data for SUPI: {}, TEID: {}, UPF IP: {}, QoS Flows: {}, AMBR DL/UL: {}/{}",
                payload.supi,
                teid,
                addr,
                qos_flows.len(),
                session_ambr_dl,
                session_ambr_ul
            );

            (
                Some(crate::models::UpfTunnelInfo {
                    teid,
                    ipv4_address: addr.to_string(),
                }),
                Some(qos_flows),
                Some(session_ambr_dl),
                Some(session_ambr_ul),
            )
        } else {
            tracing::warn!("UPF F-TEID not available, structured session data will be None");
            (None, None, None, None)
        };

    let response = PduSessionCreatedData {
        pdu_session_type: sm_context.pdu_session_type.clone(),
        ssc_mode: sm_context.ssc_mode.as_str().to_string(),
        h_smf_uri: None,
        smf_uri: Some(format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context.id)),
        pdu_session_id: payload.pdu_session_id,
        s_nssai: payload.s_nssai.clone(),
        enable_pause_charging: Some(false),
        ue_ipv4_address: ipv4_addr,
        ue_ipv6_prefix: ipv6_addr,
        dns_primary: ip_allocation.dns_primary.clone(),
        dns_secondary: ip_allocation.dns_secondary.clone(),
        mtu: sm_context.mtu,
        n1_sm_info_to_ue,
        n1_sm_msg: n1_sm_msg_simple,
        eps_pdn_cnx_info: None,
        supported_features: None,
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        dnai_list: None,
        n2_sm_info: None,
        n2_sm_info_type: Some(crate::models::N2SmInfoType::PduResSetupReq),
        ho_state: None,
        sm_context_ref: sm_context.id.clone(),
        upf_tunnel_info: upf_tunnel_info_data,
        qos_flow_list: qos_flow_list_data,
        session_ambr_downlink: session_ambr_dl_data,
        session_ambr_uplink: session_ambr_ul_data,
    };

    tracing::info!(
        "Created PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}, DNN: {}, Slice: {} (SST: {}, SD: {:?})",
        payload.supi,
        payload.pdu_session_id,
        sm_context.id,
        dnn_config.dnn,
        slice_config.slice_name,
        payload.s_nssai.sst,
        payload.s_nssai.sd
    );

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::UeIpChange,
        &payload.supi,
        payload.pdu_session_id,
        Some(payload.dnn.clone()),
        Some(payload.s_nssai.clone()),
        Some(ip_allocation.ip_address.clone()),
        None,
        Some(sm_context.id.clone()),
        None,
    ).await;

    let location = format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context.id);
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(response),
    ).into_response())
}

pub async fn retrieve_sm_context(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    payload: Option<Json<SmContextRetrieveData>>,
) -> Result<Json<SmContextRetrievedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    tracing::info!(
        "RetrieveSMContext for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context.id
    );

    let sm_context_type = payload
        .as_ref()
        .and_then(|p| p.sm_context_type.as_ref());

    if matches!(sm_context_type, Some(crate::types::SmContextType::SmContext)) {
        tracing::info!(
            "Returning full SM context for inter-SMF transfer - SUPI: {}, PSI: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        return Ok(Json(SmContextRetrievedData {
            ue_eps_pdn_connection: None,
            sm_context: Some(sm_context),
        }));
    }

    let eps_pdn_cnx = build_eps_pdn_cnx_container(&sm_context);

    Ok(Json(SmContextRetrievedData {
        ue_eps_pdn_connection: Some(eps_pdn_cnx),
        sm_context: None,
    }))
}

fn build_eps_pdn_cnx_container(ctx: &SmContext) -> String {
    let container = serde_json::json!({
        "pduSessionId": ctx.pdu_session_id,
        "dnn": ctx.dnn,
        "sNssai": ctx.s_nssai,
        "pduSessionType": ctx.pdu_session_type,
        "sscMode": ctx.ssc_mode,
        "sessionAmbr": ctx.session_ambr,
        "qosFlows": ctx.qos_flows.iter().map(|f| {
            serde_json::json!({
                "qfi": f.qfi,
                "fiveQi": f.five_qi,
                "priorityLevel": f.priority_level,
            })
        }).collect::<Vec<_>>(),
        "pduAddress": ctx.pdu_address,
    });
    general_purpose::STANDARD.encode(container.to_string().as_bytes())
}

async fn handle_inter_smf_handover_create(
    state: AppState,
    payload: PduSessionCreateData,
    collection: Collection<SmContext>,
) -> Result<Response, AppError> {
    let source_smf_uri = payload.smf_uri.as_ref()
        .ok_or_else(|| AppError::ValidationError(
            "smfUri (source SMF URI) required for inter-SMF handover".to_string()
        ))?;

    let source_ctx_ref = payload.sm_context_ref.as_ref()
        .ok_or_else(|| AppError::ValidationError(
            "smContextRef (source SM context reference) required for inter-SMF handover".to_string()
        ))?;

    tracing::info!(
        "Inter-SMF handover create - SUPI: {}, PSI: {}, Source SMF: {}, Source Context: {}",
        payload.supi,
        payload.pdu_session_id,
        source_smf_uri,
        source_ctx_ref
    );

    let retrieve_url = format!(
        "{}/nsmf-pdusession/v1/sm-contexts/{}/retrieve",
        source_smf_uri.trim_end_matches('/'),
        source_ctx_ref
    );

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::ValidationError(format!("Failed to create HTTP client: {}", e)))?;

    let retrieve_body = serde_json::json!({
        "smContextType": "SM_CONTEXT"
    });

    let retrieve_response = http_client
        .post(&retrieve_url)
        .json(&retrieve_body)
        .send()
        .await
        .map_err(|e| AppError::ValidationError(format!(
            "Failed to retrieve SM context from source SMF {}: {}", source_smf_uri, e
        )))?;

    if !retrieve_response.status().is_success() {
        return Err(AppError::ValidationError(format!(
            "Source SMF returned {} when retrieving SM context {}",
            retrieve_response.status(),
            source_ctx_ref
        )));
    }

    let retrieved: crate::types::SmContextRetrievedData = retrieve_response
        .json()
        .await
        .map_err(|e| AppError::ValidationError(format!(
            "Failed to parse retrieved SM context: {}", e
        )))?;

    let source_ctx = retrieved.sm_context
        .ok_or_else(|| AppError::ValidationError(
            "Source SMF did not return SM context in retrieve response".to_string()
        ))?;

    tracing::info!(
        "Retrieved SM context from source SMF - SUPI: {}, PSI: {}, DNN: {}, State: {:?}",
        source_ctx.supi,
        source_ctx.pdu_session_id,
        source_ctx.dnn,
        source_ctx.state
    );

    let new_id = uuid::Uuid::new_v4().to_string();
    let mut sm_context = SmContext {
        id: new_id.clone(),
        supi: source_ctx.supi,
        pdu_session_id: source_ctx.pdu_session_id,
        dnn: source_ctx.dnn,
        s_nssai: source_ctx.s_nssai,
        pdu_session_type: source_ctx.pdu_session_type.clone(),
        ssc_mode: source_ctx.ssc_mode,
        state: SmContextState::ActivePending,
        pdu_address: source_ctx.pdu_address.clone(),
        pfcp_session_id: None,
        pcf_policy_id: source_ctx.pcf_policy_id,
        chf_charging_ref: source_ctx.chf_charging_ref,
        qos_flows: source_ctx.qos_flows,
        packet_filters: source_ctx.packet_filters,
        qos_rules: source_ctx.qos_rules,
        mtu: source_ctx.mtu,
        an_tunnel_info: None,
        source_an_tunnel_info: source_ctx.an_tunnel_info,
        ue_location: payload.ue_location.clone().or(source_ctx.ue_location),
        handover_state: Some(HoState::Preparing),
        is_emergency: source_ctx.is_emergency,
        request_type: payload.request_type.clone(),
        up_security_context: source_ctx.up_security_context.clone(),
        ue_security_capabilities: source_ctx.ue_security_capabilities,
        session_ambr: source_ctx.session_ambr.clone(),
        upf_address: None,
        upf_teid: None,
        upf_tunnel_ipv4: None,
        serving_nf_id: payload.serving_nf_id.clone(),
        sm_context_status_uri: payload.sm_context_status_uri.clone(),
        created_at: source_ctx.created_at,
        updated_at: chrono::Utc::now(),
    };

    let mut upf_teid: Option<u32> = None;
    let mut upf_addr: Option<std::net::Ipv4Addr> = None;

    if let Some(ref pfcp_client) = state.pfcp_client {
        let seid = PfcpSessionManager::generate_seid(&sm_context.id, sm_context.pdu_session_id);
        let upf_ipv4: std::net::Ipv4Addr = pfcp_client.upf_address().ip().to_string().parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid UPF IPv4 address: {}", e))
        })?;

        sm_context.upf_address = Some(upf_ipv4.to_string());

        let ue_ipv4 = sm_context.pdu_address.as_ref()
            .and_then(|addr| addr.ipv4_addr.as_ref())
            .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok());

        if let Some(ue_ipv4_addr) = ue_ipv4 {
            match PfcpSessionManager::establish_session(
                pfcp_client,
                seid,
                ue_ipv4_addr,
                upf_ipv4,
                &sm_context.qos_flows,
                sm_context.up_security_context.as_ref(),
            ).await {
                Ok(pfcp_response) => {
                    sm_context.pfcp_session_id = Some(seid);
                    sm_context.state = SmContextState::Active;
                    tracing::info!(
                        "PFCP session established for inter-SMF HO - SUPI: {}, SEID: {}",
                        sm_context.supi,
                        seid
                    );

                    if let Some(ref created_pdrs) = pfcp_response.created_pdr {
                        for created_pdr in created_pdrs {
                            if let Some(ref f_teid) = created_pdr.local_f_teid {
                                upf_teid = Some(f_teid.teid);
                                upf_addr = f_teid.ipv4_address;
                                break;
                            }
                        }
                    }

                    if upf_teid.is_none() {
                        upf_teid = Some(seid as u32);
                        upf_addr = Some(upf_ipv4);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "PFCP session failed for inter-SMF HO - SUPI: {}: {}",
                        sm_context.supi,
                        e
                    );
                    return Err(AppError::ValidationError(format!(
                        "Failed to establish PFCP session at target UPF: {}", e
                    )));
                }
            }
        }
    }

    if let Some(teid) = upf_teid {
        sm_context.upf_teid = Some(teid);
    }
    if let Some(addr) = upf_addr {
        sm_context.upf_tunnel_ipv4 = Some(addr.to_string());
    }

    if let Err(e) = collection.insert_one(&sm_context).await {
        if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
            PfcpSessionManager::delete_session(pfcp_client, seid).await.ok();
        }
        return Err(AppError::DatabaseError(e.to_string()));
    }

    let cn_tunnel_info = match (upf_teid, upf_addr) {
        (Some(teid), Some(addr)) => Some(TunnelInfo {
            ipv4_addr: Some(addr.to_string()),
            ipv6_addr: None,
            gtp_teid: format!("{:08x}", teid),
        }),
        _ => None,
    };

    let upf_tunnel_info_data = match (upf_teid, upf_addr) {
        (Some(teid), Some(addr)) => Some(crate::models::UpfTunnelInfo {
            teid,
            ipv4_address: addr.to_string(),
        }),
        _ => None,
    };

    let qos_flow_list_data: Option<Vec<crate::models::QosFlowInfo>> = Some(
        sm_context.qos_flows.iter()
            .map(|flow| crate::models::QosFlowInfo { qfi: flow.qfi })
            .collect()
    );

    let response = PduSessionCreatedData {
        pdu_session_type: sm_context.pdu_session_type.clone(),
        ssc_mode: sm_context.ssc_mode.as_str().to_string(),
        h_smf_uri: None,
        smf_uri: Some(format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context.id)),
        pdu_session_id: sm_context.pdu_session_id,
        s_nssai: sm_context.s_nssai.clone(),
        enable_pause_charging: Some(false),
        ue_ipv4_address: sm_context.pdu_address.as_ref().and_then(|a| a.ipv4_addr.clone()),
        ue_ipv6_prefix: sm_context.pdu_address.as_ref().and_then(|a| a.ipv6_addr.clone()),
        dns_primary: sm_context.pdu_address.as_ref().and_then(|a| a.dns_primary.clone()),
        dns_secondary: sm_context.pdu_address.as_ref().and_then(|a| a.dns_secondary.clone()),
        mtu: sm_context.mtu,
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        eps_pdn_cnx_info: None,
        supported_features: None,
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info,
        additional_cn_tunnel_info: None,
        dnai_list: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        ho_state: Some(HoState::Preparing),
        sm_context_ref: sm_context.id.clone(),
        upf_tunnel_info: upf_tunnel_info_data,
        qos_flow_list: qos_flow_list_data,
        session_ambr_downlink: sm_context.session_ambr.as_ref()
            .and_then(|ambr| ambr.downlink.parse::<u64>().ok()),
        session_ambr_uplink: sm_context.session_ambr.as_ref()
            .and_then(|ambr| ambr.uplink.parse::<u64>().ok()),
    };

    tracing::info!(
        "Inter-SMF handover context created - SUPI: {}, PSI: {}, SM Context: {}, hoState: PREPARING",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context.id
    );

    let location = format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context.id);
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(response),
    ).into_response())
}

pub async fn admin_retrieve_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
) -> Result<Json<SmContext>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    tracing::info!(
        "Admin retrieved PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context.id
    );

    Ok(Json(sm_context))
}

async fn handle_n2_setup_response(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    payload: PduSessionUpdateData,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let n2_sm_info = payload.n2_sm_info.as_ref()
        .ok_or_else(|| AppError::ValidationError("N2 SM Info required for PDU Resource Setup Response".to_string()))?;

    let decoded_bytes = general_purpose::STANDARD
        .decode(&n2_sm_info.n2_info_content.ngap_data)
        .map_err(|e| AppError::ValidationError(format!("Failed to decode base64 NGAP data: {}", e)))?;

    let parser = crate::parsers::ngap::NgapParser::new();
    let response_transfer = parser.extract_pdu_session_resource_setup_response_transfer(&decoded_bytes)
        .map_err(|e| AppError::ValidationError(format!("Failed to decode PDU Session Resource Setup Response Transfer: {}", e)))?;

    let gtp_tunnel = &response_transfer.dl_qos_flow_per_tnl_information.up_transport_layer_information;
    let ipv4_addr = gtp_tunnel.get_ip_address();
    let teid = gtp_tunnel.get_teid()
        .ok_or_else(|| AppError::ValidationError("Failed to extract GTP TEID".to_string()))?;
    let teid_hex = format!("{:08x}", teid);

    let an_tunnel_info = crate::models::TunnelInfo {
        ipv4_addr: ipv4_addr.clone(),
        ipv6_addr: None,
        gtp_teid: teid_hex.clone(),
    };

    tracing::info!(
        "N2 Setup Response - extracted gNB tunnel: TEID={}, IP={:?} for SUPI: {}, PDU Session ID: {}",
        teid_hex,
        ipv4_addr,
        sm_context.supi,
        sm_context.pdu_session_id
    );

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let an_ipv4_str = ipv4_addr.as_ref()
            .ok_or_else(|| AppError::ValidationError("gNB IPv4 address required".to_string()))?;
        let an_ipv4 = an_ipv4_str.parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid gNB IPv4 address: {}", e))
        })?;

        PfcpSessionManager::modify_session_for_handover(
            pfcp_client,
            seid,
            an_ipv4,
            &teid_hex,
            sm_context.up_security_context.as_ref(),
            false,
        ).await.map_err(|e| {
            AppError::ValidationError(format!("Failed to activate DL FAR: {}", e))
        })?;

        tracing::info!(
            "DL FAR activated for SUPI: {}, SEID: {}, gNB: {}:{}",
            sm_context.supi,
            seid,
            an_ipv4,
            teid_hex
        );
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "an_tunnel_info": mongodb::bson::to_bson(&an_tunnel_info)
                        .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::Active)
                        .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: None,
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

async fn handle_path_switch(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    payload: PduSessionUpdateData,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    HandoverService::validate_handover_state(&sm_context.state)
        .map_err(AppError::ValidationError)?;

    if let Some(ref current_upf_address) = sm_context.upf_address {
        let relocation_decision = state.upf_selection_service.evaluate_upf_relocation(
            current_upf_address,
            payload.ue_location.clone(),
        ).await;

        if let Ok(decision) = relocation_decision {
            if decision.should_relocate {
                tracing::info!(
                    "UPF relocation required during path switch for SUPI: {}, Reason: {:?}, Target UPF: {:?}",
                    sm_context.supi,
                    decision.reason,
                    decision.target_upf_address
                );

                if let Some(ref _target_upf) = decision.target_upf_address {
                    tracing::info!(
                        "UPF relocation target identified for SUPI: {}, but inter-SMF handover via N16 not yet implemented for path switch",
                        sm_context.supi
                    );
                }
            }
        }
    }

    if sm_context.ssc_mode == SscMode::Mode1 {
        tracing::info!(
            "SSC Mode 1 path switch: IP address will be preserved for SUPI: {}",
            sm_context.supi
        );
    } else if sm_context.ssc_mode == SscMode::Mode2 {
        tracing::info!(
            "SSC Mode 2 path switch: Will release and re-establish session for SUPI: {}",
            sm_context.supi
        );
    }

    AmbrEnforcementService::validate_ambr_preservation(
        &sm_context.session_ambr,
        &payload.session_ambr,
    ).map_err(AppError::ValidationError)?;

    let effective_ambr = AmbrEnforcementService::get_effective_ambr(
        &sm_context.session_ambr,
        &payload.session_ambr,
    );

    AmbrEnforcementService::log_ambr_enforcement(
        &sm_context.supi,
        sm_context.pdu_session_id,
        &effective_ambr,
        "path switch (Xn-based handover)",
    );

    tracing::info!(
        "Path switch request received for SUPI: {}, PDU Session ID: {}, SM Context: {}, SSC Mode: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref,
        sm_context.ssc_mode.as_str()
    );

    let an_tunnel_info = if let Some(ref n2_sm_info) = payload.n2_sm_info {
        HandoverService::extract_an_tunnel_info(&n2_sm_info.n2_info_content.ngap_data)
            .map_err(AppError::ValidationError)?
    } else {
        return Err(AppError::ValidationError(
            "N2 SM Info required for path switch".to_string()
        ));
    };

    tracing::info!(
        "Extracted AN tunnel info - GTP TEID: {}, IPv4: {:?}",
        an_tunnel_info.gtp_teid,
        an_tunnel_info.ipv4_addr
    );

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::ModificationPending)
                        .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let new_state = crate::types::SmContextState::Active;
    let mut cn_tunnel_info = None;

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let upf_ipv4 = pfcp_client.upf_address().ip().to_string();

        let an_ipv4_str = an_tunnel_info.ipv4_addr.as_ref()
            .ok_or_else(|| AppError::ValidationError("AN IPv4 address required".to_string()))?;

        let an_ipv4 = an_ipv4_str.parse().map_err(|e| {
            AppError::ValidationError(format!("Invalid AN IPv4 address: {}", e))
        })?;

        match PfcpSessionManager::modify_session_for_handover(
            pfcp_client,
            seid,
            an_ipv4,
            &an_tunnel_info.gtp_teid,
            sm_context.up_security_context.as_ref(),
            true,
        ).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP Session modified for handover - SUPI: {}, SEID: {}, New AN: {}",
                    sm_context.supi,
                    seid,
                    an_ipv4
                );
                cn_tunnel_info = Some(HandoverService::generate_cn_tunnel_info(
                    &upf_ipv4,
                    &format!("{:08x}", seid & 0xFFFFFFFF),
                ));
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to modify PFCP session for handover - SUPI: {}: {}",
                    sm_context.supi,
                    e
                );
                return Err(AppError::ValidationError(format!(
                    "PFCP session modification failed: {}",
                    e
                )));
            }
        }
    } else {
        return Err(AppError::ValidationError(
            "PFCP client or session ID not available".to_string()
        ));
    }

    let mut update_doc = doc! {
        "$set": {
            "state": mongodb::bson::to_bson(&new_state)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
            "an_tunnel_info": mongodb::bson::to_bson(&an_tunnel_info)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
            "updated_at": mongodb::bson::DateTime::now()
        }
    };

    if sm_context.ssc_mode == SscMode::Mode2 {
        tracing::info!(
            "SSC Mode 2 path switch: Releasing old session and establishing new session for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        let dnn_config = state.dnn_selector.validate_dnn(&sm_context.dnn)
            .map_err(AppError::ValidationError)?;

        let mut mutable_context = sm_context.clone();
        let new_pdu_address = SscMode2Service::handle_mobility_event(
            &mut mutable_context,
            &state.db,
            state.pfcp_client.as_ref(),
            &dnn_config.ip_pool_name,
        ).await.map_err(AppError::ValidationError)?;

        tracing::info!(
            "SSC Mode 2 path switch completed: New address allocated for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
            sm_context.supi,
            new_pdu_address.ipv4_addr,
            new_pdu_address.ipv6_addr
        );

        update_doc.get_document_mut("$set")
            .map_err(|e| AppError::DatabaseError(format!("Failed to access $set document: {}", e)))?
            .insert(
                "pdu_address",
                mongodb::bson::to_bson(&new_pdu_address)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?
            );
    } else if sm_context.ssc_mode == SscMode::Mode3 {
        tracing::info!(
            "SSC Mode 3 path switch: Make-before-break for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        let dnn_config = state.dnn_selector.validate_dnn(&sm_context.dnn)
            .map_err(AppError::ValidationError)?;

        let mut mutable_context = sm_context.clone();
        let (new_pdu_address, _old_address) = SscMode3Service::handle_mobility_event(
            &mut mutable_context,
            &state.db,
            state.pfcp_client.as_ref(),
            &dnn_config.ip_pool_name,
        ).await.map_err(AppError::ValidationError)?;

        tracing::info!(
            "SSC Mode 3 path switch completed: New address allocated (make-before-break) for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
            sm_context.supi,
            new_pdu_address.ipv4_addr,
            new_pdu_address.ipv6_addr
        );

        update_doc.get_document_mut("$set")
            .map_err(|e| AppError::DatabaseError(format!("Failed to access $set document: {}", e)))?
            .insert(
                "pdu_address",
                mongodb::bson::to_bson(&new_pdu_address)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?
            );
    }

    if let Some(ref ue_location) = payload.ue_location {
        update_doc.get_document_mut("$set")
            .map_err(|e| AppError::DatabaseError(format!("Failed to access $set document: {}", e)))?
            .insert(
                "ue_location",
                mongodb::bson::to_bson(&ue_location)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?
            );
        tracing::info!(
            "Updated UE location for SUPI: {} during handover",
            sm_context.supi
        );
    }

    if let Some(ref ambr) = effective_ambr {
        update_doc.get_document_mut("$set")
            .map_err(|e| AppError::DatabaseError(format!("Failed to access $set document: {}", e)))?
            .insert(
                "session_ambr",
                mongodb::bson::to_bson(&ambr)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?
            );
        tracing::info!(
            "Updated session AMBR for SUPI: {} during path switch: UL={}, DL={}",
            sm_context.supi,
            ambr.uplink,
            ambr.downlink
        );
    }

    collection
        .update_one(doc! { "_id": &sm_context_ref }, update_doc)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let n2_ngap_bytes = if let Some(ref info) = cn_tunnel_info {
        let upf_addr: std::net::Ipv4Addr = info.ipv4_addr.as_deref().unwrap_or("0.0.0.0")
            .parse()
            .map_err(|e: std::net::AddrParseError| AppError::ValidationError(e.to_string()))?;
        let teid = u32::from_str_radix(&info.gtp_teid, 16)
            .map_err(|e| AppError::ValidationError(format!("Invalid TEID hex: {}", e)))?;
        crate::parsers::ngap_encoder::encode_path_switch_request_acknowledge_transfer(
            Some(upf_addr), Some(teid),
        )
    } else {
        crate::parsers::ngap_encoder::encode_path_switch_request_acknowledge_transfer(None, None)
    }.map_err(|e| AppError::ValidationError(format!("NGAP encode failed: {}", e)))?;

    let n2_ngap_data = general_purpose::STANDARD.encode(&n2_ngap_bytes);

    let response = PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PathSwitchReqAck,
                ngap_data: n2_ngap_data,
            },
        }),
        n2_sm_info_type: Some(N2SmInfoType::PathSwitchReqAck),
        eps_bearer_info: None,
        supported_features: None,
        ho_state: None,
        session_ambr: effective_ambr,
        cn_tunnel_info,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    };

    tracing::info!(
        "Path switch completed for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(Json(response))
}

async fn handle_up_cnx_state_change(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    up_cnx_state: &UpCnxState,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    match up_cnx_state {
        UpCnxState::Deactivated => {
            tracing::info!(
                "upCnxState DEACTIVATED for SUPI: {}, PDU Session ID: {} - UE entering idle mode",
                sm_context.supi,
                sm_context.pdu_session_id
            );

            if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
                match PfcpSessionManager::deactivate_downlink(pfcp_client, seid).await {
                    Ok(_) => {
                        tracing::info!(
                            "DL FAR set to BUFF for SUPI: {}, SEID: {}",
                            sm_context.supi,
                            seid
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to deactivate DL for SUPI: {}, SEID: {}: {}",
                            sm_context.supi,
                            seid,
                            e
                        );
                        return Err(AppError::ValidationError(format!(
                            "PFCP DL deactivation failed: {}", e
                        )));
                    }
                }
            }

            collection
                .update_one(
                    doc! { "_id": &sm_context_ref },
                    doc! {
                        "$set": {
                            "an_tunnel_info": mongodb::bson::Bson::Null,
                            "updated_at": mongodb::bson::DateTime::now()
                        }
                    }
                )
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;

            Ok(Json(PduSessionUpdatedData {
                n1_sm_info_to_ue: None,
                n1_sm_msg: None,
                n2_sm_info: None,
                n2_sm_info_type: None,
                eps_bearer_info: None,
                supported_features: None,
                ho_state: None,
                session_ambr: sm_context.session_ambr.clone(),
                cn_tunnel_info: None,
                additional_cn_tunnel_info: None,
                qos_flows_add_mod_list: None,
                qos_flows_rel_list: None,
                up_cnx_state: Some(UpCnxState::Deactivated),
                data_forwarding: None,
            }))
        }

        UpCnxState::Activating => {
            if !matches!(sm_context.state, crate::types::SmContextState::Active | crate::types::SmContextState::ModificationPending) {
                tracing::warn!(
                    "upCnxState ACTIVATING rejected - session not in operational state for SUPI: {}, state: {:?}",
                    sm_context.supi,
                    sm_context.state
                );
                return Err(AppError::ValidationError(format!(
                    "Session not in operational state: {:?}", sm_context.state
                )));
            }

            tracing::info!(
                "upCnxState ACTIVATING for SUPI: {}, PDU Session ID: {} - Service Request / re-establishing user plane",
                sm_context.supi,
                sm_context.pdu_session_id
            );

            let upf_teid = sm_context.upf_teid
                .or(sm_context.pfcp_session_id.map(|seid| seid as u32))
                .ok_or_else(|| AppError::ValidationError(
                    "No UPF TEID available for session re-activation".to_string()
                ))?;

            let upf_ipv4_str = sm_context.upf_tunnel_ipv4.as_deref()
                .or(sm_context.upf_address.as_deref())
                .ok_or_else(|| AppError::ValidationError(
                    "No UPF address available for session re-activation".to_string()
                ))?;

            let upf_ipv4: std::net::Ipv4Addr = upf_ipv4_str.parse().map_err(|e| {
                AppError::ValidationError(format!("Invalid UPF IPv4 address: {}", e))
            })?;

            let default_qfi = sm_context.qos_flows.first().map(|f| f.qfi).unwrap_or(1);

            let ambr_dl_kbps = sm_context.session_ambr.as_ref()
                .and_then(|ambr| AmbrEnforcementService::parse_ambr_bitrate(&ambr.downlink).ok())
                .map(|bps| bps / 1000)
                .unwrap_or(100_000);
            let ambr_ul_kbps = sm_context.session_ambr.as_ref()
                .and_then(|ambr| AmbrEnforcementService::parse_ambr_bitrate(&ambr.uplink).ok())
                .map(|bps| bps / 1000)
                .unwrap_or(50_000);

            let n2_transfer = crate::parsers::ngap_encoder::encode_pdu_session_resource_setup_request_transfer(
                ambr_dl_kbps,
                ambr_ul_kbps,
                upf_teid,
                upf_ipv4,
                default_qfi,
            ).map_err(|e| AppError::ValidationError(format!("Failed to encode N2 transfer: {}", e)))?;

            let n2_encoded = general_purpose::STANDARD.encode(&n2_transfer);

            tracing::info!(
                "Built N2 PDU Session Resource Setup Request Transfer for SUPI: {}, TEID: {}, UPF: {}, QFI: {}, AMBR DL/UL: {}/{}",
                sm_context.supi,
                upf_teid,
                upf_ipv4,
                default_qfi,
                ambr_dl_kbps,
                ambr_ul_kbps
            );

            let cn_tunnel_info = TunnelInfo {
                ipv4_addr: Some(upf_ipv4.to_string()),
                ipv6_addr: None,
                gtp_teid: format!("{:08x}", upf_teid),
            };

            Ok(Json(PduSessionUpdatedData {
                n1_sm_info_to_ue: None,
                n1_sm_msg: None,
                n2_sm_info: Some(N2SmInfo {
                    content_id: "n2-pdu-session-resource-setup-request-transfer".to_string(),
                    n2_info_content: N2InfoContent {
                        ngap_ie_type: NgapIeType::PduResSetupReq,
                        ngap_data: n2_encoded,
                    },
                }),
                n2_sm_info_type: Some(N2SmInfoType::PduResSetupReq),
                eps_bearer_info: None,
                supported_features: None,
                ho_state: None,
                session_ambr: sm_context.session_ambr.clone(),
                cn_tunnel_info: Some(cn_tunnel_info),
                additional_cn_tunnel_info: None,
                qos_flows_add_mod_list: None,
                qos_flows_rel_list: None,
                up_cnx_state: Some(UpCnxState::Activating),
                data_forwarding: None,
            }))
        }

        UpCnxState::Activated => {
            tracing::warn!(
                "Unexpected upCnxState ACTIVATED received for SUPI: {} - this should be set by SMF, not AMF",
                sm_context.supi
            );
            Err(AppError::ValidationError(
                "upCnxState ACTIVATED is not a valid request value".to_string()
            ))
        }
    }
}

pub async fn update_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<PduSessionUpdateData>,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    if HandoverService::is_path_switch_request(&payload.n2_sm_info_type) {
        return handle_path_switch(state, sm_context_ref, sm_context, payload).await;
    }

    if let Some(ref ho_state) = payload.ho_state {
        match ho_state {
            HoState::Preparing => {
                return handle_ho_preparing(state, sm_context_ref, sm_context, payload).await;
            }
            HoState::Prepared => {
                return handle_ho_prepared(state, sm_context_ref, sm_context, payload).await;
            }
            HoState::Completed => {
                return handle_ho_completed(state, sm_context_ref, sm_context, payload).await;
            }
            HoState::Cancelled => {
                return cancel_handover_internal(state, sm_context_ref, sm_context).await;
            }
            HoState::None => {}
        }
    }

    if matches!(payload.n2_sm_info_type, Some(N2SmInfoType::HandoverReqAck)) {
        return handle_ho_prepared(state, sm_context_ref, sm_context, payload).await;
    }

    if matches!(payload.n2_sm_info_type, Some(crate::models::N2SmInfoType::PduResSetupRsp)) {
        return handle_n2_setup_response(state, sm_context_ref, sm_context, payload).await;
    }

    if let Some(ref up_cnx_state) = payload.up_cnx_state {
        return handle_up_cnx_state_change(state, sm_context_ref, sm_context, up_cnx_state).await;
    }

    if let Some(ref n1_sm_msg) = payload.n1_sm_msg {
        let n1_data = general_purpose::STANDARD
            .decode(&n1_sm_msg.content_id)
            .map_err(|e| AppError::ValidationError(format!("Failed to decode N1 SM message: {}", e)))?;

        if !n1_data.is_empty() {
            let header = NasParser::parse_sm_header(&n1_data)
                .map_err(AppError::ValidationError)?;

            match header.message_type {
                NasMessageType::PduSessionModificationRequest => {
                    return handle_ue_modification_request(
                        state, sm_context_ref, sm_context, &n1_data,
                    ).await;
                }
                NasMessageType::PduSessionReleaseRequest => {
                    return handle_ue_release_request(
                        state, sm_context_ref, sm_context, &n1_data,
                    ).await;
                }
                NasMessageType::PduSessionModificationComplete => {
                    tracing::info!(
                        "UE confirmed PDU Session Modification for SUPI: {}, PSI: {}",
                        sm_context.supi,
                        sm_context.pdu_session_id
                    );
                    return Ok(Json(PduSessionUpdatedData {
                        n1_sm_info_to_ue: None,
                        n1_sm_msg: None,
                        n2_sm_info: None,
                        n2_sm_info_type: None,
                        eps_bearer_info: None,
                        supported_features: None,
                        ho_state: None,
                        session_ambr: sm_context.session_ambr.clone(),
                        cn_tunnel_info: None,
                        additional_cn_tunnel_info: None,
                        qos_flows_add_mod_list: None,
                        qos_flows_rel_list: None,
                        up_cnx_state: None,
                        data_forwarding: None,
                    }));
                }
                NasMessageType::PduSessionModificationCommandReject => {
                    tracing::warn!(
                        "UE rejected PDU Session Modification for SUPI: {}, PSI: {}",
                        sm_context.supi,
                        sm_context.pdu_session_id
                    );
                    return Ok(Json(PduSessionUpdatedData {
                        n1_sm_info_to_ue: None,
                        n1_sm_msg: None,
                        n2_sm_info: None,
                        n2_sm_info_type: None,
                        eps_bearer_info: None,
                        supported_features: None,
                        ho_state: None,
                        session_ambr: sm_context.session_ambr.clone(),
                        cn_tunnel_info: None,
                        additional_cn_tunnel_info: None,
                        qos_flows_add_mod_list: None,
                        qos_flows_rel_list: None,
                        up_cnx_state: None,
                        data_forwarding: None,
                    }));
                }
                _ => {
                    tracing::warn!(
                        "Unexpected N1 SM message type {:?} for SUPI: {}",
                        header.message_type,
                        sm_context.supi
                    );
                    return Err(AppError::ValidationError(format!(
                        "Unexpected N1 SM message type: {:?}",
                        header.message_type
                    )));
                }
            }
        }
    }

    handle_network_modification(state, sm_context_ref, sm_context, payload).await
}

async fn handle_ue_modification_request(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    n1_data: &[u8],
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let mod_request = NasParser::parse_pdu_session_modification_request(n1_data)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "UE-initiated PDU Session Modification for SUPI: {}, PSI: {}, PTI: {}, QoS rules: {}, QoS flow descs: {}",
        sm_context.supi,
        mod_request.pdu_session_id,
        mod_request.pti,
        mod_request.requested_qos_rules.len(),
        mod_request.requested_qos_flow_descriptions.len()
    );

    if !matches!(sm_context.state, SmContextState::Active) {
        let reject = NasParser::build_pdu_session_modification_reject(
            mod_request.pdu_session_id,
            mod_request.pti,
            GsmCause::MessageTypeNotCompatible,
        );
        let encoded = general_purpose::STANDARD.encode(&reject);
        return Ok(Json(PduSessionUpdatedData {
            n1_sm_info_to_ue: Some(RefToBinaryData { content_id: encoded }),
            n1_sm_msg: None,
            n2_sm_info: None,
            n2_sm_info_type: None,
            eps_bearer_info: None,
            supported_features: None,
            ho_state: None,
            session_ambr: sm_context.session_ambr.clone(),
            cn_tunnel_info: None,
            additional_cn_tunnel_info: None,
            qos_flows_add_mod_list: None,
            qos_flows_rel_list: None,
            up_cnx_state: None,
            data_forwarding: None,
        }));
    }

    let pf_mgr = crate::services::packet_filter::PacketFilterManager::new(Arc::new(state.db.clone()));
    if !mod_request.requested_qos_rules.is_empty() {
        match pf_mgr.process_nas_qos_rules(&sm_context_ref, &mod_request.requested_qos_rules).await {
            Ok(result) => {
                tracing::info!(
                    "Processed QoS rules for SUPI: {}: added {} PFs, removed {} PFs",
                    sm_context.supi,
                    result.added_pf_ids.len(),
                    result.removed_pf_ids.len()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to process QoS rules for SUPI: {}: {}",
                    sm_context.supi,
                    e
                );
                let reject = NasParser::build_pdu_session_modification_reject(
                    mod_request.pdu_session_id,
                    mod_request.pti,
                    GsmCause::SemanticErrorInQosOperation,
                );
                let encoded = general_purpose::STANDARD.encode(&reject);
                return Ok(Json(PduSessionUpdatedData {
                    n1_sm_info_to_ue: Some(RefToBinaryData { content_id: encoded }),
                    n1_sm_msg: None,
                    n2_sm_info: None,
                    n2_sm_info_type: None,
                    eps_bearer_info: None,
                    supported_features: None,
                    ho_state: None,
                    session_ambr: sm_context.session_ambr.clone(),
                    cn_tunnel_info: None,
                    additional_cn_tunnel_info: None,
                    qos_flows_add_mod_list: None,
                    qos_flows_rel_list: None,
                    up_cnx_state: None,
                    data_forwarding: None,
                }));
            }
        }
    }

    let qos_mgr = QosFlowManager::new(Arc::new(state.db.clone()));
    let mut add_qos_flows: Vec<QosFlow> = Vec::new();
    let mut remove_qfis: Vec<u8> = Vec::new();

    for desc in &mod_request.requested_qos_flow_descriptions {
        match desc.operation_code {
            QosFlowOperationCode::CreateNew => {
                let five_qi = desc.parameters.iter()
                    .find_map(|p| p.get_five_qi())
                    .unwrap_or(9);
                let qos_flow = state
                    .slice_qos_policy_service
                    .create_qos_flow_with_5qi(&sm_context.s_nssai, desc.qfi, five_qi);
                add_qos_flows.push(qos_flow);
            }
            QosFlowOperationCode::Delete => {
                remove_qfis.push(desc.qfi);
            }
            QosFlowOperationCode::Modify => {
                let five_qi = desc.parameters.iter()
                    .find_map(|p| p.get_five_qi())
                    .unwrap_or(sm_context.qos_flows.iter()
                        .find(|f| f.qfi == desc.qfi)
                        .map(|f| f.five_qi)
                        .unwrap_or(9));
                let modified_flow = QosFlow::new_with_5qi(desc.qfi, five_qi);
                if let Err(e) = qos_mgr.modify_qos_flow(&sm_context_ref, modified_flow).await {
                    tracing::warn!("Failed to modify QoS flow {}: {}", desc.qfi, e);
                }
            }
        }
    }

    if !add_qos_flows.is_empty() {
        qos_mgr.add_qos_flows(&sm_context_ref, add_qos_flows.clone()).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to add QoS flows: {}", e)))?;
    }
    if !remove_qfis.is_empty() {
        qos_mgr.remove_qos_flows(&sm_context_ref, remove_qfis.clone()).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to remove QoS flows: {}", e)))?;
    }

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let add_opt = if !add_qos_flows.is_empty() { Some(add_qos_flows.as_slice()) } else { None };
        let rem_opt = if !remove_qfis.is_empty() { Some(remove_qfis.as_slice()) } else { None };

        if add_opt.is_some() || rem_opt.is_some() {
            PfcpSessionManager::modify_session(
                pfcp_client, seid, None, add_opt, rem_opt,
                sm_context.up_security_context.as_ref(),
            ).await.map_err(|e| {
                tracing::error!("PFCP modification failed for SUPI: {}: {}", sm_context.supi, e);
                AppError::InternalError(format!("PFCP session modification failed: {}", e))
            })?;
        }
    }

    let authorized_rules: Vec<NasQosRule> = mod_request.requested_qos_rules.clone();
    let authorized_descs: Vec<NasQosFlowDescription> = mod_request.requested_qos_flow_descriptions.clone();

    let n1_command = NasParser::build_pdu_session_modification_command(
        mod_request.pdu_session_id,
        mod_request.pti,
        None,
        None,
        None,
        if authorized_rules.is_empty() { None } else { Some(&authorized_rules) },
        if authorized_descs.is_empty() { None } else { Some(&authorized_descs) },
    );
    let encoded_n1 = general_purpose::STANDARD.encode(&n1_command);

    let qos_flows_add_mod_list = if !add_qos_flows.is_empty() {
        Some(add_qos_flows.iter().map(|f| QosFlowItem { qfi: f.qfi, qos_profile: None }).collect())
    } else {
        None
    };
    let qos_flows_rel_list = if !remove_qfis.is_empty() {
        Some(remove_qfis.iter().map(|qfi| QosFlowItem { qfi: *qfi, qos_profile: None }).collect())
    } else {
        None
    };

    tracing::info!(
        "UE-initiated modification accepted for SUPI: {}, PSI: {}, QoS flows added: {}, removed: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        add_qos_flows.len(),
        remove_qfis.len()
    );

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: Some(RefToBinaryData { content_id: encoded_n1 }),
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: None,
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list,
        qos_flows_rel_list,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

async fn handle_ue_release_request(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    n1_data: &[u8],
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let release_request = NasParser::parse_pdu_session_release_request(n1_data)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "UE-initiated PDU Session Release for SUPI: {}, PSI: {}, PTI: {}, cause: {:?}",
        sm_context.supi,
        release_request.pdu_session_id,
        release_request.pti,
        release_request.cause
    );

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&SmContextState::InactivePending)
                        .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            },
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        if let Err(e) = PfcpSessionManager::delete_session(pfcp_client, seid).await {
            tracing::warn!(
                "Failed to delete PFCP session for SUPI: {}: {}, proceeding with release",
                sm_context.supi, e
            );
        }
    }

    IpamService::release_ip(&state.db, &sm_context_ref)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to release IP for SM Context {}: {}", sm_context_ref, e);
        })
        .ok();

    collection
        .delete_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let n1_command = NasParser::build_pdu_session_release_command(
        release_request.pdu_session_id,
        release_request.pti,
        GsmCause::RegularDeactivation,
    );
    let encoded_n1 = general_purpose::STANDARD.encode(&n1_command);

    tracing::info!(
        "UE-initiated release completed for SUPI: {}, PSI: {}",
        sm_context.supi,
        sm_context.pdu_session_id
    );

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: Some(RefToBinaryData { content_id: encoded_n1 }),
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: Some(N2SmInfoType::PduResRelCmd),
        eps_bearer_info: None,
        supported_features: None,
        ho_state: None,
        session_ambr: None,
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

async fn handle_network_modification(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    payload: PduSessionUpdateData,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    if !matches!(sm_context.state, SmContextState::Active) {
        return Err(AppError::ValidationError(
            "SM context must be in ACTIVE state for modification".to_string(),
        ));
    }

    let qos_mgr = QosFlowManager::new(Arc::new(state.db.clone()));

    let mut add_qos_flows: Vec<QosFlow> = Vec::new();
    let mut remove_qfis: Vec<u8> = Vec::new();

    if let Some(ref qos_flows_add_mod) = payload.qos_flows_add_mod_request_list {
        for qf_item in qos_flows_add_mod {
            let qos_flow = if let Some(ref profile) = qf_item.qos_profile {
                state
                    .slice_qos_policy_service
                    .create_qos_flow_with_5qi(&sm_context.s_nssai, qf_item.qfi, profile.five_qi)
            } else {
                state
                    .slice_qos_policy_service
                    .create_default_qos_flow(&sm_context.s_nssai, qf_item.qfi)
            };
            add_qos_flows.push(qos_flow);
        }

        if !add_qos_flows.is_empty() {
            qos_mgr.add_qos_flows(&sm_context_ref, add_qos_flows.clone()).await
                .map_err(|e| AppError::DatabaseError(format!("Failed to add QoS flows: {}", e)))?;
        }
    }

    if let Some(ref qos_flows_rel) = payload.qos_flows_rel_request_list {
        for qf_item in qos_flows_rel {
            remove_qfis.push(qf_item.qfi);
        }

        if !remove_qfis.is_empty() {
            qos_mgr.remove_qos_flows(&sm_context_ref, remove_qfis.clone()).await
                .map_err(|e| AppError::DatabaseError(format!("Failed to remove QoS flows: {}", e)))?;
        }
    }

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let add_opt = if !add_qos_flows.is_empty() { Some(add_qos_flows.as_slice()) } else { None };
        let rem_opt = if !remove_qfis.is_empty() { Some(remove_qfis.as_slice()) } else { None };

        if add_opt.is_some() || rem_opt.is_some() {
            PfcpSessionManager::modify_session(
                pfcp_client, seid, None, add_opt, rem_opt,
                sm_context.up_security_context.as_ref(),
            ).await.map_err(|e| {
                AppError::InternalError(format!("PFCP session modification failed: {}", e))
            })?;

            tracing::info!(
                "PFCP Session modified for SUPI: {}, SEID: {}",
                sm_context.supi,
                seid
            );
        }
    }

    let mut update_doc = doc! {
        "$set": {
            "updated_at": mongodb::bson::DateTime::now()
        }
    };

    if let Some(ref new_ambr) = payload.session_ambr {
        update_doc.get_document_mut("$set")
            .map_err(|e| AppError::DatabaseError(format!("Failed to access $set document: {}", e)))?
            .insert(
                "session_ambr",
                mongodb::bson::to_bson(new_ambr)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
            );
    }

    collection
        .update_one(doc! { "_id": &sm_context_ref }, update_doc)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let updated_ambr = payload.session_ambr.clone().or(sm_context.session_ambr.clone());

    let qos_flows_add_mod_list = if !add_qos_flows.is_empty() {
        Some(add_qos_flows.iter().map(|f| QosFlowItem { qfi: f.qfi, qos_profile: None }).collect())
    } else {
        None
    };
    let qos_flows_rel_list = if !remove_qfis.is_empty() {
        Some(remove_qfis.iter().map(|qfi| QosFlowItem { qfi: *qfi, qos_profile: None }).collect())
    } else {
        None
    };

    tracing::info!(
        "Network-initiated modification for SUPI: {}, PSI: {}, added: {}, removed: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        add_qos_flows.len(),
        remove_qfis.len()
    );

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: None,
        session_ambr: updated_ambr,
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list,
        qos_flows_rel_list,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

pub async fn release_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    body: Option<Json<SmContextReleaseData>>,
) -> Result<Response, AppError> {
    let payload = body.map(|j| j.0);
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    if let Some(ref data) = payload {
        if let Some(ref loc) = data.ue_location {
            collection
                .update_one(
                    doc! { "_id": &sm_context_ref },
                    doc! {
                        "$set": {
                            "ue_location": mongodb::bson::to_bson(loc)
                                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                            "updated_at": mongodb::bson::DateTime::now()
                        }
                    }
                )
                .await
                .map_err(|e| AppError::DatabaseError(e.to_string()))?;
        }
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::InactivePending)
                        .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        match PfcpSessionManager::delete_session(pfcp_client, seid).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP session deleted for SUPI: {}, SEID: {}",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete PFCP session for SUPI: {}: {}, proceeding with cleanup",
                    sm_context.supi,
                    e
                );
            }
        }
    }

    if let (Some(ref pcf_client), Some(ref policy_id)) = (&state.pcf_client, &sm_context.pcf_policy_id) {
        let pcf_uri = std::env::var("PCF_URI").unwrap_or_default();

        match pcf_client.delete_sm_policy(&pcf_uri, policy_id).await {
            Ok(_) => {
                tracing::info!(
                    "SM policy deleted for SUPI: {}, Policy ID: {}",
                    sm_context.supi,
                    policy_id
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete SM policy for SUPI: {}: {}, proceeding with cleanup",
                    sm_context.supi,
                    e
                );
            }
        }
    }

    if let (Some(ref chf_client), Some(ref charging_ref)) = (&state.chf_client, &sm_context.chf_charging_ref) {
        let chf_uri = std::env::var("CHF_URI").unwrap_or_default();

        let nf_identification = crate::types::chf::NfIdentification {
            nf_name: format!("SMF-{}", std::env::var("NF_INSTANCE_ID").unwrap_or_else(|_| "unknown".to_string())),
            nf_ip_v4_address: Some(std::env::var("SMF_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())),
            nf_ip_v6_address: None,
            nf_plmn_id: None,
            nf_fqdn: None,
        };

        let charging_request = crate::types::chf::ChargingDataRequest {
            subscriber_identifier: sm_context.supi.clone(),
            nf_consumer_identification: nf_identification,
            invocation_time_stamp: chrono::Utc::now().to_rfc3339(),
            invocation_sequence_number: 1,
            one_time_event: Some(false),
            one_time_event_type: None,
            notify_uri: None,
            multipleunit_usage: None,
            triggers: Some(vec![crate::types::chf::Trigger::StopOfServiceDataFlow]),
            pdu_session_charging_information: None,
            roaming_qbc_information: None,
            tenant_identifier: None,
        };

        match chf_client.release_charging_session(&chf_uri, charging_ref, charging_request).await {
            Ok(_) => {
                tracing::info!(
                    "Charging session released for SUPI: {}, Charging Ref: {}",
                    sm_context.supi,
                    charging_ref
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to release charging session for SUPI: {}: {}, proceeding with cleanup",
                    sm_context.supi,
                    e
                );
            }
        }
    }

    let release_cause = payload.as_ref().and_then(|d| d.cause.clone());

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::PduSesRelease,
        &sm_context.supi,
        sm_context.pdu_session_id,
        Some(sm_context.dnn.clone()),
        Some(sm_context.s_nssai.clone()),
        None,
        None,
        Some(sm_context_ref.clone()),
        Some(crate::types::Cause::RegularDeactivation),
    ).await;

    IpamService::release_ip(&state.db, &sm_context_ref)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to release IP for SM Context {}: {}", sm_context_ref, e);
        })
        .ok();

    collection
        .delete_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if let Some(ref status_uri) = sm_context.sm_context_status_uri {
        let client = reqwest::Client::new();
        let notification = SmContextStatusNotification {
            status_info: SmContextStatusInfo {
                resource_status: ResourceStatus::Released,
                cause: release_cause,
            },
        };
        let uri = status_uri.clone();
        tokio::spawn(async move {
            match client.post(&uri).json(&notification).send().await {
                Ok(resp) => {
                    tracing::info!(
                        "SmContextStatusNotification sent to AMF, status: {}",
                        resp.status()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to send SmContextStatusNotification to AMF: {}", e);
                }
            }
        });
    }

    tracing::info!(
        "Released PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn list_ue_pdu_sessions(
    State(state): State<AppState>,
    Path(supi): Path<String>,
    Query(query): Query<SmContextListQuery>,
) -> Result<Json<Vec<SmContextSummary>>, AppError> {
    validate_supi(&supi).map_err(AppError::ValidationError)?;

    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let mut filter = doc! { "supi": &supi };
    if let Some(pdu_session_id) = query.pdu_session_id {
        filter.insert("pdu_session_id", pdu_session_id as i32);
    }
    if let Some(ref dnn) = query.dnn {
        filter.insert("dnn", dnn);
    }

    let sessions: Vec<SmContext> = collection
        .find(filter)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .try_collect()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let summaries: Vec<SmContextSummary> = sessions.into_iter().map(SmContextSummary::from).collect();

    tracing::debug!(
        "Retrieved {} PDU sessions for SUPI: {}",
        summaries.len(),
        supi
    );

    Ok(Json(summaries))
}

pub async fn retrieve_pdu_session_by_supi(
    State(state): State<AppState>,
    Path((supi, pdu_session_id)): Path<(String, u8)>,
) -> Result<Json<SmContextSummary>, AppError> {
    validate_supi(&supi).map_err(AppError::ValidationError)?;
    validate_pdu_session_id(pdu_session_id).map_err(AppError::ValidationError)?;

    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find(doc! { "supi": &supi, "pdu_session_id": pdu_session_id as i32 })
        .sort(doc! { "updated_at": -1 })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .try_next()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("SM Context not found".to_string()))?;

    tracing::debug!(
        "Retrieved PDU Session for SUPI: {}, PDU Session ID: {}",
        supi,
        pdu_session_id
    );

    Ok(Json(SmContextSummary::from(sm_context)))
}

async fn handle_ho_preparing(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    payload: PduSessionUpdateData,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    HandoverService::validate_handover_state(&sm_context.state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover preparing for SUPI: {}, PSI: {}, Target: {:?}",
        sm_context.supi,
        sm_context.pdu_session_id,
        payload.target_id
    );

    if sm_context.ssc_mode == SscMode::Mode1 {
        if let Some(ref pdu_addr) = sm_context.pdu_address {
            tracing::info!(
                "SSC Mode 1: IP preserved during handover for SUPI: {}, IPv4: {:?}",
                sm_context.supi,
                pdu_addr.ipv4_addr
            );
        }
    }

    let upf_ipv4 = sm_context.upf_tunnel_ipv4
        .as_deref()
        .or_else(|| sm_context.upf_address.as_deref())
        .unwrap_or("127.0.0.1");
    let upf_teid = sm_context.upf_teid.unwrap_or(0);

    let cn_tunnel_info = TunnelInfo {
        ipv4_addr: Some(upf_ipv4.to_string()),
        ipv6_addr: None,
        gtp_teid: format!("{:08x}", upf_teid),
    };

    let n2_transfer = crate::parsers::ngap_encoder::encode_pdu_session_resource_setup_request_transfer(
        sm_context.session_ambr.as_ref().map(|a| a.downlink.parse::<u64>().unwrap_or(1000000)).unwrap_or(1000000),
        sm_context.session_ambr.as_ref().map(|a| a.uplink.parse::<u64>().unwrap_or(1000000)).unwrap_or(1000000),
        upf_teid,
        upf_ipv4.parse().unwrap_or(std::net::Ipv4Addr::LOCALHOST),
        sm_context.qos_flows.first().map(|f| f.qfi).unwrap_or(1),
    ).map_err(|e| AppError::ValidationError(format!("Failed to encode NGAP transfer: {}", e)))?;

    let n2_data = general_purpose::STANDARD.encode(&n2_transfer);

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "handover_state": mongodb::bson::to_bson(&HoState::Preparing)
                        .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: Some(N2SmInfo {
            content_id: "n2-handover-command".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::HandoverCmd,
                ngap_data: n2_data,
            },
        }),
        n2_sm_info_type: Some(N2SmInfoType::HandoverCmd),
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Preparing),
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: Some(cn_tunnel_info),
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: payload.data_forwarding,
    }))
}

async fn handle_ho_prepared(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    payload: PduSessionUpdateData,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    HandoverService::validate_ho_state_for_request_ack(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover request ack for SUPI: {}, PSI: {}",
        sm_context.supi,
        sm_context.pdu_session_id
    );

    let n2_sm_info = payload.n2_sm_info
        .as_ref()
        .ok_or_else(|| AppError::ValidationError(
            "N2 SM Info with PDUSessionResourceSetupResponseTransfer required for Handover Request Acknowledge".to_string()
        ))?;

    let resources = HandoverService::extract_allocated_handover_resources(&n2_sm_info.n2_info_content.ngap_data)
        .map_err(|e| AppError::ValidationError(format!(
            "Failed to extract handover resources for SUPI {}: {}", sm_context.supi, e
        )))?;

    let mapping_result = QosFlowMappingService::map_qos_flows_to_target(
        &sm_context.qos_flows,
        &resources.allocated_qos_flow_ids,
        &resources.failed_qos_flow_ids,
    );

    if !mapping_result.mapping_status.is_acceptable() {
        return Err(AppError::ValidationError(format!(
            "QoS flow mapping failed: {:?}",
            mapping_result.mapping_status
        )));
    }

    if let Some(ref up_sec) = sm_context.up_security_context {
        if up_sec.integrity_protection_activated {
            if resources.integrity_protection_result == Some(crate::types::ngap::IntegrityProtectionResult::NotPerformed) {
                tracing::warn!(
                    "Target gNB did not activate integrity protection for SUPI: {}, PSI: {} - was active on source",
                    sm_context.supi,
                    sm_context.pdu_session_id
                );
            }
        }
        if up_sec.confidentiality_protection_activated {
            if resources.confidentiality_protection_result == Some(crate::types::ngap::ConfidentialityProtectionResult::NotPerformed) {
                tracing::warn!(
                    "Target gNB did not activate confidentiality protection for SUPI: {}, PSI: {} - was active on source",
                    sm_context.supi,
                    sm_context.pdu_session_id
                );
            }
        }
    }

    let updated_up_security = sm_context.up_security_context.clone().map(|mut sec| {
        if let Some(ref ip_result) = resources.integrity_protection_result {
            sec.integrity_protection_activated = *ip_result == crate::types::ngap::IntegrityProtectionResult::Performed;
        }
        if let Some(ref cp_result) = resources.confidentiality_protection_result {
            sec.confidentiality_protection_activated = *cp_result == crate::types::ngap::ConfidentialityProtectionResult::Performed;
        }
        sec
    });

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&HoState::Prepared)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "source_an_tunnel_info": mongodb::bson::to_bson(&sm_context.an_tunnel_info)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "an_tunnel_info": mongodb::bson::to_bson(&resources.target_tunnel_info)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "updated_at": mongodb::bson::DateTime::now()
    };

    if !mapping_result.allocated_flows.is_empty() {
        update_doc.insert(
            "qos_flows",
            mongodb::bson::to_bson(&mapping_result.allocated_flows)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    if let Some(ref up_sec) = updated_up_security {
        update_doc.insert(
            "up_security_context",
            mongodb::bson::to_bson(up_sec)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if let (Some(ref pfcp_client), Some(pfcp_session_id)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        if let Err(e) = PfcpSessionManager::deactivate_downlink(pfcp_client, pfcp_session_id).await {
            tracing::error!(
                "Failed to buffer DL at UPF during handover for SUPI: {}, PSI: {}: {}",
                sm_context.supi, sm_context.pdu_session_id, e
            );
        }
    }

    let upf_ipv4 = sm_context.upf_tunnel_ipv4
        .as_deref()
        .or_else(|| sm_context.upf_address.as_deref())
        .unwrap_or("127.0.0.1");
    let upf_teid = sm_context.upf_teid.unwrap_or(0);

    let cn_tunnel_info = TunnelInfo {
        ipv4_addr: Some(upf_ipv4.to_string()),
        ipv6_addr: None,
        gtp_teid: format!("{:08x}", upf_teid),
    };

    let qos_flows_rel_list = if !mapping_result.failed_flows.is_empty() {
        Some(mapping_result.failed_flows.iter().map(|f| QosFlowItem {
            qfi: f.qfi,
            qos_profile: None,
        }).collect())
    } else {
        None
    };

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Prepared),
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: Some(cn_tunnel_info),
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list,
        up_cnx_state: None,
        data_forwarding: payload.data_forwarding,
    }))
}

// NON-STANDARD: This endpoint does not exist in TS 29.502.
// In 3GPP, handover request ack is handled via POST /sm-contexts/{ref}/modify
// with n2SmInfoType=HANDOVER_REQ_ACK. This dedicated endpoint exists because
// the modify handler was split for readability. The AMF should call /modify instead.
pub async fn handle_handover_request_ack(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<crate::types::HandoverRequestAckData>,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    HandoverService::validate_ho_state_for_request_ack(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover request ack (dedicated) for SUPI: {}, PSI: {}, request PSI: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        payload.pdu_session_id
    );

    if payload.pdu_session_id != sm_context.pdu_session_id {
        return Err(AppError::ValidationError(format!(
            "PDU Session ID mismatch: request={}, context={}",
            payload.pdu_session_id, sm_context.pdu_session_id
        )));
    }

    let n2_sm_info = payload.n2_sm_info
        .as_ref()
        .ok_or_else(|| AppError::ValidationError(
            "N2 SM Info with PDUSessionResourceSetupResponseTransfer required for Handover Request Acknowledge".to_string()
        ))?;

    let resources = HandoverService::extract_allocated_handover_resources(&n2_sm_info.n2_info_content.ngap_data)
        .map_err(|e| AppError::ValidationError(format!(
            "Failed to extract handover resources for SUPI {}: {}", sm_context.supi, e
        )))?;

    let mapping_result = QosFlowMappingService::map_qos_flows_to_target(
        &sm_context.qos_flows,
        &resources.allocated_qos_flow_ids,
        &resources.failed_qos_flow_ids,
    );

    if !mapping_result.mapping_status.is_acceptable() {
        return Err(AppError::ValidationError(format!(
            "QoS flow mapping failed: {:?}",
            mapping_result.mapping_status
        )));
    }

    if let Some(ref up_sec) = sm_context.up_security_context {
        if up_sec.integrity_protection_activated {
            if resources.integrity_protection_result == Some(crate::types::ngap::IntegrityProtectionResult::NotPerformed) {
                tracing::warn!(
                    "Target gNB did not activate integrity protection for SUPI: {}, PSI: {} - was active on source",
                    sm_context.supi,
                    sm_context.pdu_session_id
                );
            }
        }
        if up_sec.confidentiality_protection_activated {
            if resources.confidentiality_protection_result == Some(crate::types::ngap::ConfidentialityProtectionResult::NotPerformed) {
                tracing::warn!(
                    "Target gNB did not activate confidentiality protection for SUPI: {}, PSI: {} - was active on source",
                    sm_context.supi,
                    sm_context.pdu_session_id
                );
            }
        }
    }

    let updated_up_security = sm_context.up_security_context.clone().map(|mut sec| {
        if let Some(ref ip_result) = resources.integrity_protection_result {
            sec.integrity_protection_activated = *ip_result == crate::types::ngap::IntegrityProtectionResult::Performed;
        }
        if let Some(ref cp_result) = resources.confidentiality_protection_result {
            sec.confidentiality_protection_activated = *cp_result == crate::types::ngap::ConfidentialityProtectionResult::Performed;
        }
        sec
    });

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&HoState::Prepared)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "source_an_tunnel_info": mongodb::bson::to_bson(&sm_context.an_tunnel_info)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "an_tunnel_info": mongodb::bson::to_bson(&resources.target_tunnel_info)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "updated_at": mongodb::bson::DateTime::now()
    };

    if !mapping_result.allocated_flows.is_empty() {
        update_doc.insert(
            "qos_flows",
            mongodb::bson::to_bson(&mapping_result.allocated_flows)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    if let Some(ref up_sec) = updated_up_security {
        update_doc.insert(
            "up_security_context",
            mongodb::bson::to_bson(up_sec)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if let (Some(ref pfcp_client), Some(pfcp_session_id)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        if let Err(e) = PfcpSessionManager::deactivate_downlink(pfcp_client, pfcp_session_id).await {
            tracing::error!(
                "Failed to buffer DL at UPF during handover for SUPI: {}, PSI: {}: {}",
                sm_context.supi, sm_context.pdu_session_id, e
            );
        }
    }

    let upf_ipv4 = sm_context.upf_tunnel_ipv4
        .as_deref()
        .or_else(|| sm_context.upf_address.as_deref())
        .unwrap_or("127.0.0.1");
    let upf_teid = sm_context.upf_teid.unwrap_or(0);

    let cn_tunnel_info = TunnelInfo {
        ipv4_addr: Some(upf_ipv4.to_string()),
        ipv6_addr: None,
        gtp_teid: format!("{:08x}", upf_teid),
    };

    let qos_flows_rel_list = if !mapping_result.failed_flows.is_empty() {
        Some(mapping_result.failed_flows.iter().map(|f| QosFlowItem {
            qfi: f.qfi,
            qos_profile: None,
        }).collect())
    } else {
        None
    };

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Prepared),
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: Some(cn_tunnel_info),
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list,
        up_cnx_state: None,
        data_forwarding: payload.data_forwarding,
    }))
}

async fn handle_ho_completed(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    payload: PduSessionUpdateData,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    if matches!(payload.cause, Some(crate::models::SmContextUpdateCause::RelDueToHo)) {
        return handle_source_smf_ho_release(state, sm_context_ref, sm_context, collection).await;
    }

    HandoverService::validate_ho_state_for_notify(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover completed for SUPI: {}, PSI: {}",
        sm_context.supi,
        sm_context.pdu_session_id
    );

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&HoState::Completed)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "state": mongodb::bson::to_bson(&SmContextState::Active)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "updated_at": mongodb::bson::DateTime::now()
    };

    let an_tunnel_info = payload.an_tunnel_info.as_ref()
        .or(sm_context.an_tunnel_info.as_ref());

    if let Some(an_tunnel_info) = an_tunnel_info {
        if payload.an_tunnel_info.is_some() {
            update_doc.insert(
                "an_tunnel_info",
                mongodb::bson::to_bson(an_tunnel_info)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
            );
        }

        if let (Some(ref pfcp_client), Some(pfcp_session_id)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
            if let Some(an_ipv4_str) = an_tunnel_info.ipv4_addr.as_ref() {
                let an_ipv4 = an_ipv4_str.parse().map_err(|e| {
                    AppError::ValidationError(format!("Invalid AN tunnel IPv4 address '{}': {}", an_ipv4_str, e))
                })?;
                PfcpSessionManager::modify_session_for_handover(
                    pfcp_client,
                    pfcp_session_id,
                    an_ipv4,
                    &an_tunnel_info.gtp_teid,
                    sm_context.up_security_context.as_ref(),
                    true,
                ).await.map_err(|e| {
                    AppError::ValidationError(format!(
                        "Failed to update PFCP session for handover completion SUPI: {}, PSI: {}: {}",
                        sm_context.supi, sm_context.pdu_session_id, e
                    ))
                })?;
            }
        }
    }

    if let Some(ref ue_location) = payload.ue_location {
        update_doc.insert(
            "ue_location",
            mongodb::bson::to_bson(ue_location)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    if sm_context.ssc_mode == SscMode::Mode2 {
        let dnn_config = state.dnn_selector.validate_dnn(&sm_context.dnn)
            .map_err(AppError::ValidationError)?;

        let mut mutable_context = sm_context.clone();
        let new_pdu_address = SscMode2Service::handle_mobility_event(
            &mut mutable_context,
            &state.db,
            state.pfcp_client.as_ref(),
            &dnn_config.ip_pool_name,
        ).await.map_err(AppError::ValidationError)?;

        update_doc.insert(
            "pdu_address",
            mongodb::bson::to_bson(&new_pdu_address)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    } else if sm_context.ssc_mode == SscMode::Mode3 {
        let dnn_config = state.dnn_selector.validate_dnn(&sm_context.dnn)
            .map_err(AppError::ValidationError)?;

        let mut mutable_context = sm_context.clone();
        let (new_pdu_address, _old_address) = SscMode3Service::handle_mobility_event(
            &mut mutable_context,
            &state.db,
            state.pfcp_client.as_ref(),
            &dnn_config.ip_pool_name,
        ).await.map_err(AppError::ValidationError)?;

        update_doc.insert(
            "pdu_address",
            mongodb::bson::to_bson(&new_pdu_address)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::UpPathChange,
        &sm_context.supi,
        sm_context.pdu_session_id,
        Some(sm_context.dnn.clone()),
        Some(sm_context.s_nssai.clone()),
        sm_context.pdu_address.as_ref().and_then(|a| a.ipv4_addr.clone()),
        sm_context.pdu_address.as_ref().and_then(|a| a.ipv6_addr.clone()),
        Some(sm_context_ref.clone()),
        None,
    ).await;

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Completed),
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

async fn handle_source_smf_ho_release(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
    collection: Collection<SmContext>,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    tracing::info!(
        "Source SMF HO release (cause: REL_DUE_TO_HO) - SUPI: {}, PSI: {}",
        sm_context.supi,
        sm_context.pdu_session_id
    );

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        match PfcpSessionManager::delete_session(pfcp_client, seid).await {
            Ok(_) => {
                tracing::info!(
                    "Source PFCP session deleted for inter-SMF HO - SUPI: {}, SEID: {}",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete source PFCP session for inter-SMF HO - SUPI: {}: {}",
                    sm_context.supi,
                    e
                );
            }
        }
    }

    if let (Some(ref pcf_client), Some(ref policy_id)) = (&state.pcf_client, &sm_context.pcf_policy_id) {
        let pcf_uri = std::env::var("PCF_URI").unwrap_or_default();
        if let Err(e) = pcf_client.delete_sm_policy(&pcf_uri, policy_id).await {
            tracing::warn!(
                "Failed to delete SM policy during inter-SMF HO release - SUPI: {}: {}",
                sm_context.supi,
                e
            );
        }
    }

    IpamService::release_ip(&state.db, &sm_context.id).await.ok();

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": {
                "state": mongodb::bson::to_bson(&SmContextState::Inactive)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                "handover_state": mongodb::bson::to_bson(&HoState::Completed)
                    .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
                "updated_at": mongodb::bson::DateTime::now()
            }}
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Source SM context released after inter-SMF HO - SUPI: {}, PSI: {}",
        sm_context.supi,
        sm_context.pdu_session_id
    );

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Completed),
        session_ambr: None,
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

// NON-STANDARD: This endpoint does not exist in TS 29.502.
// In 3GPP, handover cancel is handled via POST /sm-contexts/{ref}/modify
// with hoState=CANCELLED. This dedicated endpoint exists because the modify
// handler was split for readability. The AMF should call /modify instead.
pub async fn handle_handover_cancel(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<crate::types::HandoverCancelData>,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    if payload.pdu_session_id != sm_context.pdu_session_id {
        return Err(AppError::ValidationError(format!(
            "PDU Session ID mismatch: request={}, context={}",
            payload.pdu_session_id, sm_context.pdu_session_id
        )));
    }

    tracing::info!(
        "Handover cancel (dedicated) for SUPI: {}, PSI: {}, cause: {:?}",
        sm_context.supi,
        sm_context.pdu_session_id,
        payload.cause
    );

    cancel_handover_internal(state, sm_context_ref, sm_context).await
}

async fn cancel_handover_internal(
    state: AppState,
    sm_context_ref: String,
    sm_context: SmContext,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    HandoverService::validate_ho_state_for_cancel(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    let source_tunnel = sm_context.source_an_tunnel_info.as_ref()
        .or(sm_context.an_tunnel_info.as_ref());

    if matches!(sm_context.handover_state, Some(HoState::Prepared)) {
        if let (Some(ref pfcp_client), Some(pfcp_session_id), Some(tunnel)) =
            (&state.pfcp_client, sm_context.pfcp_session_id, source_tunnel)
        {
            if let Some(ref an_ipv4_str) = tunnel.ipv4_addr {
                let an_ipv4 = an_ipv4_str.parse().map_err(|e| {
                    AppError::ValidationError(format!(
                        "Invalid source AN tunnel IPv4 '{}': {}", an_ipv4_str, e
                    ))
                })?;
                if let Err(e) = PfcpSessionManager::reactivate_downlink(
                    pfcp_client,
                    pfcp_session_id,
                    an_ipv4,
                    &tunnel.gtp_teid,
                ).await {
                    tracing::error!(
                        "Failed to reactivate DL after handover cancel for SUPI: {}, PSI: {}: {}",
                        sm_context.supi, sm_context.pdu_session_id, e
                    );
                }
            }
        }
    }

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&HoState::Cancelled)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "state": mongodb::bson::to_bson(&sm_context.state)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "updated_at": mongodb::bson::DateTime::now()
    };

    if let Some(ref source_tunnel_info) = sm_context.source_an_tunnel_info {
        update_doc.insert(
            "an_tunnel_info",
            mongodb::bson::to_bson(source_tunnel_info)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    update_doc.insert("source_an_tunnel_info", mongodb::bson::Bson::Null);

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Cancelled),
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}


// NON-STANDARD: This endpoint does not exist in TS 29.502.
// In 3GPP, handover notify is handled via POST /sm-contexts/{ref}/modify
// with hoState=COMPLETED. This dedicated endpoint exists because the modify
// handler was split for readability. The AMF should call /modify instead.
pub async fn handle_handover_notify(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<crate::types::HandoverNotifyData>,
) -> Result<Json<PduSessionUpdatedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    if payload.pdu_session_id != sm_context.pdu_session_id {
        return Err(AppError::ValidationError(format!(
            "PDU Session ID mismatch: request={}, context={}",
            payload.pdu_session_id, sm_context.pdu_session_id
        )));
    }

    HandoverService::validate_ho_state_for_notify(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover notify for SUPI: {}, PSI: {}, hoState: {:?}",
        sm_context.supi,
        sm_context.pdu_session_id,
        payload.ho_state
    );

    let an_tunnel_info = payload.an_tunnel_info.as_ref()
        .or(sm_context.an_tunnel_info.as_ref())
        .ok_or_else(|| AppError::ValidationError(
            "No AN tunnel info available: not in request and not stored from Prepared phase".to_string()
        ))?;

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&HoState::Completed)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "state": mongodb::bson::to_bson(&SmContextState::Active)
            .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        "updated_at": mongodb::bson::DateTime::now()
    };

    if payload.an_tunnel_info.is_some() {
        update_doc.insert(
            "an_tunnel_info",
            mongodb::bson::to_bson(an_tunnel_info)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    if let (Some(ref pfcp_client), Some(pfcp_session_id)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        if let Some(an_ipv4_str) = an_tunnel_info.ipv4_addr.as_ref() {
            let an_ipv4 = an_ipv4_str.parse().map_err(|e| {
                AppError::ValidationError(format!("Invalid AN tunnel IPv4 address '{}': {}", an_ipv4_str, e))
            })?;
            PfcpSessionManager::modify_session_for_handover(
                pfcp_client,
                pfcp_session_id,
                an_ipv4,
                &an_tunnel_info.gtp_teid,
                sm_context.up_security_context.as_ref(),
                true,
            ).await.map_err(|e| {
                AppError::ValidationError(format!(
                    "Failed to update PFCP session for handover completion SUPI: {}, PSI: {}: {}",
                    sm_context.supi, sm_context.pdu_session_id, e
                ))
            })?;
        } else {
            return Err(AppError::ValidationError(
                "AN tunnel info missing IPv4 address for PFCP update".to_string()
            ));
        }
    }

    if let Some(ref ue_location) = payload.ue_location {
        update_doc.insert(
            "ue_location",
            mongodb::bson::to_bson(ue_location)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    if sm_context.ssc_mode == SscMode::Mode2 {
        let dnn_config = state.dnn_selector.validate_dnn(&sm_context.dnn)
            .map_err(AppError::ValidationError)?;

        let mut mutable_context = sm_context.clone();
        let new_pdu_address = SscMode2Service::handle_mobility_event(
            &mut mutable_context,
            &state.db,
            state.pfcp_client.as_ref(),
            &dnn_config.ip_pool_name,
        ).await.map_err(AppError::ValidationError)?;

        update_doc.insert(
            "pdu_address",
            mongodb::bson::to_bson(&new_pdu_address)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    } else if sm_context.ssc_mode == SscMode::Mode3 {
        let dnn_config = state.dnn_selector.validate_dnn(&sm_context.dnn)
            .map_err(AppError::ValidationError)?;

        let mut mutable_context = sm_context.clone();
        let (new_pdu_address, _old_address) = SscMode3Service::handle_mobility_event(
            &mut mutable_context,
            &state.db,
            state.pfcp_client.as_ref(),
            &dnn_config.ip_pool_name,
        ).await.map_err(AppError::ValidationError)?;

        update_doc.insert(
            "pdu_address",
            mongodb::bson::to_bson(&new_pdu_address)
                .map_err(|e| AppError::DatabaseError(format!("BSON serialization failed: {}", e)))?,
        );
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    state.notification_service.notify_pdu_session_event(
        &state.db,
        crate::types::EventType::UpPathChange,
        &sm_context.supi,
        sm_context.pdu_session_id,
        Some(sm_context.dnn.clone()),
        Some(sm_context.s_nssai.clone()),
        sm_context.pdu_address.as_ref().and_then(|a| a.ipv4_addr.clone()),
        sm_context.pdu_address.as_ref().and_then(|a| a.ipv6_addr.clone()),
        Some(sm_context_ref.clone()),
        None,
    ).await;

    Ok(Json(PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n1_sm_msg: None,
        n2_sm_info: None,
        n2_sm_info_type: None,
        eps_bearer_info: None,
        supported_features: None,
        ho_state: Some(HoState::Completed),
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        qos_flows_add_mod_list: None,
        qos_flows_rel_list: None,
        up_cnx_state: None,
        data_forwarding: None,
    }))
}

fn not_implemented_response(operation: &str) -> Response {
    let body = serde_json::json!({
        "type": "https://httpstatuses.io/501",
        "title": "Not Implemented",
        "status": 501,
        "detail": format!("{} is not yet implemented", operation),
        "cause": "NOT_IMPLEMENTED"
    });
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/problem+json")],
        Json(body),
    ).into_response()
}

pub async fn send_mo_data(
    State(_state): State<AppState>,
    Path(_sm_context_ref): Path<String>,
) -> Response {
    not_implemented_response("SendMoData")
}

pub async fn create_pdu_session_hsmf(
    State(_state): State<AppState>,
    Json(_payload): Json<serde_json::Value>,
) -> Response {
    not_implemented_response("PostPduSessions (H-SMF create)")
}

pub async fn modify_pdu_session_hsmf(
    State(_state): State<AppState>,
    Path(_pdu_session_ref): Path<String>,
    Json(_payload): Json<serde_json::Value>,
) -> Response {
    not_implemented_response("UpdatePduSession (H-SMF modify)")
}

pub async fn release_pdu_session_hsmf(
    State(_state): State<AppState>,
    Path(_pdu_session_ref): Path<String>,
) -> Response {
    not_implemented_response("ReleasePduSession (H-SMF release)")
}

pub async fn retrieve_pdu_session_hsmf(
    State(_state): State<AppState>,
    Path(_pdu_session_ref): Path<String>,
    Json(_payload): Json<serde_json::Value>,
) -> Response {
    not_implemented_response("RetrievePduSession (H-SMF retrieve)")
}

pub async fn transfer_mo_data_hsmf(
    State(_state): State<AppState>,
    Path(_pdu_session_ref): Path<String>,
) -> Response {
    not_implemented_response("TransferMoData (H-SMF)")
}
