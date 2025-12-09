use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mongodb::{bson::doc, Collection};
use futures::TryStreamExt;
use crate::db::AppState;
use crate::models::{Ambr, PduSessionCreateData, PduSessionCreatedData, PduSessionReleaseData, PduSessionReleasedData, PduSessionUpdateData, PduSessionUpdatedData, SmContext, N2SmInfoType, TunnelInfo};
use crate::types::{N2SmInfo, N2InfoContent, NgapIeType, NasParser, PduAddress, PduSessionType, QosFlow, SscMode, HandoverRequiredData, HandoverRequiredResponse, HandoverRequestAckData, HandoverNotifyData, HandoverCancelData, HoState};
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
use std::sync::Arc;

pub async fn create_pdu_session(
    State(state): State<AppState>,
    Json(payload): Json<PduSessionCreateData>,
) -> Result<Json<PduSessionCreatedData>, AppError> {
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

    let (subscriber_5qi, subscriber_ambr, subscriber_ssc_modes) = if let Some(ref udm_client) = state.udm_client {
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

                        if let Some(qos_5qi) = sub_5qi {
                            tracing::info!(
                                "Using subscriber 5QI: {} from UDM for SUPI: {}",
                                qos_5qi,
                                payload.supi
                            );
                        }

                        if sub_ambr.is_some() {
                            tracing::info!(
                                "Using subscriber session AMBR from UDM for SUPI: {}",
                                payload.supi
                            );
                        }

                        (sub_5qi, sub_ambr, sub_ssc_modes)
                    } else {
                        tracing::warn!(
                            "DNN {} not found in subscriber's UDM data for SUPI: {}, using defaults",
                            payload.dnn,
                            payload.supi
                        );
                        (None, None, None)
                    }
                } else {
                    tracing::warn!(
                        "No DNN configurations found in UDM data for SUPI: {}, using defaults",
                        payload.supi
                    );
                    (None, None, None)
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to retrieve SM data from UDM for SUPI: {}: {}, continuing with defaults",
                    payload.supi,
                    e
                );
                (None, None, None)
            }
        }
    } else {
        tracing::debug!("UDM client not available, skipping subscriber validation");
        (None, None, None)
    };

    let existing = collection
        .find_one(doc! { "supi": &payload.supi, "pdu_session_id": payload.pdu_session_id as i32 })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    if existing.is_some() {
        return Err(AppError::ValidationError(format!(
            "PDU Session already exists for SUPI {} with PDU Session ID {}",
            payload.supi, payload.pdu_session_id
        )));
    }

    let mut sm_context = SmContext::new(&payload);

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

        let n1_data = base64::decode(&n1_sm_msg.content_id).unwrap_or_default();

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
            Ok(_) => {
                sm_context.pfcp_session_id = Some(seid);
                sm_context.state = crate::types::SmContextState::Active;
                tracing::info!(
                    "PFCP Session established for SUPI: {}, SEID: {}, State: Active",
                    payload.supi,
                    seid
                );
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

    collection
        .insert_one(&sm_context)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let n1_sm_info_to_ue = if let Some(ref up_sec_ctx) = sm_context.up_security_context {
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

        let integrity_required = up_sec_ctx.integrity_protection_activated;
        let confidentiality_required = up_sec_ctx.confidentiality_protection_activated;

        let nas_accept_msg = NasParser::build_pdu_session_establishment_accept(
            payload.pdu_session_id,
            1,
            pdu_session_type_value,
            ssc_mode_value,
            integrity_required,
            confidentiality_required,
        );

        let encoded = base64::encode(&nas_accept_msg);

        tracing::info!(
            "Built N1 PDU Session Establishment Accept for SUPI: {} with UP security policy - Integrity: {}, Confidentiality: {}",
            payload.supi,
            integrity_required,
            confidentiality_required
        );

        Some(crate::types::RefToBinaryData {
            content_id: encoded,
        })
    } else {
        tracing::debug!(
            "No UP security context available for SUPI: {}, N1 response will not include UP security policy",
            payload.supi
        );
        None
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
        eps_pdn_cnx_info: None,
        supported_features: None,
        session_ambr: sm_context.session_ambr.clone(),
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
        dnai_list: None,
        n2_sm_info: Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResSetupReq,
                ngap_data: "base64_encoded_ngap_data".to_string(),
            },
        }),
        n2_sm_info_type: Some(crate::models::N2SmInfoType::PduResSetupReq),
        sm_context_ref: sm_context.id.clone(),
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

    Ok(Json(response))
}

pub async fn retrieve_pdu_session(
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
        "Retrieved PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context.id
    );

    Ok(Json(sm_context))
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
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::ModificationPending).unwrap(),
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let mut new_state = crate::types::SmContextState::Active;
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
                new_state = crate::types::SmContextState::ModificationPending;
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
            "state": mongodb::bson::to_bson(&new_state).unwrap(),
            "an_tunnel_info": mongodb::bson::to_bson(&an_tunnel_info).unwrap(),
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

        update_doc.get_document_mut("$set").unwrap().insert(
            "pdu_address",
            mongodb::bson::to_bson(&new_pdu_address).unwrap()
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

        update_doc.get_document_mut("$set").unwrap().insert(
            "pdu_address",
            mongodb::bson::to_bson(&new_pdu_address).unwrap()
        );
    }

    if let Some(ref ue_location) = payload.ue_location {
        update_doc.get_document_mut("$set").unwrap().insert(
            "ue_location",
            mongodb::bson::to_bson(&ue_location).unwrap()
        );
        tracing::info!(
            "Updated UE location for SUPI: {} during handover",
            sm_context.supi
        );
    }

    if let Some(ref ambr) = effective_ambr {
        update_doc.get_document_mut("$set").unwrap().insert(
            "session_ambr",
            mongodb::bson::to_bson(&ambr).unwrap()
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

    let response = PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n2_sm_info: Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResModifyReq,
                ngap_data: "base64_encoded_path_switch_ack".to_string(),
            },
        }),
        n2_sm_info_type: Some(N2SmInfoType::PathSwitchReqAck),
        eps_bearer_info: None,
        supported_features: None,
        session_ambr: effective_ambr,
        cn_tunnel_info,
        additional_cn_tunnel_info: None,
    };

    tracing::info!(
        "Path switch completed for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(Json(response))
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

    let mut new_state = crate::types::SmContextState::Active;

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::ModificationPending).unwrap(),
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

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
            add_qos_flows.push(qos_flow.clone());
        }

        if !add_qos_flows.is_empty() {
            if let Err(e) = qos_mgr.add_qos_flows(&sm_context_ref, add_qos_flows.clone()).await {
                tracing::warn!("Failed to add QoS flows: {}", e);
            }
        }
    }

    if let Some(ref qos_flows_rel) = payload.qos_flows_rel_request_list {
        for qf_item in qos_flows_rel {
            remove_qfis.push(qf_item.qfi);
        }

        if !remove_qfis.is_empty() {
            if let Err(e) = qos_mgr.remove_qos_flows(&sm_context_ref, remove_qfis.clone()).await {
                tracing::warn!("Failed to remove QoS flows: {}", e);
            }
        }
    }

    if let (Some(ref pfcp_client), Some(seid)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
        let add_flows_opt = if !add_qos_flows.is_empty() { Some(add_qos_flows.as_slice()) } else { None };
        let remove_qfis_opt = if !remove_qfis.is_empty() { Some(remove_qfis.as_slice()) } else { None };

        match PfcpSessionManager::modify_session(pfcp_client, seid, None, add_flows_opt, remove_qfis_opt, sm_context.up_security_context.as_ref()).await {
            Ok(_) => {
                tracing::info!(
                    "PFCP Session modified for SUPI: {}, SEID: {}, State: ModificationPending -> Active",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                new_state = crate::types::SmContextState::ModificationPending;
                tracing::warn!(
                    "Failed to modify PFCP session for SUPI: {}: {}, State remains: ModificationPending",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client or session ID not available, skipping PFCP session modification, State: ModificationPending -> Active");
    }

    let updated_ambr = payload.session_ambr.clone().or(Some(Ambr {
        uplink: "100 Mbps".to_string(),
        downlink: "100 Mbps".to_string(),
    }));

    let update_doc = doc! {
        "$set": {
            "state": mongodb::bson::to_bson(&new_state).unwrap(),
            "updated_at": mongodb::bson::DateTime::now()
        }
    };

    collection
        .update_one(doc! { "_id": &sm_context_ref }, update_doc)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let response = PduSessionUpdatedData {
        n1_sm_info_to_ue: None,
        n2_sm_info: payload.n2_sm_info.or(Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResModifyReq,
                ngap_data: "base64_encoded_ngap_data".to_string(),
            },
        })),
        n2_sm_info_type: payload.n2_sm_info_type.or(Some(crate::models::N2SmInfoType::PduResSetupReq)),
        eps_bearer_info: None,
        supported_features: None,
        session_ambr: updated_ambr,
        cn_tunnel_info: None,
        additional_cn_tunnel_info: None,
    };

    tracing::info!(
        "Updated PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(Json(response))
}

pub async fn release_pdu_session(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<PduSessionReleaseData>,
) -> Result<Json<PduSessionReleasedData>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::InactivePending).unwrap(),
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
                    "PFCP Session deleted for SUPI: {}, SEID: {}, State: InactivePending -> Deleted",
                    sm_context.supi,
                    seid
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to delete PFCP session for SUPI: {}: {}, proceeding with SM Context deletion",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PFCP client or session ID not available, skipping PFCP session deletion, State: InactivePending -> Deleted");
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
                    "Failed to delete SM policy for SUPI: {}: {}, proceeding with SM Context deletion",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("PCF client or policy ID not available, skipping SM policy deletion");
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
                    "Failed to release charging session for SUPI: {}: {}, proceeding with SM Context deletion",
                    sm_context.supi,
                    e
                );
            }
        }
    } else {
        tracing::debug!("CHF client or charging ref not available, skipping charging session release");
    }

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

    if sm_context.ssc_mode == SscMode::Mode1 {
        tracing::info!(
            "SSC Mode 1: Releasing IP address on PDU session termination for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
            sm_context.supi,
            sm_context.pdu_address.as_ref().and_then(|a| a.ipv4_addr.as_ref()),
            sm_context.pdu_address.as_ref().and_then(|a| a.ipv6_addr.as_ref())
        );
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

    let response = PduSessionReleasedData {
        n1_sm_info_to_ue: None,
        n2_sm_info: payload.n2_sm_info.or(Some(N2SmInfo {
            content_id: "n2-sm-info".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResRelCmd,
                ngap_data: "base64_encoded_ngap_data".to_string(),
            },
        })),
        n2_sm_info_type: payload.n2_sm_info_type.or(Some(crate::models::N2SmInfoType::PduResRelCmd)),
    };

    tracing::info!(
        "Released PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref
    );

    Ok(Json(response))
}

#[derive(Debug)]
pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    NotFound(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (status, message).into_response()
    }
}

pub async fn list_ue_pdu_sessions(
    State(state): State<AppState>,
    Path(supi): Path<String>,
) -> Result<Json<Vec<SmContext>>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sessions: Vec<SmContext> = collection
        .find(doc! { "supi": &supi })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .try_collect()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Retrieved {} PDU sessions for SUPI: {}",
        sessions.len(),
        supi
    );

    Ok(Json(sessions))
}

pub async fn retrieve_pdu_session_by_supi(
    State(state): State<AppState>,
    Path((supi, pdu_session_id)): Path<(String, u8)>,
) -> Result<Json<SmContext>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "supi": &supi, "pdu_session_id": pdu_session_id as i32 })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!(
            "SM Context not found for SUPI {} with PDU Session ID {}",
            supi, pdu_session_id
        )))?;

    tracing::info!(
        "Retrieved PDU Session for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        supi,
        pdu_session_id,
        sm_context.id
    );

    Ok(Json(sm_context))
}

pub async fn handle_handover_required(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<HandoverRequiredData>,
) -> Result<Json<HandoverRequiredResponse>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    HandoverService::validate_handover_state(&sm_context.state)
        .map_err(AppError::ValidationError)?;

    AmbrEnforcementService::log_ambr_enforcement(
        &sm_context.supi,
        sm_context.pdu_session_id,
        &sm_context.session_ambr,
        "N2-based handover preparation",
    );

    if sm_context.ssc_mode == SscMode::Mode1 {
        if let Some(ref pdu_addr) = sm_context.pdu_address {
            tracing::info!(
                "SSC Mode 1: IP address will be preserved during handover for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
                sm_context.supi,
                pdu_addr.ipv4_addr,
                pdu_addr.ipv6_addr
            );
        }
    }

    tracing::info!(
        "Handover required notification received for SUPI: {}, PDU Session ID: {}, SM Context: {}, SSC Mode: {}, Target: {:?}",
        sm_context.supi,
        sm_context.pdu_session_id,
        sm_context_ref,
        sm_context.ssc_mode.as_str(),
        payload.target_id.ran_node_id.gnb_id
    );

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::ModificationPending).unwrap(),
                    "handover_state": mongodb::bson::to_bson(&HoState::Preparing).unwrap(),
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    let cn_tunnel_info = if let Some(pfcp_session_id) = sm_context.pfcp_session_id {
        let upf_ipv4 = std::env::var("UPF_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let gtp_teid = format!("{:08x}", pfcp_session_id as u32);

        Some(HandoverService::generate_cn_tunnel_info(&upf_ipv4, &gtp_teid))
    } else {
        None
    };

    tracing::info!(
        "Prepared handover resources for SUPI: {}, CN Tunnel Info: {:?}",
        sm_context.supi,
        cn_tunnel_info
    );

    let response = HandoverRequiredResponse {
        n2_sm_info: Some(N2SmInfo {
            content_id: "n2-ho-required-ack".to_string(),
            n2_info_content: N2InfoContent {
                ngap_ie_type: NgapIeType::PduResSetupReq,
                ngap_data: "base64_encoded_ho_required_ack".to_string(),
            },
        }),
        n2_sm_info_ext1: None,
        ho_state: Some(HoState::Preparing),
        cn_tunnel_info,
        additional_cn_tunnel_info: None,
    };

    tracing::info!(
        "Handover required response prepared for SUPI: {}, HO State: {:?}",
        sm_context.supi,
        response.ho_state
    );

    Ok(Json(response))
}

pub async fn handle_handover_request_ack(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<HandoverRequestAckData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    HandoverService::validate_ho_state_for_request_ack(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover request acknowledgment received for SUPI: {}, PDU Session ID: {}, SM Context: {}",
        sm_context.supi,
        payload.pdu_session_id,
        sm_context_ref
    );

    if payload.pdu_session_id != sm_context.pdu_session_id {
        return Err(AppError::ValidationError(format!(
            "PDU Session ID mismatch: expected {}, got {}",
            sm_context.pdu_session_id,
            payload.pdu_session_id
        )));
    }

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&HoState::Prepared).unwrap(),
        "updated_at": mongodb::bson::DateTime::now()
    };

    let allocated_resources = if let Some(ref n2_sm_info) = payload.n2_sm_info {
        match HandoverService::extract_allocated_handover_resources(&n2_sm_info.n2_info_content.ngap_data) {
            Ok(resources) => {
                tracing::info!(
                    "Handover resource allocation successful for SUPI: {}, Allocated QoS flows: {:?}, Failed QoS flows: {:?}",
                    sm_context.supi,
                    resources.allocated_qos_flow_ids,
                    resources.failed_qos_flow_ids
                );

                let mapping_result = QosFlowMappingService::map_qos_flows_to_target(
                    &sm_context.qos_flows,
                    &resources.allocated_qos_flow_ids,
                    &resources.failed_qos_flow_ids,
                );

                tracing::info!(
                    "QoS flow mapping status for SUPI: {}: {:?}, {}",
                    sm_context.supi,
                    mapping_result.mapping_status,
                    QosFlowMappingService::get_qos_flow_summary(&mapping_result.allocated_flows)
                );

                if !mapping_result.mapping_status.is_acceptable() {
                    tracing::error!(
                        "QoS flow mapping failed for SUPI: {}, status: {:?}",
                        sm_context.supi,
                        mapping_result.mapping_status
                    );
                    return Err(AppError::ValidationError(format!(
                        "QoS flow mapping failed: {:?}. Critical flows could not be allocated at target",
                        mapping_result.mapping_status
                    )));
                }

                update_doc.insert(
                    "an_tunnel_info",
                    mongodb::bson::to_bson(&resources.target_tunnel_info).unwrap(),
                );

                if !mapping_result.allocated_flows.is_empty() {
                    update_doc.insert(
                        "qos_flows",
                        mongodb::bson::to_bson(&mapping_result.allocated_flows).unwrap(),
                    );
                    tracing::info!(
                        "Updated QoS flows for SUPI: {} to reflect allocated resources: {:?}",
                        sm_context.supi,
                        mapping_result.allocated_flows.iter().map(|qf| qf.qfi).collect::<Vec<_>>()
                    );
                }

                if resources.security_activated {
                    tracing::info!(
                        "User plane security activated at target for SUPI: {}",
                        sm_context.supi
                    );
                }

                Some(resources)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to extract allocated handover resources for SUPI: {}: {}, continuing without resource coordination",
                    sm_context.supi,
                    e
                );
                None
            }
        }
    } else {
        tracing::debug!(
            "No N2 SM info provided in handover request ack for SUPI: {}, skipping resource extraction",
            sm_context.supi
        );
        None
    };

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Handover state updated to Prepared for SUPI: {}, PDU Session ID: {}, Resources allocated: {}",
        sm_context.supi,
        sm_context.pdu_session_id,
        allocated_resources.is_some()
    );

    Ok(Json(serde_json::json!({
        "status": "success",
        "handoverState": "PREPARED",
        "allocatedQosFlows": allocated_resources.as_ref().map(|r| &r.allocated_qos_flow_ids),
        "failedQosFlows": allocated_resources.as_ref().map(|r| &r.failed_qos_flow_ids),
        "securityActivated": allocated_resources.as_ref().map(|r| r.security_activated).unwrap_or(false)
    })))
}

pub async fn handle_handover_notify(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<HandoverNotifyData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    HandoverService::validate_ho_state_for_notify(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    AmbrEnforcementService::log_ambr_enforcement(
        &sm_context.supi,
        sm_context.pdu_session_id,
        &sm_context.session_ambr,
        "N2-based handover completion",
    );

    tracing::info!(
        "Handover notify received for SUPI: {}, PDU Session ID: {}, SM Context: {}, HO State: {:?}",
        sm_context.supi,
        payload.pdu_session_id,
        sm_context_ref,
        payload.ho_state
    );

    if payload.pdu_session_id != sm_context.pdu_session_id {
        return Err(AppError::ValidationError(format!(
            "PDU Session ID mismatch: expected {}, got {}",
            sm_context.pdu_session_id,
            payload.pdu_session_id
        )));
    }

    let mut update_doc = doc! {
        "handover_state": mongodb::bson::to_bson(&payload.ho_state).unwrap(),
        "updated_at": mongodb::bson::DateTime::now()
    };

    if matches!(payload.ho_state, HoState::Completed) {
        if sm_context.ssc_mode == SscMode::Mode1 {
            if let Some(ref existing_pdu_addr) = sm_context.pdu_address {
                SscBehaviorService::validate_handover_ip_behavior(
                    &sm_context.ssc_mode,
                    existing_pdu_addr,
                    None,
                ).map_err(AppError::ValidationError)?;

                tracing::info!(
                    "SSC Mode 1 handover completed: IP address preserved for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
                    sm_context.supi,
                    existing_pdu_addr.ipv4_addr,
                    existing_pdu_addr.ipv6_addr
                );
            }
        } else if sm_context.ssc_mode == SscMode::Mode2 {
            tracing::info!(
                "SSC Mode 2 handover: Releasing old session and establishing new session for SUPI: {}, PDU Session ID: {}",
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
                "SSC Mode 2 handover completed: New address allocated for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
                sm_context.supi,
                new_pdu_address.ipv4_addr,
                new_pdu_address.ipv6_addr
            );

            update_doc.insert(
                "pdu_address",
                mongodb::bson::to_bson(&new_pdu_address).unwrap(),
            );
        } else if sm_context.ssc_mode == SscMode::Mode3 {
            tracing::info!(
                "SSC Mode 3 handover: Make-before-break for SUPI: {}, PDU Session ID: {}",
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
                "SSC Mode 3 handover completed: New address allocated (make-before-break) for SUPI: {}, IPv4: {:?}, IPv6: {:?}",
                sm_context.supi,
                new_pdu_address.ipv4_addr,
                new_pdu_address.ipv6_addr
            );

            update_doc.insert(
                "pdu_address",
                mongodb::bson::to_bson(&new_pdu_address).unwrap(),
            );
        }

        update_doc.insert(
            "state",
            mongodb::bson::to_bson(&crate::types::SmContextState::Active).unwrap(),
        );

        if let Some(ref an_tunnel_info) = payload.an_tunnel_info {
            update_doc.insert(
                "an_tunnel_info",
                mongodb::bson::to_bson(an_tunnel_info).unwrap(),
            );

            if let (Some(ref pfcp_client), Some(pfcp_session_id)) = (&state.pfcp_client, sm_context.pfcp_session_id) {
                tracing::info!(
                    "Updating PFCP session for SUPI: {}, PFCP Session ID: {}",
                    sm_context.supi,
                    pfcp_session_id
                );

                if let Some(an_ipv4_str) = an_tunnel_info.ipv4_addr.as_ref() {
                    if let Ok(an_ipv4) = an_ipv4_str.parse() {
                        if let Err(e) = PfcpSessionManager::modify_session_for_handover(
                            pfcp_client,
                            pfcp_session_id,
                            an_ipv4,
                            &an_tunnel_info.gtp_teid,
                            sm_context.up_security_context.as_ref(),
                        ).await {
                            tracing::error!("Failed to modify PFCP session: {}", e);
                        }
                    } else {
                        tracing::error!("Invalid AN IPv4 address: {}", an_ipv4_str);
                    }
                }
            }
        }

        if let Some(ref ue_location) = payload.ue_location {
            update_doc.insert(
                "ue_location",
                mongodb::bson::to_bson(ue_location).unwrap(),
            );
        }

        let updated_sm_context = collection
            .find_one(doc! { "_id": &sm_context_ref })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

        let continuity_check = QosFlowMappingService::check_qos_flow_continuity(
            &sm_context.supi,
            sm_context.pdu_session_id,
            &sm_context.qos_flows,
            &updated_sm_context.qos_flows,
        );

        if !continuity_check.continuity_status.is_acceptable() {
            tracing::error!(
                "QoS flow continuity check failed for SUPI: {}, PDU Session ID: {}, status: {:?}",
                sm_context.supi,
                sm_context.pdu_session_id,
                continuity_check.continuity_status
            );
            return Err(AppError::ValidationError(format!(
                "QoS flow continuity interrupted: {:?}. Missing flows: {:?}",
                continuity_check.continuity_status,
                continuity_check.missing_flows
            )));
        }

        tracing::info!(
            "QoS flow continuity maintained for SUPI: {}, PDU Session ID: {}: {}",
            sm_context.supi,
            sm_context.pdu_session_id,
            QosFlowMappingService::get_qos_flow_summary(&updated_sm_context.qos_flows)
        );

        tracing::info!(
            "Handover completed for SUPI: {}, PDU Session ID: {}, UE Location: {:?}",
            sm_context.supi,
            sm_context.pdu_session_id,
            payload.ue_location
        );
    } else if matches!(payload.ho_state, HoState::Cancelled) {
        update_doc.insert(
            "state",
            mongodb::bson::to_bson(&crate::types::SmContextState::Active).unwrap(),
        );

        tracing::info!(
            "Handover cancelled for SUPI: {}, PDU Session ID: {}, reverting to Active state",
            sm_context.supi,
            sm_context.pdu_session_id
        );
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! { "$set": update_doc }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Handover state updated for SUPI: {}, PDU Session ID: {}, Final HO State: {:?}",
        sm_context.supi,
        sm_context.pdu_session_id,
        payload.ho_state
    );

    Ok(Json(serde_json::json!({
        "status": "success",
        "handoverState": format!("{:?}", payload.ho_state).to_uppercase()
    })))
}

pub async fn handle_handover_cancel(
    State(state): State<AppState>,
    Path(sm_context_ref): Path<String>,
    Json(payload): Json<HandoverCancelData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let collection: Collection<SmContext> = state.db.collection("sm_contexts");

    let sm_context = collection
        .find_one(doc! { "_id": &sm_context_ref })
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("SM Context {} not found", sm_context_ref)))?;

    HandoverService::validate_ho_state_for_cancel(&sm_context.handover_state)
        .map_err(AppError::ValidationError)?;

    tracing::info!(
        "Handover cancel received for SUPI: {}, PDU Session ID: {}, SM Context: {}, Cause: {:?}",
        sm_context.supi,
        payload.pdu_session_id,
        sm_context_ref,
        payload.cause
    );

    if payload.pdu_session_id != sm_context.pdu_session_id {
        return Err(AppError::ValidationError(format!(
            "PDU Session ID mismatch: expected {}, got {}",
            sm_context.pdu_session_id,
            payload.pdu_session_id
        )));
    }

    collection
        .update_one(
            doc! { "_id": &sm_context_ref },
            doc! {
                "$set": {
                    "state": mongodb::bson::to_bson(&crate::types::SmContextState::Active).unwrap(),
                    "handover_state": mongodb::bson::to_bson(&HoState::Cancelled).unwrap(),
                    "updated_at": mongodb::bson::DateTime::now()
                }
            }
        )
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Handover cancelled for SUPI: {}, PDU Session ID: {}, reverting to Active state, Cause: {:?}",
        sm_context.supi,
        sm_context.pdu_session_id,
        payload.cause
    );

    Ok(Json(serde_json::json!({
        "status": "success",
        "handoverState": "CANCELLED",
        "cause": format!("{:?}", payload.cause).to_uppercase()
    })))
}
