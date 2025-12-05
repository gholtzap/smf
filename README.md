# 5G SMF (Session Management Function)

A 5G Session Management Function implementation in Rust, following 3GPP specifications.

## Overview

This SMF implementation supports the following 3GPP service interfaces:
- **Nsmf_PDUSession**: PDU Session management (TS 29.502)
- **Nsmf_EventExposure**: Event exposure service (TS 29.508)
- **Nsmf_NIDD**: Non-IP Data Delivery (TS 29.542)

## Configuration

Create a `.env` file with the following variables:

```
PORT=8080
MONGODB_URI=mongodb://localhost:27017
UPF_HOST=127.0.0.1
UPF_PORT=8805
PFCP_BIND_ADDR=0.0.0.0
PFCP_BIND_PORT=8805
NRF_URI=http://localhost:8000
PCF_URI=http://localhost:8001
UDM_URI=http://localhost:8002
NF_INSTANCE_ID=
SMF_HOST=127.0.0.1
```

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run
```

The server will start on `http://localhost:8080` by default.

## IMPLEMENTED FEATURES

### PDU Session Management (TS 29.502)
- PDU Session Create: SM Context creation endpoint (POST /nsmf-pdusession/v1/sm-contexts)
- PDU Session Retrieve: SM Context retrieval endpoint (GET /nsmf-pdusession/v1/sm-contexts/{smContextRef})
- PDU Session Update: SM Context modification endpoint (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify)
- PDU Session Release: SM Context release endpoint (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/release)

### Event Exposure Service (TS 29.508)
- Event subscription creation endpoint (POST /nsmf-event-exposure/v1/subscriptions)
- Event subscription update endpoint (PUT /nsmf-event-exposure/v1/subscriptions/{subscriptionId})
- Event subscription deletion endpoint (DELETE /nsmf-event-exposure/v1/subscriptions/{subscriptionId})
- Event notification data models and types (EventNotification, EventReport, PduSessionEventInfo, Cause)
- PDU session event notifications (UE IP change and PDU session release events)

### Network Function Integration - N4 Interface (PFCP with UPF)
- PFCP message data models (Session Establishment Request/Response, Modification, Deletion)
- PFCP client implementation for UDP communication with UPF
- PFCP session lifecycle management
- Integration with PDU session create/update/release handlers

### IP & Network Configuration
- IP Address Management (IPAM) for PDU sessions
  - Dynamic IP allocation from configurable pools
  - Default pool: 10.60.0.0/16 with DNS servers (8.8.8.8, 8.8.4.4)
  - IP allocation tracking in MongoDB
  - Automatic IP release on session termination
- DNS configuration delivery to UEs
  - Primary and secondary DNS server configuration in IP pools
  - DNS server addresses included in PDU session creation response
  - DNS configuration stored in PDU address structure
  - Automatic DNS propagation from IPAM to UE
- IPv4 and IPv6 dual-stack support
  - IPv4-only PDU sessions (PduSessionType::Ipv4)
  - IPv6-only PDU sessions (PduSessionType::Ipv6)
  - Dual-stack PDU sessions (PduSessionType::Ipv4v6)
  - IPv6 prefix delegation (/64 subnets from configurable pools)
  - Default IPv6 pool: 2001:db8::/32 with DNS servers (2001:4860:4860::8888, 2001:4860:4860::8844)
  - IPv6 prefix allocation tracking in MongoDB
  - Automatic IPv6 prefix release on session termination
  - PDU session type selection based on UE request
  - IPv6 gateway and DNS configuration per pool

### UPF Health Monitoring
- UPF node discovery and health monitoring
  - Periodic heartbeat requests (30 second intervals)
  - PFCP association setup and management
  - UPF status tracking in MongoDB (Active/Inactive/Unknown)
  - Automatic failure detection and status updates
  - Consecutive failure counting with configurable threshold

### Network Function Integration - N4 Interface (NRF)
- NRF client implementation (Nnrf service endpoints)
  - NFProfile registration and deregistration
  - NF service discovery (Nnrf_NFDiscovery)
  - NF management (Nnrf_NFManagement)
  - Subscription to NF status changes
  - Heartbeat mechanism for keep-alive
  - Support for querying NF instances by type and filters
- NRF integration for service registration
  - SMF service profile creation and registration
  - Automatic registration on startup
  - Periodic heartbeat mechanism (60 second intervals)
  - Graceful deregistration on shutdown
  - NFService advertisement for nsmf-pdusession and nsmf-event-exposure
  - SMF-specific info including S-NSSAI and DNN support
- NRF integration for service discovery
  - Service discovery for other NFs (AMF, PCF, UDM, UPF, UDR, CHF)
  - Discovered NF instance caching
  - Subscription to NF status change notifications
  - Automatic cache updates on NF registration/deregistration/profile changes
  - NF status notification callback endpoint
- AMF discovery and selection
  - AMF discovery via NRF with query parameters (S-NSSAI, PLMN ID, TAI)
  - AMF selection based on multiple criteria (S-NSSAI, TAI, GUAMI, priority, capacity, load)
  - AMF info data models (GUAMI list, TAI list, TAI range list, backup AMF info)
  - Scoring algorithm for optimal AMF selection
  - Support for selecting single or multiple AMF instances
  - Filtering by NF status (registered/suspended/undiscoverable)
  - TAI and TAI range matching for location-based selection
  - Service URI extraction from NFProfile and NFService
- AMF client implementation (HTTP client for Namf service endpoints)
  - AMF client with support for N1N2 message transfer operations
  - N1N2MessageTransfer endpoint support (POST /namf-comm/v1/ue-contexts/{ueId}/n1-n2-messages)
  - N1N2MessageTransfer status query (GET /namf-comm/v1/ue-contexts/{ueId}/n1-n2-messages/{transactionId})
  - UE context transfer support (POST /namf-comm/v1/ue-contexts/{ueId}/transfer)
  - UE context release support (DELETE /namf-comm/v1/ue-contexts/{ueId})
  - N2 info notification callback support
  - Multipart message handling for N1/N2 binary data
  - N1 message container types (SM, LPP, SMS, UPDP classes)
  - N2 information container types (SM, NRPPA, PWS classes)
  - UE context transfer types with access type and mobility registration support
- UDM client implementation (HTTP client for Nudm service endpoints)
  - UDM client data models for Nudm_SDM (Session Management Subscription Data)
  - UDM client data models for Nudm_UECM (UE Context Management)
  - UDM client HTTP implementation with error handling
  - SM subscription data retrieval endpoint (GET /nudm-sdm/v2/{supi}/sm-data)
  - SDM subscription creation endpoint (POST /nudm-sdm/v2/{supi}/sdm-subscriptions)
  - SDM subscription modification endpoint (PUT /nudm-sdm/v2/{supi}/sdm-subscriptions/{subscriptionId})
  - SDM subscription deletion endpoint (DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{subscriptionId})
  - Session management subscription data types (DNN configurations, QoS profiles, AMBR, SSC modes)
  - Support for query parameters (S-NSSAI, DNN, PLMN ID)
- UDM integration for subscriber data retrieval
  - UDM discovery via NRF service discovery
  - Integration with PDU session creation flow for subscriber validation
  - Subscriber authorization validation for DNN access
  - Subscriber-specific QoS profile (5QI) application from UDM data
  - Subscriber-specific session AMBR (uplink/downlink bit rates) from UDM data
  - DNN configuration validation against subscriber's allowed DNNs
  - SSC mode validation from subscriber data
  - Automatic fallback to DNN and slice defaults when UDM unavailable
- PCF client implementation (HTTP client for Npcf service endpoints)
  - PCF client data models for Npcf_SMPolicyControl (SM Policy Control)
  - SM policy context data models (SmPolicyContextData, SmPolicyUpdateContextData)
  - SM policy decision data models (SmPolicyDecision, PccRule, QosData, ChargingData)
  - PCF client HTTP implementation with error handling
  - SM policy creation endpoint (POST /npcf-smpolicycontrol/v1/sm-policies)
  - SM policy update endpoint (POST /npcf-smpolicycontrol/v1/sm-policies/{policyId}/update)
  - SM policy deletion endpoint (POST /npcf-smpolicycontrol/v1/sm-policies/{policyId}/delete)
  - SM policy retrieval endpoint (GET /npcf-smpolicycontrol/v1/sm-policies/{policyId})
  - Integration with PDU session create and release handlers
  - Policy ID tracking in SM context
  - Support for PCC rules, QoS data, charging data, and traffic control data
  - Comprehensive data models for session rules, flow information, and policy triggers

### SSC Mode Management
- SSC mode selection and validation framework
  - SSC mode type definitions (Mode 1, Mode 2, Mode 3)
  - SSC mode selector service with configuration support
  - SSC mode validation based on UE request, subscriber data, and network policy
  - Default SSC mode selection with fallback logic
  - SSC mode persistence in SM context
  - SSC mode delivery in PDU session creation response
  - Integration with UDM subscriber data for allowed SSC modes
  - Conversion support between UDM and SMF SSC mode representations

### Session Management
- Session state transitions with proper state machine (Idle, ActivePending, Active, InactivePending, Inactive, ModificationPending)
  - ActivePending -> Active transition during PDU session creation after PFCP session establishment
  - Active -> ModificationPending -> Active transitions during PDU session updates
  - Active -> InactivePending transition during PDU session release
- Multi-PDU session per UE support
  - Unique constraint on (SUPI, PDU Session ID) to prevent duplicates
  - Validation on PDU session creation to reject duplicate session IDs
  - List all PDU sessions for a UE endpoint (GET /nsmf-pdusession/v1/ue-contexts/{supi}/sm-contexts)
  - Retrieve PDU session by SUPI and PDU Session ID endpoint (GET /nsmf-pdusession/v1/ue-contexts/{supi}/sm-contexts/{pduSessionId})
  - MongoDB index optimization for session lookups by SUPI

### QoS & Traffic Management
- QoS Flow Management
  - QoS flow creation with QFI (QoS Flow Identifier) assignment
  - QoS flow modification (add/modify/delete flows)
  - QoS flow to PFCP QER (QoS Enforcement Rule) mapping
  - 5QI (5G QoS Identifier) handling with standardized QoS profiles (5QI 1-9, 65-67, 69-70, 79-80)
  - GBR (Guaranteed Bit Rate) and non-GBR flow support
  - Default QoS flow (5QI 9) automatically assigned to new PDU sessions
  - QoS flow validation (QFI range 0-63, bit rate validation, flow type enforcement)
  - Integration with PDU session create and update handlers
- Packet Filter Management
  - Packet filter creation and parsing
  - SDF (Service Data Flow) template matching
  - Flow description parsing (IP 5-tuple)
  - Uplink and downlink packet filter direction handling
  - Packet filter CRUD operations (add/modify/delete/get)
  - Packet filter validation (ID, precedence, components, QFI)
  - IPv4 and IPv6 address filtering with masks and prefix lengths
  - Port filtering (single port and port ranges)
  - Protocol identifier filtering
  - Type of Service (TOS) and flow label filtering
  - SDF template to packet filter conversion endpoints
  - Integration with PDU session management
- QoS Rule Enforcement
  - QoS rule creation with precedence and priority
  - QoS rule application to PDU sessions
  - Dynamic QoS rule updates
  - QoS rule to QoS flow and packet filter mapping
  - Default QoS rule automatically assigned to new PDU sessions
  - QoS rule validation (precedence, QFI, packet filter references)
  - Rule operation codes (create, delete, modify)
  - CRUD operations for QoS rules (add/modify/delete/get)
  - QoS rule application endpoint for enforcement
  - Integration with PDU session management
- S-NSSAI based slice selection
  - Network slice configuration with SST and SD values
  - Pre-configured slice profiles (eMBB, URLLC, MIoT, eMBB-Premium)
  - S-NSSAI validation during PDU session creation
  - Slice-specific QoS profiles (5QI assignment per slice)
  - Slice-specific session AMBR (uplink/downlink bit rates)
  - Slice-specific IP pool assignment
  - Allowed slice list enforcement
  - Automatic slice selection and configuration application
- DNN (Data Network Name) based routing
  - DNN configuration with description and routing parameters
  - Pre-configured DNN profiles (internet, ims, edge)
  - DNN validation during PDU session creation
  - DNN-specific IP pool assignment
  - DNN-specific session AMBR (uplink/downlink bit rates)
  - DNN-specific QoS profiles (5QI assignment per DNN)
  - DNN-specific MTU configuration
  - DNN priority-based selection
  - Allowed DNN list enforcement
  - Integration with slice-based configuration

### MTU Configuration
- MTU configuration per DNN (configurable in DNN profiles)
- MTU configuration per IP pool (configurable in IP pool settings)
- MTU value included in PDU session creation response
- MTU value stored in SM context
- Default MTU value of 1500 bytes
- MTU propagation from IP pool or DNN to UE

### Mobility & Handover
- Xn-based intra-SMF handover (gNB-to-gNB with same SMF)
  - Path switch request detection and processing
  - AN tunnel information extraction and storage
  - UE location tracking during handover
  - PFCP session modification for tunnel endpoint updates
  - CN tunnel information generation for target gNB
  - State validation for handover eligibility
  - Path switch acknowledgment with N2 SM info
  - Integration with PDU session update handler
- N2-based handover
  - Handover required notification handling from source AMF
  - Target identification and validation (gNB ID, TAI)
  - SM context state transition to ModificationPending
  - CN tunnel information generation for target system
  - N2 SM information container preparation
  - Handover state tracking (None, Preparing, Prepared, Completed, Cancelled)
  - Direct forwarding path availability indication
  - Handover required response endpoint (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/handover-required)
  - Handover request acknowledgment processing
  - Handover state validation for request acknowledgment
  - PDU session ID validation in acknowledgment
  - Handover state update from Preparing to Prepared
  - Handover request acknowledgment endpoint (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/handover-request-ack)
  - Handover notify handling for completion confirmation
  - Handover completion state processing (HO state Completed/Cancelled)
  - AN tunnel information update during handover completion
  - UE location tracking update during handover completion
  - PFCP session modification during handover completion
  - SM context state restoration on handover completion
  - Handover notify endpoint (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/handover-notify)

## NOT IMPLEMENTED FEATURES

### PDU Session Management (TS 29.502)
- PDU Session Transfer: Inter-SMF session transfer endpoints

### NIDD Service (TS 29.542)
- NIDD endpoints (TS 29.542)

### Data Models & Types
- 3GPP data models and types
- Session context structures
- Network slice selection data

### Network Function Integration - Other NFs
- AMF communication (Namf callbacks) for N1/N2 messaging
  - N1 message container handling (NAS messages)
  - N2 message container handling (NGAP messages)
  - N1N2MessageTransfer endpoint implementation
  - AMF callback endpoints for N1/N2 message delivery
- UDR client integration for direct data access
  - UDR client data models (Nudr_DataRepository)
  - UDR client HTTP implementation
  - UDR discovery via NRF
  - Direct UDR data access endpoints
- CHF integration for charging

### Session Management
- Session continuity and mobility (handover procedures):
  - N2-based handover completion:
    - Handover cancellation and failure handling
    - N2 SM information extraction and processing during handover
    - Handover resource allocation coordination with target gNB
    - UE context transfer request/response between SMFs
  - Inter-SMF handover (SMF relocation during handover)
  - UPF relocation and selection during handover
  - QoS flow mapping and continuity during handover
  - Session AMBR enforcement during handover
- Service and Session Continuity (SSC) mode behavior:
  - SSC mode 1: IP address preservation during mobility
  - SSC mode 2: Session release and re-establishment logic
  - SSC mode 3: Make-before-break session establishment logic
- Emergency services PDU session establishment

### QoS & Traffic Management
- Slice-specific QoS policies

### Security
- OAuth2 authentication for SBI
- Service-based interface security
- User plane encryption and integrity protection
- Authorization and access control

### Advanced Features
- Local breakout and MEC support
- Roaming support (home/visited SMF coordination)
- 4G/5G interworking (EPS interworking)
- Lawful intercept interfaces
- NEF integration for external API exposure