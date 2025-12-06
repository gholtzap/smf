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
CHF_URI=http://localhost:8003
NF_INSTANCE_ID=
SMF_HOST=127.0.0.1
OAUTH2_ENABLED=false
OAUTH2_ISSUER=
OAUTH2_AUDIENCE=
OAUTH2_REQUIRED_SCOPE=
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
- UDR client implementation (HTTP client for Nudr service endpoints)
  - UDR client data models for Nudr_DataRepository (Session Management Subscription Data, SMF Selection Data)
  - UDR client HTTP implementation with error handling
  - SM subscription data retrieval endpoint (GET /nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{snssai})
  - SM subscription data creation endpoint (PUT /nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{snssai})
  - SM subscription data update endpoint (PATCH /nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{snssai})
  - SM subscription data deletion endpoint (DELETE /nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{snssai})
  - SMF selection subscription data retrieval endpoint (GET /nudr-dr/v2/subscription-data/{supi}/context-data/smf-selection-subscription-data)
  - SMF selection subscription data creation endpoint (PUT /nudr-dr/v2/subscription-data/{supi}/context-data/smf-selection-subscription-data)
  - Comprehensive data models for DNN configurations, QoS profiles, SSC modes, UE behavior, and geographic areas
  - Support for query parameters (DNN, PLMN ID)
- UDR integration for direct data repository access
  - UDR discovery via NRF service discovery
  - UDR client initialization with NRF-based discovery
  - Direct data repository access for session management subscription data
  - SMF selection subscription data access
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
- CHF client implementation (HTTP client for Nchf service endpoints)
  - CHF client data models for Nchf_ConvergedCharging (Converged Charging)
  - Charging data models (ChargingDataRequest, ChargingDataResponse, PduSessionChargingInformation)
  - CHF client HTTP implementation with error handling
  - Charging session creation endpoint (POST /nchf-convergedcharging/v3/chargingdata)
  - Charging session update endpoint (POST /nchf-convergedcharging/v3/chargingdata/{ChargingDataRef}/update)
  - Charging session release endpoint (POST /nchf-convergedcharging/v3/chargingdata/{ChargingDataRef}/release)
  - Integration with PDU session create and release handlers
  - Charging reference tracking in SM context
  - Support for usage reporting, quota management, and trigger-based charging
  - Comprehensive data models for rating groups, QoS information, and location data
- AMF callback endpoints for N1/N2 messaging
  - N1N2 message transfer status notification endpoint (POST /namf-callback/v1/ue-contexts/{ueId}/n1-n2-transfers/{transactionId}/notify)
  - N2 information notification endpoint (POST /namf-callback/v1/sm-contexts/{ueId}/pdu-sessions/{pduSessionId}/n2-notify)
  - N1 message container handling (NAS messages)
  - N2 message container handling (NGAP messages)
  - Support for PDU resource setup, modify, release responses and failures
  - Support for path switch and handover notifications
  - Status notification processing with cause indication

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
- Emergency services PDU session establishment
  - Emergency request type detection (InitialEmergencyRequest, ExistingEmergencyPduSession)
  - Emergency DNN validation (sos, emergency, ims-emergency)
  - High-priority QoS assignment for emergency sessions (5QI 5)
  - Support for unauthenticated SUPI in emergency scenarios
  - Emergency session tracking in SM context
  - Automatic emergency service authorization

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

### Slice-specific QoS Policies
- Slice-specific QoS policy framework with comprehensive policy types
  - Per-slice default QoS flow configurations (5QI, priority, delay budget, error rate)
  - Additional QoS flow configurations per slice
  - Slice-specific QoS flow type enforcement (GBR, non-GBR, delay-GBR)
  - Slice-specific preemption capability and vulnerability settings
  - Maximum QoS flows per slice configuration
- Slice QoS policy service for policy management
  - Default policies for standard slices (eMBB, URLLC, MIoT, eMBB-Premium)
  - Policy-based QoS flow creation with slice-specific parameters
  - QoS flow validation against slice policies
  - Priority level assignment per slice
- Integration with PDU session management
  - Automatic slice-specific QoS application during PDU session creation
  - Slice-specific QoS enforcement during PDU session updates
  - QoS flow creation aligned with slice policies
  - Priority and QoS parameter inheritance from slice configuration

### Security
- OAuth2 authentication for SBI:
  - OAuth2 token validation middleware
    - JWT token parsing and validation
    - Token expiration checking
    - Bearer token authentication support
    - Request extension for validated tokens
    - Configurable OAuth2 settings (issuer, audience, scope)
    - Environment-based configuration (OAUTH2_ENABLED, OAUTH2_ISSUER, OAUTH2_AUDIENCE, OAUTH2_REQUIRED_SCOPE)
    - Protected and public route separation
    - Conditional middleware application
  - NRF OAuth2 token endpoint integration
    - OAuth2 token client for requesting access tokens
    - Support for client_credentials grant type
    - NF instance ID and type identification in token requests
    - Target NF type specification for service-specific tokens
    - Custom scope support for fine-grained access control
  - Access token caching and refresh logic
    - Token cache with expiration tracking
    - Automatic token refresh with configurable buffer time (default 300 seconds)
    - Per-target and per-scope token caching
    - Token invalidation and cache management
    - Thread-safe token storage using Arc and RwLock
  - Token-based authentication for outbound NF requests
    - OAuth2RequestBuilder for attaching bearer tokens to HTTP requests
    - OAuth2ClientExt trait for seamless integration with reqwest
    - Automatic token acquisition and attachment to outbound requests
    - Support for NRF, UDM, PCF, and CHF client authentication
    - Optional OAuth2 authentication per client instance
    - Service-specific scope selection (nnrf-nfm, nudm-sdm, npcf-smpolicycontrol, nchf-convergedcharging)

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
  - Handover cancellation and failure handling
  - Handover state validation for cancellation (Preparing/Prepared states)
  - Handover cancel cause support (HO_TARGET_NOT_ALLOWED, HO_TARGET_BECOMING_RICH, HO_TARGET_NOT_REACHABLE, HO_FAILURE_IN_TARGET_SYSTEM, HO_CANCELLED)
  - SM context state restoration to Active on cancellation
  - Handover cancel endpoint (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/handover-cancel)

## NOT IMPLEMENTED FEATURES

### PDU Session Management (TS 29.502)
- PDU Session Transfer: Inter-SMF session transfer endpoints

### NIDD Service (TS 29.542)
- NIDD endpoints (TS 29.542)

### Data Models & Types
- 3GPP data models and types
- Session context structures
- Network slice selection data

### Session Management
- Session continuity and mobility (handover procedures):
  - N2-based handover completion:
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

### Security
- Service-based interface security:
  - TLS configuration for HTTP server
  - Certificate management
  - Mutual TLS (mTLS) support
- User plane encryption and integrity protection:
  - UP security policy negotiation
  - Encryption algorithm selection (NEA0, NEA1, NEA2, NEA3)
  - Integrity algorithm selection (NIA0, NIA1, NIA2, NIA3)
- Authorization and access control:
  - NF authorization policy framework
  - Resource-based access control
  - Scope validation for OAuth2 tokens

### Advanced Features
- Local breakout and MEC support
- Roaming support (home/visited SMF coordination)
- 4G/5G interworking (EPS interworking)
- Lawful intercept interfaces
- NEF integration for external API exposure