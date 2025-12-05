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
- UDM/UDR integration for subscriber data retrieval
- PCF integration for policy control
- CHF integration for charging

### Session Management
- Session continuity and mobility (handover procedures)
- Service and Session Continuity (SSC) modes (1/2/3)
- Emergency services PDU session establishment

### IP & Network Configuration
- DNS configuration delivery to UEs
- MTU configuration
- IPv4 and IPv6 dual-stack support

### QoS & Traffic Management
- QoS Rule Enforcement
  - QoS rule creation with precedence and priority
  - QoS rule application to PDU sessions
  - Dynamic QoS rule updates
- Network Slice Selection
  - S-NSSAI based slice selection
  - DNN (Data Network Name) based routing
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