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
- Session state management and persistence
- Multi-PDU session per UE support
- Session continuity and mobility (handover procedures)
- Service and Session Continuity (SSC) modes (1/2/3)
- Emergency services PDU session establishment

### IP & Network Configuration
- DNS configuration delivery to UEs
- MTU configuration
- IPv4 and IPv6 dual-stack support

### QoS & Traffic Management
- QoS flow management
- QoS rule enforcement
- Packet filter management
- Network slice selection

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