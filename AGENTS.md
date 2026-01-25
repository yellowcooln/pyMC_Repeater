# AGENTS.md

This file documents the manual changes made to integrate pyMC_Repeater with Home Assistant’s meshcore-ha using a MeshCore TCP bridge.

## Summary
A MeshCore TCP bridge was added so meshcore-ha can connect to pyMC_Repeater via TCP without modifying HA. The bridge:
- Implements MeshCore TCP framing and essential commands.
- Responds to MeshCore protocol queries (appstart, device info, contacts, status, telemetry, etc.).
- Transmits actual RF packets for login/logout, status, telemetry, and path discovery/reset.
- Decrypts RF protocol responses and forwards them back to HA over TCP.

## Files Added/Modified

### New
- `repeater/meshcore_bridge.py`
  - TCP server that emulates MeshCore protocol for meshcore-ha.
  - Generates SELF_INFO, DEVICE_INFO, CONTACTS, STATUS_RESPONSE, TELEMETRY_RESPONSE, LOGIN_SUCCESS, etc.
  - Injects real RF packets using `pymc_core` for:
    - Login / logout
    - Status request
    - Telemetry request
    - Path discovery / reset path (best-effort trace)
  - Decrypts RF protocol responses (PAYLOAD_TYPE_RESPONSE / PATH) and forwards to HA.

### Modified
- `repeater/main.py`
  - Starts/stops the MeshCore TCP bridge based on config.
- `repeater/packet_router.py`
  - Routes RF response packets to the bridge for decryption/forwarding.
- `config.yaml.example`
  - Adds `meshcore_bridge` configuration block.

## Config
Add this to `/etc/pymc_repeater/config.yaml`:
```yaml
meshcore_bridge:
  enabled: true
  host: "0.0.0.0"
  port: 5000
```
Use a different port if your UI is not on 8000 or if 5000 is in use.

## MeshCore TCP Bridge Behavior

### Implemented commands
- `send_appstart` → `SELF_INFO`
- `device_query` → `DEVICE_INFO`
- `get_contacts` → contacts from pyMC neighbor DB
- `send_login` → `MSG_SENT` + `LOGIN_SUCCESS` (and RF login packet)
- `send_logout` → `MSG_SENT` (and RF logout packet)
- `send_statusreq` and `binary_req(STATUS)` → `MSG_SENT`, RF status request, and TCP status response
- `get_self_telemetry` and `binary_req(TELEMETRY)` → `MSG_SENT`, RF telemetry request, and TCP telemetry response
- `set_other_params` → `OK`
- `reset_path` → `OK` (and RF trace packet)
- `path_discovery` → `MSG_SENT` (and RF trace packet)
- `get_time`, `set_time`, `get_bat`, `get_msg`, `send_advert` → basic responses

### RF injection
RF packets are sent using `pymc_core.protocol.PacketBuilder` and `Dispatcher.send_packet`.

### RF response forwarding
The bridge:
- Intercepts PAYLOAD_TYPE_RESPONSE/PATH packets.
- Decrypts them using shared secret.
- For status: converts pyMC’s 58-byte stats struct into MeshCore’s expected format.
- For telemetry: forwards the CayenneLPP payload to HA.

## Known limitations
- Path discovery/reset uses trace packets as best-effort.
- Some MeshCore admin/config commands are ACK-only (no device config changes).
- Contact list depends on pyMC neighbor DB; it may be empty on fresh setups.

## Commits (tcp-bridge branch)
- `Add MeshCore TCP bridge for HA compatibility`
- `Handle string contact types in MeshCore bridge`
- `Emit login success for MeshCore bridge`
- `Delay binary responses for pending request registration`
- `Handle set_other_params command in MeshCore bridge`
- `Inject RF packets for HA repeater commands`
- `Forward RF protocol responses to HA over TCP`

## Usage in HA
Use meshcore-ha TCP mode and point it to the bridge host/port.
