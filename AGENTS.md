# Relay Companion Whitelist Feature

This file tracks the relay companion whitelist feature only.

## What Exists

- Repeater mode supports `forward`, `monitor`, and `relay`.
- Relay whitelist CLI commands:
  - `relay list`
  - `relay add <64-hex-pubkey>`
  - `relay del <64-hex-pubkey>`
- CLI help (`help` or `?`) includes relay commands.
- Relay companion API endpoint:
  - `GET /api/relay_companions`
  - `POST /api/relay_companions` with `{"public_key":"<64-hex>"}` 
  - `DELETE /api/relay_companions?public_key=<64-hex>`
- Relay companions are stored in config at:
  - `repeater.relay_companions` (array of normalized lowercase 64-hex pubkeys)

## Relay Behavior

- In `relay` mode, forwarding is whitelist-gated:
  - Direct/text/group/control/path-style payloads are forwarded only when src or dst hash matches a companion hash.
  - Advert packets are forwarded only when advert source hash matches a companion hash.
- If no companions are configured, `relay` mode behaves like normal forwarding mode (no lockout).

## UI Notes

- Mode cycle supports all 3 modes.
- Relay mode status text shows as `Relay Mode 🟣`.

