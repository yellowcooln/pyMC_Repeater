# Relay Mode Feature (Forward / Monitor / Relay)

This file tracks relay-mode behavior and commands only.

## Current Modes

- Repeater supports 3 modes:
  - `forward`
  - `monitor`
  - `relay`
- `relay=false` is not used as a substitute for monitor mode.

## Relay Companion Whitelist

- Relay companion commands:
  - `relay` (shows relay command help/usage)
  - `relay list`
  - `relay add <64-hex-pubkey>`
  - `relay del <64-hex-pubkey>`
- Relay companion API:
  - `GET /api/relay_companions`
  - `POST /api/relay_companions` with `{"public_key":"<64-hex>"}`
  - `DELETE /api/relay_companions?public_key=<64-hex>`
- Stored in config:
  - `repeater.relay_companions` (normalized lowercase 64-hex pubkeys)

## Relay Policy (Compat vs Strict)

- Relay policy setting:
  - `repeater.relay_mode` with values:
    - `compat` (default)
    - `strict`
- Meaning:
  - `compat`: whitelist by companion hashes where possible; allow payload types that cannot be identity-verified at this layer.
  - `strict`: whitelist by companion hashes where possible; drop payload types that cannot be identity-verified.
- API support:
  - `POST /api/update_radio_config` with `{"relay_mode":"compat|strict"}`
- CLI support:
  - `get relay.mode`
  - `set relay.mode <compat|strict>`

## UI Notes

- Web UI supports all 3 repeater modes.
- Repeater Settings includes a Relay Policy selector (`Compat` / `Strict`).
