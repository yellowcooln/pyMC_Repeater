import asyncio
import logging
import os
import random
import struct
import time
from typing import Coroutine, List, Optional

from pymc_core.protocol.packet_builder import PacketBuilder
from pymc_core.node.handlers.protocol_request import REQ_TYPE_GET_STATUS
from pymc_core.protocol.constants import PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE
from pymc_core.protocol.crypto import CryptoUtils
from pymc_core.protocol.identity import Identity

logger = logging.getLogger("MeshcoreBridge")

FRAME_START = 0x3C

# MeshCore protocol packet types (subset used by HA integration)
PKT_OK = 0x00
PKT_ERROR = 0x01
PKT_CONTACT_START = 0x02
PKT_CONTACT = 0x03
PKT_CONTACT_END = 0x04
PKT_SELF_INFO = 0x05
PKT_MSG_SENT = 0x06
PKT_CURRENT_TIME = 0x09
PKT_NO_MORE_MSGS = 0x0A
PKT_BATTERY = 0x0C
PKT_DEVICE_INFO = 0x0D
PKT_STATUS_RESPONSE = 0x87
PKT_LOGIN_SUCCESS = 0x85
PKT_LOGIN_FAILED = 0x86
PKT_TELEMETRY_RESPONSE = 0x8B
PKT_BINARY_RESPONSE = 0x8C

# Command bytes
CMD_APPSTART = 0x01
CMD_GET_CONTACTS = 0x04
CMD_GET_TIME = 0x05
CMD_SET_TIME = 0x06
CMD_SEND_ADVERT = 0x07
CMD_RESET_PATH = 0x0D
CMD_GET_BAT = 0x14
CMD_DEVICE_QUERY = 0x16
CMD_SEND_LOGIN = 0x1A
CMD_SEND_STATUSREQ = 0x1B
CMD_SEND_LOGOUT = 0x1D
CMD_SEND_MSG = 0x02
CMD_GET_MSG = 0x0A
CMD_GET_SELF_TELEMETRY = 0x27
CMD_BINARY_REQ = 0x32
CMD_SET_OTHER_PARAMS = 0x26
CMD_SEND_PATH_DISCOVERY = 0x34

# Binary request types (from meshcore BinaryReqType)
BINREQ_STATUS = 0x01
BINREQ_TELEMETRY = 0x03

DEFAULT_TIMEOUT_MS = 4000


class MeshcoreTCPBridge:
    def __init__(self, daemon, host: str = "0.0.0.0", port: int = 5000) -> None:
        self.daemon = daemon
        self.host = host
        self.port = port
        self._server: Optional[asyncio.base_events.Server] = None
        self._pending_requests: dict[tuple[int, str], dict] = {}

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        addr = ", ".join(str(sock.getsockname()) for sock in self._server.sockets or [])
        logger.info("MeshCore TCP bridge listening on %s", addr)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("MeshCore TCP bridge stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("MeshCore TCP client connected: %s", peer)
        try:
            while True:
                header = await reader.readexactly(3)
                if not header:
                    break
                if header[0] != FRAME_START:
                    logger.warning("Invalid frame start byte: %s", header[0])
                    continue
                size = int.from_bytes(header[1:3], byteorder="little")
                if size == 0:
                    continue
                payload = await reader.readexactly(size)
                await self._handle_payload(payload, writer)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            logger.error("MeshCore TCP client error: %s", exc, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("MeshCore TCP client disconnected: %s", peer)

    async def _handle_payload(self, payload: bytes, writer: asyncio.StreamWriter) -> None:
        if not payload:
            return
        cmd = payload[0]

        if cmd == CMD_APPSTART:
            await self._send_self_info(writer)
            await self._send_device_info(writer)
            await self._send_contacts(writer)
            return

        if cmd == CMD_DEVICE_QUERY and len(payload) > 1 and payload[1] == 0x03:
            await self._send_device_info(writer)
            return

        if cmd == CMD_GET_CONTACTS:
            await self._send_contacts(writer)
            return

        if cmd == CMD_SEND_ADVERT:
            await self._send_ok(writer)
            return

        if cmd == CMD_RESET_PATH:
            await self._send_ok(writer)
            contact = self._contact_from_payload(payload, offset=1)
            if contact:
                self._schedule_rf_task(self._send_rf_reset_path(contact), "reset_path")
            return

        if cmd == CMD_SET_TIME:
            await self._send_ok(writer)
            return

        if cmd == CMD_SET_OTHER_PARAMS:
            await self._send_ok(writer)
            return

        if cmd == CMD_GET_TIME:
            await self._send_current_time(writer)
            return

        if cmd == CMD_GET_BAT:
            await self._send_battery(writer)
            return

        if cmd == CMD_GET_MSG:
            await self._send_no_more_msgs(writer)
            return

        if cmd == CMD_GET_SELF_TELEMETRY:
            if len(payload) >= 37:
                await self._send_msg_sent(writer)
                contact = self._contact_from_payload(payload, offset=5)
                if contact:
                    self._schedule_rf_task(self._send_rf_telem_request(contact), "telemetry_request")
            else:
                await self._send_self_telemetry(writer)
            return

        if cmd == CMD_SEND_PATH_DISCOVERY:
            await self._send_msg_sent(writer)
            contact = self._contact_from_payload(payload, offset=2)
            if contact:
                self._schedule_rf_task(self._send_rf_path_discovery(contact), "path_discovery")
            return

        if cmd == CMD_BINARY_REQ:
            await self._handle_binary_req(payload, writer)
            return

        if cmd in (CMD_SEND_LOGIN, CMD_SEND_STATUSREQ, CMD_SEND_LOGOUT, CMD_SEND_MSG):
            await self._send_msg_sent(writer)
            if cmd == CMD_SEND_STATUSREQ:
                contact = self._contact_from_payload(payload, offset=1)
                if contact:
                    self._register_pending(contact, "status", writer)
                    self._schedule_rf_task(self._send_rf_status_request(contact), "status_request")
                    pubkey_prefix = bytes.fromhex(contact.public_key)[:6]
                    await asyncio.sleep(0.05)
                    await self._send_status_response(writer, pubkey_prefix)
            if cmd == CMD_SEND_LOGIN:
                contact = self._contact_from_payload(payload, offset=1)
                password = self._parse_login_password(payload, offset=1 + 32)
                if contact and password is not None:
                    self._schedule_rf_task(self._send_rf_login(contact, password), "login")
                    pubkey_prefix = bytes.fromhex(contact.public_key)[:6]
                    await asyncio.sleep(0.05)
                    await self._send_login_success(writer, pubkey_prefix)
            if cmd == CMD_SEND_LOGOUT:
                contact = self._contact_from_payload(payload, offset=1)
                if contact:
                    self._schedule_rf_task(self._send_rf_logout(contact), "logout")
            return

        logger.debug("Unhandled MeshCore command: 0x%02X", cmd)
        await self._send_error(writer, 0)

    async def _send_packet(self, writer: asyncio.StreamWriter, payload: bytes) -> None:
        pkt = bytes([FRAME_START]) + len(payload).to_bytes(2, byteorder="little") + payload
        writer.write(pkt)
        await writer.drain()

    async def _send_ok(self, writer: asyncio.StreamWriter) -> None:
        await self._send_packet(writer, bytes([PKT_OK]))

    async def _send_error(self, writer: asyncio.StreamWriter, code: int) -> None:
        await self._send_packet(writer, bytes([PKT_ERROR, code & 0xFF]))

    async def _send_msg_sent(self, writer: asyncio.StreamWriter) -> bytes:
        tag = os.urandom(4)
        payload = bytes([PKT_MSG_SENT, 0x00]) + tag + int(DEFAULT_TIMEOUT_MS).to_bytes(4, "little")
        await self._send_packet(writer, payload)
        return tag

    async def _send_current_time(self, writer: asyncio.StreamWriter) -> None:
        now = int(time.time())
        payload = bytes([PKT_CURRENT_TIME]) + now.to_bytes(4, "little")
        await self._send_packet(writer, payload)

    async def _send_no_more_msgs(self, writer: asyncio.StreamWriter) -> None:
        await self._send_packet(writer, bytes([PKT_NO_MORE_MSGS]))

    async def _send_battery(self, writer: asyncio.StreamWriter) -> None:
        # Report full LiPo to match HA expectations
        payload = bytes([PKT_BATTERY]) + (4200).to_bytes(2, "little")
        await self._send_packet(writer, payload)

    async def _send_self_info(self, writer: asyncio.StreamWriter) -> None:
        config = self.daemon.config
        node_name = config.get("repeater", {}).get("node_name", "PyMC-Repeater")
        lat = float(config.get("repeater", {}).get("latitude", 0.0))
        lon = float(config.get("repeater", {}).get("longitude", 0.0))
        radio = config.get("radio", {})

        public_key = b""  # 32 bytes
        if self.daemon.local_identity:
            try:
                public_key = self.daemon.local_identity.get_public_key()
            except Exception:
                public_key = b""
        public_key = public_key[:32].ljust(32, b"\x00")

        tx_power = int(radio.get("tx_power", 14))
        max_tx_power = tx_power
        adv_type = 2  # repeater

        # MeshCore expects Hz values in SELF_INFO
        radio_freq = int(radio.get("frequency", 0))
        radio_bw = int(radio.get("bandwidth", 0))
        radio_sf = int(radio.get("spreading_factor", 7))
        radio_cr = int(radio.get("coding_rate", 5))

        telemetry_mode = 0
        manual_add_contacts = 0
        multi_acks = 0
        adv_loc_policy = 0

        payload = bytearray()
        payload.append(PKT_SELF_INFO)
        payload.append(adv_type & 0xFF)
        payload.append(tx_power & 0xFF)
        payload.append(max_tx_power & 0xFF)
        payload.extend(public_key)
        payload.extend(int(lat * 1e6).to_bytes(4, "little", signed=True))
        payload.extend(int(lon * 1e6).to_bytes(4, "little", signed=True))
        payload.append(multi_acks & 0xFF)
        payload.append(adv_loc_policy & 0xFF)
        payload.append(telemetry_mode & 0xFF)
        payload.append(manual_add_contacts & 0xFF)
        payload.extend(int(radio_freq).to_bytes(4, "little", signed=False))
        payload.extend(int(radio_bw).to_bytes(4, "little", signed=False))
        payload.append(radio_sf & 0xFF)
        payload.append(radio_cr & 0xFF)
        payload.extend(node_name.encode("utf-8")[:64])

        await self._send_packet(writer, bytes(payload))

    async def _send_device_info(self, writer: asyncio.StreamWriter) -> None:
        config = self.daemon.config
        model = config.get("letsmesh", {}).get("model", "PyMC-Repeater")
        fw_build = "pymc-bridge"
        version = "0.1"

        payload = bytearray()
        payload.append(PKT_DEVICE_INFO)
        payload.append(3)  # fw ver >= 3 to include extended fields
        payload.append(50)  # max_contacts/2 => 100
        payload.append(4)  # max_channels
        payload.extend((0).to_bytes(4, "little"))  # ble_pin

        fw_build_bytes = fw_build.encode("utf-8")[:12].ljust(12, b"\x00")
        model_bytes = model.encode("utf-8")[:40].ljust(40, b"\x00")
        version_bytes = version.encode("utf-8")[:20].ljust(20, b"\x00")

        payload.extend(fw_build_bytes)
        payload.extend(model_bytes)
        payload.extend(version_bytes)

        await self._send_packet(writer, bytes(payload))

    async def _send_contacts(self, writer: asyncio.StreamWriter) -> None:
        contacts = self._build_contacts()
        await self._send_packet(writer, bytes([PKT_CONTACT_START]) + len(contacts).to_bytes(4, "little"))

        for contact in contacts:
            pkt = bytearray()
            pkt.append(PKT_CONTACT)
            pkt.extend(contact["public_key"])
            pkt.append(contact["type"] & 0xFF)
            pkt.append(contact["flags"] & 0xFF)
            pkt.append(contact["out_path_len"] & 0xFF)
            pkt.extend(contact["out_path"])
            pkt.extend(contact["adv_name"])
            pkt.extend(int(contact["last_advert"]).to_bytes(4, "little"))
            pkt.extend(int(contact["adv_lat"] * 1e6).to_bytes(4, "little", signed=True))
            pkt.extend(int(contact["adv_lon"] * 1e6).to_bytes(4, "little", signed=True))
            pkt.extend(int(contact["lastmod"]).to_bytes(4, "little"))
            await self._send_packet(writer, bytes(pkt))

        lastmod = int(time.time())
        await self._send_packet(writer, bytes([PKT_CONTACT_END]) + lastmod.to_bytes(4, "little"))

    def _build_contacts(self) -> List[dict]:
        contacts: List[dict] = []
        storage = None
        if self.daemon.repeater_handler and self.daemon.repeater_handler.storage:
            storage = self.daemon.repeater_handler.storage

        # Match UI "Tracking" count: only include recent adverts and known contact types
        allowed_types = {"chat node", "repeater", "room server"}
        cutoff = time.time() - (168 * 3600)  # 7 days, matches UI hours=168

        neighbors = storage.get_neighbors() if storage else {}
        for pubkey_hex, info in neighbors.items():
            contact_type = info.get("contact_type")
            if not contact_type or str(contact_type).strip().lower() not in allowed_types:
                continue

            try:
                pubkey_bytes = bytes.fromhex(pubkey_hex)
            except Exception:
                continue

            pubkey_bytes = pubkey_bytes[:32].ljust(32, b"\x00")
            node_name = info.get("node_name") or "Unknown"
            is_repeater = bool(info.get("is_repeater"))
            node_type = self._coerce_contact_type(contact_type, is_repeater)

            out_path_len = 0
            flags = 0

            adv_name_bytes = node_name.encode("utf-8")[:32].ljust(32, b"\x00")
            last_seen = int(info.get("last_seen") or time.time())
            if last_seen < cutoff:
                continue
            lat = float(info.get("latitude") or 0.0)
            lon = float(info.get("longitude") or 0.0)

            contacts.append(
                {
                    "public_key": pubkey_bytes,
                    "type": node_type,
                    "flags": flags,
                    "out_path_len": out_path_len,
                    "out_path": b"\x00" * 64,
                    "adv_name": adv_name_bytes,
                    "last_advert": last_seen,
                    "adv_lat": lat,
                    "adv_lon": lon,
                    "lastmod": last_seen,
                }
            )

        return contacts

    def _coerce_contact_type(self, contact_type, is_repeater: bool) -> int:
        if contact_type is None:
            return 2 if is_repeater else 1
        if isinstance(contact_type, int):
            return contact_type
        if isinstance(contact_type, str):
            lookup = {
                "repeater": 2,
                "room_server": 3,
                "roomserver": 3,
                "sensor": 4,
                "client": 1,
                "node": 1,
            }
            return lookup.get(contact_type.strip().lower(), 2 if is_repeater else 1)
        return 2 if is_repeater else 1

    async def _send_self_telemetry(self, writer: asyncio.StreamWriter) -> None:
        prefix = self._local_pubkey_prefix()
        lpp_bytes = self._build_self_telemetry_lpp()
        logger.info("Self telemetry LPP bytes: %s", lpp_bytes.hex() if lpp_bytes else "<empty>")
        payload = bytes([PKT_TELEMETRY_RESPONSE]) + prefix + lpp_bytes
        await self._send_packet(writer, payload)

    def _build_self_telemetry_lpp(self) -> bytes:
        temp_c = self._get_cpu_temp_c()
        if temp_c is None:
            logger.info("CPU temp unavailable; self telemetry empty")
            return b""

        # Cayenne LPP temperature: channel, type(0x67), int16 value (0.1C), big-endian
        temp10 = int(round(temp_c * 10))
        logger.info("CPU temp %.2fC; self telemetry temp10=%s", temp_c, temp10)
        lpp = bytes([1, 0x67]) + temp10.to_bytes(2, "big", signed=True)
        # MeshCore telemetry expects a length prefix
        return bytes([len(lpp)]) + lpp

    def _get_cpu_temp_c(self) -> float | None:
        def _is_valid_temp(value: float | None) -> bool:
            if value is None:
                return False
            try:
                return 1.0 <= float(value) <= 120.0
            except (TypeError, ValueError):
                return False

        temps = None
        try:
            repeater_handler = getattr(self.daemon, "repeater_handler", None)
            storage = getattr(repeater_handler, "storage", None) if repeater_handler else None
            stats = storage.hardware_stats.get_stats() if storage and getattr(storage, "hardware_stats", None) else None
            if isinstance(stats, dict):
                temps = stats.get("temperatures")
        except Exception:
            temps = None

        if not temps:
            return self._read_sysfs_cpu_temp_c()

        preferred = ("cpu", "coretemp", "package", "soc", "thermal", "acpitz")
        for key in preferred:
            for name, value in temps.items():
                if key in name.lower():
                    try:
                        temp = float(value)
                        if _is_valid_temp(temp):
                            return temp
                    except (TypeError, ValueError):
                        continue

        for value in temps.values():
            try:
                temp = float(value)
                if _is_valid_temp(temp):
                    return temp
            except (TypeError, ValueError):
                continue

        return self._read_sysfs_cpu_temp_c()

    def _read_sysfs_cpu_temp_c(self) -> float | None:
        paths = []
        try:
            from glob import glob
            paths.extend(glob("/sys/class/thermal/thermal_zone*/temp"))
            paths.extend(glob("/sys/class/hwmon/hwmon*/temp*_input"))
        except Exception:
            return None

        temps = []
        for path in paths:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    raw = handle.read().strip()
                if not raw:
                    continue
                val = float(raw)
                temp_c = val / 1000.0 if val > 1000 else val
                if 1.0 <= temp_c <= 120.0:
                    temps.append(temp_c)
            except Exception:
                continue

        return max(temps) if temps else None

    def _filter_self_lpp(self, lpp_bytes: bytes) -> bytes:
        if not lpp_bytes:
            return b""

        filtered = bytearray()
        i = 0
        while i + 1 < len(lpp_bytes):
            channel = lpp_bytes[i]
            lpp_type = lpp_bytes[i + 1]
            i += 2

            # Keep only channel 1 temperature for self telemetry
            if channel == 1 and lpp_type == 0x67 and i + 2 <= len(lpp_bytes):
                filtered.extend([channel, lpp_type])
                filtered.extend(lpp_bytes[i:i + 2])

            # Skip payload for known types
            if lpp_type in (0x00, 0x01):  # digital in/out (1 byte)
                i += 1
            elif lpp_type in (0x02, 0x03, 0x67, 0x71):  # analog/temperature/baro (2 bytes)
                i += 2
            elif lpp_type == 0x68:  # humidity (1 byte)
                i += 1
            elif lpp_type == 0x65:  # illuminance (2 bytes)
                i += 2
            elif lpp_type == 0x66:  # presence (1 byte)
                i += 1
            elif lpp_type == 0x73:  # accelerometer (6 bytes)
                i += 6
            elif lpp_type == 0x88:  # gps (9 bytes)
                i += 9
            else:
                # Unknown type: stop to avoid misalignment
                break

        return bytes(filtered)

    def _filter_remote_lpp(self, lpp_bytes: bytes) -> bytes:
        if not lpp_bytes:
            return b""

        filtered = bytearray()
        i = 0
        while i + 3 < len(lpp_bytes):
            channel = lpp_bytes[i]
            lpp_type = lpp_bytes[i + 1]
            i += 2

            if lpp_type == 0x67:
                if i + 2 > len(lpp_bytes):
                    break
                raw = lpp_bytes[i : i + 2]
                temp10 = int.from_bytes(raw, "big", signed=True)
                if temp10 != -1:
                    # Force all remote temperatures to channel 1
                    filtered.extend([1, lpp_type])
                    filtered.extend(raw)
                i += 2
                continue

            # Skip payload for known types we don't want to forward
            if lpp_type in (0x00, 0x01, 0x68, 0x66):  # digital/humidity/presence (1 byte)
                i += 1
                continue
            if lpp_type in (0x02, 0x03, 0x71, 0x65):  # analog/baro/illuminance (2 bytes)
                i += 2
                continue
            if lpp_type == 0x73:  # accelerometer (6 bytes)
                i += 6
                continue
            if lpp_type == 0x88:  # gps (9 bytes)
                i += 9
                continue

            # Unknown type: stop parsing to avoid misalignment
            break

        return bytes(filtered)

    async def _handle_binary_req(self, payload: bytes, writer: asyncio.StreamWriter) -> None:
        if len(payload) < 34:
            await self._send_error(writer, 0)
            return

        dst = payload[1:33]
        req_type = payload[33]
        pubkey_prefix = dst[:6]
        contact = self._contact_from_pubkey_bytes(dst)

        tag = await self._send_msg_sent(writer)
        # Give client time to register pending binary request before responding
        await asyncio.sleep(0.2)

        if req_type == BINREQ_STATUS:
            if contact:
                self._register_pending(contact, "status", writer)
                self._schedule_rf_task(self._send_rf_status_request(contact), "status_request")
            status_bytes = self._build_status_payload()
            await self._send_binary_response(writer, tag, status_bytes)
            return

        if req_type == BINREQ_TELEMETRY:
            if contact:
                self._register_pending(contact, "telemetry", writer)
                self._schedule_rf_task(self._send_rf_telem_request(contact), "telemetry_request")
            await self._send_binary_response(writer, tag, b"")
            return

        await self._send_binary_response(writer, tag, b"")

    async def _send_binary_response(self, writer: asyncio.StreamWriter, tag: bytes, data: bytes) -> None:
        payload = bytes([PKT_BINARY_RESPONSE]) + tag + data
        await self._send_packet(writer, payload)

    async def _send_status_response(self, writer: asyncio.StreamWriter, pubkey_prefix: bytes) -> None:
        status_bytes = self._build_status_payload()
        payload = bytes([PKT_STATUS_RESPONSE, 0x00]) + pubkey_prefix[:6] + status_bytes
        await self._send_packet(writer, payload)

    async def _send_status_response_bytes(self, writer: asyncio.StreamWriter, pubkey_prefix: bytes, status_bytes: bytes) -> None:
        payload = bytes([PKT_STATUS_RESPONSE, 0x00]) + pubkey_prefix[:6] + status_bytes
        await self._send_packet(writer, payload)

    async def _send_telemetry_response_bytes(self, writer: asyncio.StreamWriter, pubkey_prefix: bytes, lpp_bytes: bytes) -> None:
        original_hex = lpp_bytes.hex() if lpp_bytes else ""
        is_local = pubkey_prefix[:6] == self._local_pubkey_prefix()
        if is_local:
            lpp_bytes = self._filter_self_lpp(lpp_bytes)
        else:
            lpp_bytes = self._filter_remote_lpp(lpp_bytes)
            if lpp_bytes:
                lpp_bytes = bytes([len(lpp_bytes)]) + lpp_bytes
        logger.info(
            "Telemetry LPP pubkey=%s original=%s filtered=%s",
            pubkey_prefix[:6].hex(),
            original_hex if original_hex else "<empty>",
            lpp_bytes.hex() if lpp_bytes else "<empty>",
        )
        payload = bytes([PKT_TELEMETRY_RESPONSE]) + pubkey_prefix[:6] + lpp_bytes
        await self._send_packet(writer, payload)

    async def _send_login_success(self, writer: asyncio.StreamWriter, pubkey_prefix: bytes) -> None:
        # Permissions: bit0=admin
        perms = 0x01
        payload = bytes([PKT_LOGIN_SUCCESS, perms]) + pubkey_prefix[:6]
        await self._send_packet(writer, payload)

    def _build_status_payload(self) -> bytes:
        radio = getattr(self.daemon, "radio", None)
        engine = getattr(self.daemon, "repeater_handler", None)

        noise_floor = -120
        last_rssi = -120
        last_snr_raw = 0
        if radio:
            try:
                if hasattr(radio, "get_noise_floor"):
                    noise_floor = int(radio.get_noise_floor())
                if hasattr(radio, "last_rssi"):
                    last_rssi = int(radio.last_rssi)
                if hasattr(radio, "last_snr"):
                    last_snr_raw = int(float(radio.last_snr) * 4.0)
            except Exception:
                pass

        n_packets_recv = 0
        n_packets_sent = 0
        total_air_time_secs = 0

        if engine:
            n_packets_recv = int(getattr(engine, "rx_count", 0))
            n_packets_sent = int(getattr(engine, "forwarded_count", 0))
            airtime_mgr = getattr(engine, "airtime_mgr", None)
            if airtime_mgr and hasattr(airtime_mgr, "total_airtime_ms"):
                total_air_time_secs = int(airtime_mgr.total_airtime_ms / 1000)

        uptime_secs = int(time.time())
        if engine and hasattr(engine, "start_time"):
            try:
                uptime_secs = int(time.time() - engine.start_time)
            except Exception:
                pass

        stats = struct.pack(
            "<HHhhIIIIIIIIIhIII",
            4200,  # batt_milli_volts (full LiPo)
            0,  # curr_tx_queue_len
            int(noise_floor),
            int(last_rssi),
            n_packets_recv,
            n_packets_sent,
            total_air_time_secs,
            uptime_secs,
            0,  # n_sent_flood
            0,  # n_sent_direct
            0,  # n_recv_flood
            0,  # n_recv_direct
            0,  # err_events
            int(last_snr_raw),
            0,  # n_direct_dups
            0,  # n_flood_dups
            0,  # total_rx_air_time_secs
        )

        return stats

    def _local_pubkey_prefix(self) -> bytes:
        if self.daemon.local_identity:
            try:
                return self.daemon.local_identity.get_public_key()[:6]
            except Exception:
                return b"\x00" * 6
        return b"\x00" * 6

    def _extract_pubkey_prefix(self, payload: bytes, offset: int, length: int) -> Optional[bytes]:
        if len(payload) < offset + length:
            return None
        dst = payload[offset:offset + length]
        return dst[:6]

    def _contact_from_payload(self, payload: bytes, offset: int) -> Optional["_SimpleContact"]:
        if len(payload) < offset + 32:
            return None
        return self._contact_from_pubkey_bytes(payload[offset:offset + 32])

    def _contact_from_pubkey_bytes(self, pubkey_bytes: bytes) -> Optional["_SimpleContact"]:
        if len(pubkey_bytes) < 32:
            return None
        return _SimpleContact(public_key=pubkey_bytes[:32].hex(), contact_type=2)

    def _parse_login_password(self, payload: bytes, offset: int) -> Optional[str]:
        if len(payload) <= offset:
            return ""
        try:
            return payload[offset:].decode("utf-8", "ignore")
        except Exception:
            return ""

    def _schedule_rf_task(self, coro: Coroutine, action: str) -> None:
        try:
            asyncio.create_task(coro)
        except Exception as exc:
            logger.error("Failed to schedule RF %s: %s", action, exc)

    def _register_pending(self, contact: "_SimpleContact", kind: str, writer: asyncio.StreamWriter) -> None:
        try:
            contact_hash = int(contact.public_key[:2], 16)
        except Exception:
            return
        self._pending_requests[(contact_hash, kind)] = {"writer": writer, "contact": contact, "ts": time.time()}

    async def handle_rf_packet(self, packet) -> bool:
        payload_type = packet.get_payload_type()
        if payload_type not in (PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE):
            return False
        if len(packet.payload) < 3:
            return False

        dest_hash = packet.payload[0]
        src_hash = packet.payload[1]
        encrypted_data = bytes(packet.payload[2:])

        # Only process if we have pending requests for this source hash
        pending_status = self._pending_requests.get((src_hash, "status"))
        pending_telemetry = self._pending_requests.get((src_hash, "telemetry"))
        if not pending_status and not pending_telemetry:
            return False

        contact = None
        if pending_status:
            contact = pending_status.get("contact")
        if not contact and pending_telemetry:
            contact = pending_telemetry.get("contact")
        if not contact:
            return False

        identity = self.daemon.local_identity
        if not identity:
            return False

        try:
            contact_pubkey = bytes.fromhex(contact.public_key)
            peer_id = Identity(contact_pubkey)
            shared_secret = peer_id.calc_shared_secret(identity.get_private_key())
            aes_key = shared_secret[:16]
            plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)
        except Exception as exc:
            logger.error("Failed to decrypt RF response: %s", exc)
            return False

        if not plaintext or len(plaintext) < 4:
            return False

        # Strip reflected timestamp (first 4 bytes)
        payload = plaintext[4:]
        pubkey_prefix = contact_pubkey[:6]

        if pending_status and len(payload) >= 58:
            status_bytes = self._pymc_status_to_meshcore(payload[:58])
            if status_bytes:
                await self._send_status_response_bytes(pending_status["writer"], pubkey_prefix, status_bytes)
            self._pending_requests.pop((src_hash, "status"), None)
            return True

        if pending_telemetry and len(payload) > 0:
            await self._send_telemetry_response_bytes(pending_telemetry["writer"], pubkey_prefix, payload)
            self._pending_requests.pop((src_hash, "telemetry"), None)
            return True

        return False

    async def _send_rf_login(self, contact: "_SimpleContact", password: str) -> None:
        identity = self.daemon.local_identity
        dispatcher = self.daemon.dispatcher
        if not identity or not dispatcher:
            logger.warning("RF login skipped: local identity or dispatcher missing")
            return
        try:
            packet = PacketBuilder.create_login_packet(contact, identity, password)
            await dispatcher.send_packet(packet, wait_for_ack=False)
            self._record_tx_packet(packet)
            logger.info("RF login sent to %s", contact.public_key[:12])
        except Exception as exc:
            logger.error("RF login failed: %s", exc, exc_info=True)

    async def _send_rf_logout(self, contact: "_SimpleContact") -> None:
        identity = self.daemon.local_identity
        dispatcher = self.daemon.dispatcher
        if not identity or not dispatcher:
            logger.warning("RF logout skipped: local identity or dispatcher missing")
            return
        try:
            packet, crc = PacketBuilder.create_logout_packet(contact, identity)
            await dispatcher.send_packet(packet, wait_for_ack=False, expected_crc=crc)
            self._record_tx_packet(packet)
            logger.info("RF logout sent to %s", contact.public_key[:12])
        except Exception as exc:
            logger.error("RF logout failed: %s", exc, exc_info=True)

    async def _send_rf_status_request(self, contact: "_SimpleContact") -> None:
        identity = self.daemon.local_identity
        dispatcher = self.daemon.dispatcher
        if not identity or not dispatcher:
            logger.warning("RF status request skipped: local identity or dispatcher missing")
            return
        try:
            packet, _ts = PacketBuilder.create_protocol_request(
                contact=contact, local_identity=identity, protocol_code=REQ_TYPE_GET_STATUS
            )
            await dispatcher.send_packet(packet, wait_for_ack=False)
            self._record_tx_packet(packet)
            logger.info("RF status request sent to %s", contact.public_key[:12])
        except Exception as exc:
            logger.error("RF status request failed: %s", exc, exc_info=True)

    async def _send_rf_telem_request(self, contact: "_SimpleContact") -> None:
        identity = self.daemon.local_identity
        dispatcher = self.daemon.dispatcher
        if not identity or not dispatcher:
            logger.warning("RF telemetry request skipped: local identity or dispatcher missing")
            return
        try:
            packet, _ts = PacketBuilder.create_telem_request(contact, identity)
            await dispatcher.send_packet(packet, wait_for_ack=False)
            self._record_tx_packet(packet)
            logger.info("RF telemetry request sent to %s", contact.public_key[:12])
        except Exception as exc:
            logger.error("RF telemetry request failed: %s", exc, exc_info=True)

    async def _send_rf_path_discovery(self, contact: "_SimpleContact") -> None:
        dispatcher = self.daemon.dispatcher
        if not dispatcher:
            logger.warning("RF path discovery skipped: dispatcher missing")
            return
        try:
            tag = random.randint(0, 0xFFFFFFFF)
            dest_hash = int(contact.public_key[:2], 16)
            packet = PacketBuilder.create_trace(tag=tag, auth_code=0, flags=0, path=[dest_hash])
            await dispatcher.send_packet(packet, wait_for_ack=False)
            self._record_tx_packet(packet)
            logger.info("RF path discovery (trace) sent to %s", contact.public_key[:12])
        except Exception as exc:
            logger.error("RF path discovery failed: %s", exc, exc_info=True)

    async def _send_rf_reset_path(self, contact: "_SimpleContact") -> None:
        dispatcher = self.daemon.dispatcher
        if not dispatcher:
            logger.warning("RF reset path skipped: dispatcher missing")
            return
        try:
            tag = random.randint(0, 0xFFFFFFFF)
            dest_hash = int(contact.public_key[:2], 16)
            packet = PacketBuilder.create_trace(tag=tag, auth_code=0, flags=1, path=[dest_hash])
            await dispatcher.send_packet(packet, wait_for_ack=False)
            self._record_tx_packet(packet)
            logger.info("RF reset path (trace) sent to %s", contact.public_key[:12])
        except Exception as exc:
            logger.error("RF reset path failed: %s", exc, exc_info=True)

    def _record_tx_packet(self, packet) -> None:
        handler = getattr(self.daemon, "repeater_handler", None)
        if not handler:
            return
        try:
            pkt_hash = packet.get_packet_hash_hex(16) if hasattr(packet, "get_packet_hash_hex") else ""
            packet_record = {
                "timestamp": time.time(),
                "payload_length": len(packet.payload) if getattr(packet, "payload", None) else 0,
                "type": packet.get_payload_type(),
                "route": packet.get_route_type(),
                "length": len(packet.payload or b""),
                "rssi": 0,
                "snr": 0,
                "score": 0,
                "tx_delay_ms": 0,
                "transmitted": True,
                "is_duplicate": False,
                "packet_hash": pkt_hash,
                "drop_reason": None,
                "path_hash": None,
                "src_hash": None,
                "dst_hash": None,
                "original_path": None,
                "forwarded_path": None,
                "raw_packet": packet.write_to().hex() if hasattr(packet, "write_to") else None,
                "lbt_attempts": 0,
                "lbt_backoff_delays_ms": None,
                "lbt_channel_busy": False,
            }
            handler.log_trace_record(packet_record)
        except Exception as exc:
            logger.debug("Failed to record RF TX packet: %s", exc)

    def _pymc_status_to_meshcore(self, data: bytes) -> Optional[bytes]:
        try:
            if len(data) < 58:
                return None
            values = struct.unpack("<HHhhIIIIIIIIIhIII", data[:58])
            batt_mv = values[0]
            tx_queue = values[1]
            noise_floor = values[2]
            last_rssi = values[3]
            nb_recv = values[4]
            nb_sent = values[5]
            airtime = values[6]
            uptime = values[7]
            sent_flood = values[8]
            sent_direct = values[9]
            recv_flood = values[10]
            recv_direct = values[11]
            err_events = values[12]
            last_snr = values[13]
            direct_dups = values[14]
            flood_dups = values[15]
            rx_airtime = values[16]

            err_events_16 = min(int(err_events), 0xFFFF)
            direct_dups_16 = min(int(direct_dups), 0xFFFF)
            flood_dups_16 = min(int(flood_dups), 0xFFFF)

            return struct.pack(
                "<HHhhIIIIIIIIIhHHI",
                batt_mv,
                tx_queue,
                noise_floor,
                last_rssi,
                nb_recv,
                nb_sent,
                airtime,
                uptime,
                sent_flood,
                sent_direct,
                recv_flood,
                recv_direct,
                err_events_16,
                last_snr,
                direct_dups_16,
                flood_dups_16,
                rx_airtime,
            )
        except Exception as exc:
            logger.error("Failed to convert status payload: %s", exc)
            return None


class _SimpleContact:
    def __init__(self, public_key: str, contact_type: int = 2, sync_since: int = 0) -> None:
        self.public_key = public_key
        self.type = contact_type
        self.sync_since = sync_since
