import asyncio
import logging
import os
import struct
import time
from typing import List, Optional

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
            await self._send_self_telemetry(writer)
            return

        if cmd == CMD_BINARY_REQ:
            await self._handle_binary_req(payload, writer)
            return

        if cmd in (CMD_SEND_LOGIN, CMD_SEND_STATUSREQ, CMD_SEND_LOGOUT, CMD_SEND_MSG):
            await self._send_msg_sent(writer)
            if cmd == CMD_SEND_STATUSREQ:
                pubkey_prefix = self._extract_pubkey_prefix(payload, offset=1, length=32)
                if pubkey_prefix:
                    await asyncio.sleep(0.05)
                    await self._send_status_response(writer, pubkey_prefix)
            if cmd == CMD_SEND_LOGIN:
                pubkey_prefix = self._extract_pubkey_prefix(payload, offset=1, length=32)
                if pubkey_prefix:
                    await asyncio.sleep(0.05)
                    await self._send_login_success(writer, pubkey_prefix)
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
        # No battery on typical repeater hosts; report 0mV
        payload = bytes([PKT_BATTERY]) + (0).to_bytes(2, "little")
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

        radio_freq = int(radio.get("frequency", 0) / 1000)  # Hz -> kHz
        radio_bw = int(radio.get("bandwidth", 0) / 1000)  # Hz -> kHz
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

        neighbors = storage.get_neighbors() if storage else {}
        for pubkey_hex, info in neighbors.items():
            try:
                pubkey_bytes = bytes.fromhex(pubkey_hex)
            except Exception:
                continue

            pubkey_bytes = pubkey_bytes[:32].ljust(32, b"\x00")
            node_name = info.get("node_name") or "Unknown"
            contact_type = info.get("contact_type")
            is_repeater = bool(info.get("is_repeater"))
            node_type = self._coerce_contact_type(contact_type, is_repeater)

            out_path_len = -1
            flags = 0

            adv_name_bytes = node_name.encode("utf-8")[:32].ljust(32, b"\x00")
            last_seen = int(info.get("last_seen") or time.time())
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
        payload = bytes([PKT_TELEMETRY_RESPONSE]) + prefix + b""
        await self._send_packet(writer, payload)

    async def _handle_binary_req(self, payload: bytes, writer: asyncio.StreamWriter) -> None:
        if len(payload) < 34:
            await self._send_error(writer, 0)
            return

        dst = payload[1:33]
        req_type = payload[33]
        pubkey_prefix = dst[:6]

        tag = await self._send_msg_sent(writer)
        # Give client time to register pending binary request before responding
        await asyncio.sleep(0.2)

        if req_type == BINREQ_STATUS:
            status_bytes = self._build_status_payload()
            await self._send_binary_response(writer, tag, status_bytes)
            return

        if req_type == BINREQ_TELEMETRY:
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
            0,  # batt_milli_volts
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
