"""Parse binary response payloads by request type (BinaryReqType)."""

from __future__ import annotations

import logging
from typing import Optional

from .constants import BinaryReqType

logger = logging.getLogger(__name__)


def parse_binary_response(
    request_type: int,
    data: bytes,
    pubkey_prefix: str = "",
    context: Optional[dict] = None,
) -> Optional[dict]:
    """Parse response_data by request_type. Returns dict or None."""
    if request_type == BinaryReqType.STATUS and len(data) >= 52:
        return _parse_status(data, pubkey_prefix=pubkey_prefix or None)
    if request_type == BinaryReqType.TELEMETRY and len(data) >= 0:
        return _parse_telemetry(data)
    if request_type == BinaryReqType.MMA and len(data) >= 4:
        return _parse_mma(data[4:])  # skip 4-byte header
    if request_type == BinaryReqType.ACL:
        return _parse_acl(data)
    if request_type == BinaryReqType.NEIGHBOURS:
        return _parse_neighbours(data, context or {})
    if request_type == BinaryReqType.OWNER_INFO and len(data) >= 4:
        return _parse_owner_info(data)
    return {"raw_hex": data.hex(), "request_type": request_type}


def _parse_status(data: bytes, pubkey_prefix: Optional[str] = None, offset: int = 0) -> dict:
    """Parse status response (52 bytes)."""
    res = {}
    if pubkey_prefix is None and len(data) >= 8:
        res["pubkey_pre"] = data[2:8].hex()
        offset = 8
    else:
        res["pubkey_pre"] = pubkey_prefix or ""
    res["bat"] = int.from_bytes(data[offset : offset + 2], byteorder="little")
    res["tx_queue_len"] = int.from_bytes(data[offset + 2 : offset + 4], byteorder="little")
    res["noise_floor"] = int.from_bytes(
        data[offset + 4 : offset + 6], byteorder="little", signed=True
    )
    res["last_rssi"] = int.from_bytes(
        data[offset + 6 : offset + 8], byteorder="little", signed=True
    )
    res["nb_recv"] = int.from_bytes(data[offset + 8 : offset + 12], byteorder="little")
    res["nb_sent"] = int.from_bytes(data[offset + 12 : offset + 16], byteorder="little")
    res["airtime"] = int.from_bytes(data[offset + 16 : offset + 20], byteorder="little")
    res["uptime"] = int.from_bytes(data[offset + 20 : offset + 24], byteorder="little")
    res["sent_flood"] = int.from_bytes(data[offset + 24 : offset + 28], byteorder="little")
    res["sent_direct"] = int.from_bytes(data[offset + 28 : offset + 32], byteorder="little")
    res["recv_flood"] = int.from_bytes(data[offset + 32 : offset + 36], byteorder="little")
    res["recv_direct"] = int.from_bytes(data[offset + 36 : offset + 40], byteorder="little")
    res["full_evts"] = int.from_bytes(data[offset + 40 : offset + 42], byteorder="little")
    res["last_snr"] = (
        int.from_bytes(data[offset + 42 : offset + 44], byteorder="little", signed=True) / 4
    )
    res["direct_dups"] = int.from_bytes(data[offset + 44 : offset + 46], byteorder="little")
    res["flood_dups"] = int.from_bytes(data[offset + 46 : offset + 48], byteorder="little")
    res["rx_airtime"] = int.from_bytes(data[offset + 48 : offset + 52], byteorder="little")
    return res


def _parse_telemetry(data: bytes) -> dict:
    """Telemetry: Cayenne LPP or raw. Dict has raw_hex; optional LPP if cayennelpp available."""
    out: dict = {"raw_hex": data.hex()}
    try:
        from cayennelpp import LppFrame

        frame = LppFrame.from_bytes(data)
        out["lpp"] = [
            {"channel": d.channel, "type": d.type_id, "value": d.data} for d in frame.data
        ]
    except Exception:
        logger.debug("Optional LPP parse failed for telemetry", exc_info=True)
    return out


def _parse_mma(data: bytes) -> dict:
    """MMA: LPP min/max/avg or raw."""
    out: dict = {"raw_hex": data.hex()}
    try:
        from cayennelpp import LppFrame

        frame = LppFrame.from_bytes(data)
        out["mma"] = [{"channel": d.channel, "type": d.type_id, "data": d.data} for d in frame.data]
    except Exception:
        logger.debug("Optional LPP parse failed for MMA", exc_info=True)
    return out


def _parse_owner_info(data: bytes) -> dict:
    """Parse GET_OWNER_INFO response: tag(4) + 'version\\nname\\nowner' (variable)."""
    try:
        text = data[4:].decode("utf-8", errors="replace").strip()
        parts = text.split("\n", 2)
        return {
            "tag": int.from_bytes(data[:4], "little"),
            "version": parts[0] if len(parts) > 0 else "",
            "node_name": parts[1] if len(parts) > 1 else "",
            "owner_info": parts[2] if len(parts) > 2 else "",
            "raw_text": text,
        }
    except Exception:
        logger.debug("Owner info parse failed, returning fallback", exc_info=True)
        return {"raw_hex": data.hex(), "request_type": BinaryReqType.OWNER_INFO}


def _parse_acl(buf: bytes) -> dict:
    """ACL: 7-byte entries (key 6 + perm 1)."""
    res = []
    i = 0
    while i + 7 <= len(buf):
        key = buf[i : i + 6].hex()
        perm = buf[i + 6]
        if key != "000000000000":
            res.append({"key": key, "perm": perm})
        i += 7
    return {"acl": res}


def _parse_neighbours(data: bytes, context: dict) -> dict:
    """Neighbours: count(2) + results_count(2) + entries (pubkey_prefix + secs_ago(4) + snr(1))."""
    if len(data) < 4:
        return {"raw_hex": data.hex()}
    pk_plen = context.get("pubkey_prefix_length", 6)
    neighbours_count = int.from_bytes(data[0:2], "little", signed=True)
    results_count = int.from_bytes(data[2:4], "little", signed=True)
    neighbours_list = []
    i = 4
    for _ in range(results_count):
        if i + pk_plen + 4 + 1 > len(data):
            break
        pubkey = data[i : i + pk_plen].hex()
        i += pk_plen
        secs_ago = int.from_bytes(data[i : i + 4], "little", signed=True)
        i += 4
        snr = int.from_bytes(data[i : i + 1], "little", signed=True) / 4
        i += 1
        neighbours_list.append({"pubkey": pubkey, "secs_ago": secs_ago, "snr": snr})
    return {
        "neighbours_count": neighbours_count,
        "results_count": results_count,
        "neighbours": neighbours_list,
    }
