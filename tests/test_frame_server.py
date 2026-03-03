"""Tests for CompanionFrameServer and advert push frame construction."""

import asyncio
import struct
from unittest.mock import AsyncMock, Mock

import pytest

from pymc_core.companion.constants import (
    ERR_CODE_TABLE_FULL,
    ERR_CODE_UNSUPPORTED_CMD,
    MAX_PATH_SIZE,
    PUB_KEY_SIZE,
    PUSH_CODE_ADVERT,
    PUSH_CODE_NEW_ADVERT,
)
from pymc_core.companion.frame_server import CompanionFrameServer, _build_advert_push_frames
from pymc_core.companion.models import Contact, SentResult


def test_build_advert_push_frames_short_only_when_no_name():
    """Contact with empty name yields only short frame; full is None."""
    pubkey = bytes(range(32))
    contact = Contact(public_key=pubkey, name="")
    short, full = _build_advert_push_frames(contact)
    assert full is None
    assert len(short) == 1 + PUB_KEY_SIZE
    assert short[0] == PUSH_CODE_ADVERT
    assert short[1:33] == pubkey


def test_build_advert_push_frames_short_and_full_when_has_name():
    """Contact with name yields short frame and full NEW_ADVERT frame."""
    pubkey = bytes(range(32))
    contact = Contact(
        public_key=pubkey,
        name="Alice",
        adv_type=1,
        flags=2,
        out_path_len=0,
        out_path=b"",
        last_advert_timestamp=1000,
        lastmod=2000,
        gps_lat=52.5,
        gps_lon=-1.7,
    )
    short, full = _build_advert_push_frames(contact)
    assert full is not None
    # Short frame
    assert len(short) == 1 + PUB_KEY_SIZE
    assert short[0] == PUSH_CODE_ADVERT
    assert short[1:33] == pubkey
    # Full frame: code(1) + pubkey(32) + adv_type,flags,opl(3) + path(64) + name(32)
    # + last_advert(4) + gps_lat(4) + gps_lon(4) + lastmod(4)
    expected_full_len = 1 + 32 + 3 + MAX_PATH_SIZE + 32 + 4 + 4 + 4 + 4
    assert len(full) == expected_full_len
    assert full[0] == PUSH_CODE_NEW_ADVERT
    assert full[1:33] == pubkey
    assert full[33] == 1  # adv_type
    assert full[34] == 2  # flags
    assert full[35] == 0  # opl_byte (out_path_len 0)
    out_path = full[36 : 36 + MAX_PATH_SIZE]
    assert out_path == b"\x00" * MAX_PATH_SIZE
    name_b = full[36 + MAX_PATH_SIZE : 36 + MAX_PATH_SIZE + 32]
    assert name_b.startswith(b"Alice")
    assert name_b.rstrip(b"\x00") == b"Alice"
    offset = 36 + MAX_PATH_SIZE + 32
    assert struct.unpack("<I", full[offset : offset + 4])[0] == 1000
    assert struct.unpack("<i", full[offset + 4 : offset + 8])[0] == int(52.5 * 1e6)
    assert struct.unpack("<i", full[offset + 8 : offset + 12])[0] == int(-1.7 * 1e6)
    assert struct.unpack("<I", full[offset + 12 : offset + 16])[0] == 2000


def test_build_advert_push_frames_pubkey_padded_if_short():
    """Public key shorter than 32 bytes is zero-padded."""
    short_key = bytes([0xAB] * 16)
    contact = Contact(public_key=short_key, name="")
    short, full = _build_advert_push_frames(contact)
    assert short[1:17] == short_key
    assert short[17:33] == b"\x00" * 16


def test_build_advert_push_frames_out_path_len_negative_becomes_0xff():
    """out_path_len < 0 encodes as opl_byte 0xFF."""
    pubkey = bytes(range(32))
    contact = Contact(
        public_key=pubkey,
        name="Bob",
        out_path_len=-1,
    )
    _, full = _build_advert_push_frames(contact)
    assert full is not None
    assert full[35] == 0xFF


def test_build_advert_push_frames_name_truncated_to_32_bytes():
    """Long name is truncated to 32 bytes in full frame."""
    pubkey = bytes(range(32))
    long_name = "A" * 64
    contact = Contact(public_key=pubkey, name=long_name)
    _, full = _build_advert_push_frames(contact)
    assert full is not None
    name_slice = full[36 + MAX_PATH_SIZE : 36 + MAX_PATH_SIZE + 32]
    assert len(name_slice) == 32
    assert name_slice == b"A" * 32


class _MockBridgeSendRawDirect:
    """Minimal bridge for CMD_SEND_RAW_DATA tests."""

    def __init__(self, success: bool = True):
        self.calls = []
        self._success = success

    async def send_raw_data_direct(self, path: bytes, payload: bytes):
        self.calls.append((path, payload))
        return SentResult(success=self._success)


@pytest.mark.asyncio
async def test_cmd_send_raw_data_valid_writes_ok():
    """Valid CMD_SEND_RAW_DATA -> _write_ok."""
    bridge = _MockBridgeSendRawDirect(success=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    data = bytes([1, 0x42]) + b"\x01\x02\x03\x04"
    await server._cmd_send_raw_data(data)
    assert bridge.calls == [(b"\x42", b"\x01\x02\x03\x04")]
    server._write_ok.assert_called_once()
    server._write_err.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_invalid_len_writes_unsupported():
    """Invalid CMD_SEND_RAW_DATA len < 6 -> ERR_CODE_UNSUPPORTED_CMD."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_send_raw_data(b"\x00\x00\x00")
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_send_failure_writes_table_full():
    """send_raw_data_direct returns False -> ERR_CODE_TABLE_FULL."""
    bridge = _MockBridgeSendRawDirect(success=False)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    data = bytes([1, 0x42]) + b"\x01\x02\x03\x04"
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 1
    server._write_err.assert_called_once_with(ERR_CODE_TABLE_FULL)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_push_trace_data_enqueues_frame():
    """push_trace_data enqueues a correctly formatted trace frame."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    await server.push_trace_data(
        path_len=1,
        flags=0,
        tag=1,
        auth_code=0,
        path_hashes=b"\x00",
        path_snrs=b"\x00",
        final_snr_byte=0,
    )
    assert not server._write_queue.empty()
    frame = server._write_queue.get_nowait()
    # Frame format: FRAME_OUTBOUND_PREFIX + 2-byte LE length + payload
    assert frame[0] == 0x3E  # FRAME_OUTBOUND_PREFIX
    _ = struct.unpack("<H", frame[1:3])[0]  # payload length
    assert frame[3] == 0x89  # PUSH_CODE_TRACE_DATA


@pytest.mark.asyncio
async def test_push_rx_raw_enqueues_frame():
    """push_rx_raw enqueues a correctly formatted RX raw frame."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    server.push_rx_raw(snr=-5.0, rssi=-100, raw=b"abc")
    assert not server._write_queue.empty()
    frame = server._write_queue.get_nowait()
    assert frame[0] == 0x3E  # FRAME_OUTBOUND_PREFIX
    assert frame[3] == 0x88  # PUSH_CODE_LOG_RX_DATA


@pytest.mark.asyncio
async def test_push_burst_all_enqueued():
    """Multiple rapid pushes all land in the queue."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    for i in range(5):
        server.push_rx_raw(snr=0.0, rssi=-80, raw=bytes([i]))
    assert server._write_queue.qsize() == 5


def test_push_rx_raw_sync_enqueues_immediately():
    """Sync push_rx_raw() enqueues immediately with no event loop scheduling."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    server.push_rx_raw(snr=-5.0, rssi=-100, raw=b"abc")
    assert server._write_queue.qsize() == 1


@pytest.mark.asyncio
async def test_writer_loop_writes_and_drains():
    """_writer_loop writes enqueued frames and drains."""
    bridge = Mock()
    bridge.get_time = Mock(return_value=12345)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    writer = Mock()
    writer.write = Mock()
    writer.drain = AsyncMock()
    writer.is_closing = Mock(return_value=False)
    writer.close = Mock()

    # Enqueue a frame only; schedule sentinel after a yield so the queue
    # appears empty when _writer_loop checks after writing the frame,
    # which triggers the drain path.
    server._enqueue_frame(bytes([0x01]))

    async def _send_sentinel():
        await asyncio.sleep(0)  # Yield so writer loop processes frame first
        server._write_queue.put_nowait(None)

    asyncio.create_task(_send_sentinel())

    await server._writer_loop(writer)

    writer.write.assert_called_once()
    writer.drain.assert_awaited_once()
