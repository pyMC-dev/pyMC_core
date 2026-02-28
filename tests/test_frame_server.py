"""Tests for CompanionFrameServer and advert push frame construction."""

import struct

from pymc_core.companion.constants import (
    MAX_PATH_SIZE,
    PUB_KEY_SIZE,
    PUSH_CODE_ADVERT,
    PUSH_CODE_NEW_ADVERT,
)
from pymc_core.companion.frame_server import _build_advert_push_frames
from pymc_core.companion.models import Contact


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
