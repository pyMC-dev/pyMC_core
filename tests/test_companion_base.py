"""Tests for companion base: ResponseWaiter, adv_type_to_flags, and base API via CompanionRadio."""

import pytest

from pymc_core.companion.companion_base import ResponseWaiter, adv_type_to_flags
from pymc_core.companion.constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
)
from pymc_core.protocol.constants import (
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
)


# ---------------------------------------------------------------------------
# ResponseWaiter
# ---------------------------------------------------------------------------


class TestResponseWaiter:
    def test_initial_state(self):
        w = ResponseWaiter()
        assert w.data["success"] is False
        assert w.data["text"] is None
        assert w.data["parsed"] == {}

    def test_callback_sets_data_and_event(self):
        w = ResponseWaiter()
        w.callback(True, "hello", {"k": "v"})
        assert w.data["success"] is True
        assert w.data["text"] == "hello"
        assert w.data["parsed"] == {"k": "v"}
        assert w.event.is_set()

    @pytest.mark.asyncio
    async def test_wait_returns_after_callback(self):
        w = ResponseWaiter()
        w.callback(True, "done", {"x": 1})
        result = await w.wait(timeout=1.0)
        assert result["success"] is True
        assert result["text"] == "done"
        assert result["parsed"] == {"x": 1}
        assert "timeout" not in result

    @pytest.mark.asyncio
    async def test_wait_timeout(self):
        w = ResponseWaiter()
        result = await w.wait(timeout=0.05)
        assert result["timeout"] is True
        assert result["success"] is False


# ---------------------------------------------------------------------------
# adv_type_to_flags
# ---------------------------------------------------------------------------


class TestAdvTypeToFlags:
    def test_chat(self):
        assert adv_type_to_flags(ADV_TYPE_CHAT) == ADVERT_FLAG_IS_CHAT_NODE

    def test_repeater(self):
        assert adv_type_to_flags(ADV_TYPE_REPEATER) == ADVERT_FLAG_IS_REPEATER

    def test_room(self):
        assert adv_type_to_flags(ADV_TYPE_ROOM) == ADVERT_FLAG_IS_ROOM_SERVER

    def test_sensor(self):
        assert adv_type_to_flags(ADV_TYPE_SENSOR) == ADVERT_FLAG_IS_SENSOR

    def test_unknown_defaults_to_chat(self):
        assert adv_type_to_flags(99) == ADVERT_FLAG_IS_CHAT_NODE
        assert adv_type_to_flags(0) == ADVERT_FLAG_IS_CHAT_NODE
