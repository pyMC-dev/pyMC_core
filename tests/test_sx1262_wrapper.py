import pytest

from pymc_core.hardware.sx1262_wrapper import SX1262Radio
from pymc_core.hardware.signal_utils import snr_register_to_db


def test_positive_snr_conversion():
    assert snr_register_to_db(0x10) == pytest.approx(4.0)


def test_negative_snr_conversion():
    assert snr_register_to_db(0xF0) == pytest.approx(-4.0)


def test_fractional_negative_snr_conversion():
    assert snr_register_to_db(0xEE) == pytest.approx(-4.5)


def test_snr_register_bounds():
    assert snr_register_to_db(0x7F) == pytest.approx(31.75)
    assert snr_register_to_db(0x80) == pytest.approx(-32.0)


def test_none_defaults_to_zero():
    assert snr_register_to_db(None) == 0.0


def test_16bit_positive_conversion():
    assert snr_register_to_db(0x0014, bits=16) == pytest.approx(5.0)


def test_16bit_negative_conversion():
    assert snr_register_to_db(0xFFF0, bits=16) == pytest.approx(-4.0)


def test_invalid_bit_width_raises():
    with pytest.raises(ValueError):
        snr_register_to_db(0x00, bits=0)


def test_normalize_en_pins_uses_single_pin_when_list_missing():
    assert SX1262Radio._normalize_en_pins(en_pin=26, en_pins=None) == [26]


def test_normalize_en_pins_prefers_list_and_filters_disabled_entries():
    assert SX1262Radio._normalize_en_pins(en_pin=26, en_pins=[26, -1, 23, 26]) == [26, 23]
