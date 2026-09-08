# tests/test_h265.py
import pytest

from nooie_proxy.h265 import H265PayloadDescriptor, h265_depayload, nal_type, opens_a_group

# header NAL h.265 valido: TRAIL_R (tipo 1) -> byte0 0x02, byte1 0x01
TRAIL = bytes([0x02, 0x01]) + b"\x11\x22\x33"
# SPS (33) -> 0x42 01 ; PPS (34) -> 0x44 01 ; IDR_W_RADL (19) -> 0x26 01
SPS = bytes([0x42, 0x01]) + b"\xaa" * 6
IDR = bytes([0x26, 0x01]) + b"\xbb" * 8


def fu(real_type: int, start: bool, end: bool, payload: bytes) -> bytes:
    header = bytes([49 << 1, 0x01])  # FU indicator, layer 0 tid 1
    fu_header = (0x80 if start else 0) | (0x40 if end else 0) | real_type
    return header + bytes([fu_header]) + payload


def test_single_nal_gets_a_start_code():
    descriptor, data = H265PayloadDescriptor.parse(TRAIL)
    assert descriptor.first_fragment is True
    assert data == b"\x00\x00\x01" + TRAIL


def test_fu_first_fragment_rebuilds_the_nal_header():
    descriptor, data = H265PayloadDescriptor.parse(fu(19, True, False, b"AA"))
    assert descriptor.first_fragment is True
    # header reconstruido: tipo 19 -> byte0 0x26, byte1 preservado 0x01
    assert data == b"\x00\x00\x01" + bytes([0x26, 0x01]) + b"AA"


def test_fu_middle_and_last_are_bare_payload():
    for end in (False, True):
        descriptor, data = H265PayloadDescriptor.parse(fu(19, False, end, b"BB"))
        assert descriptor.first_fragment is False
        assert data == b"BB"


def test_fu_roundtrip_reassembles_the_original_nal():
    original = IDR + b"\xcc" * 100
    fragments = [
        fu(19, True, False, original[2:50]),
        fu(19, False, False, original[50:90]),
        fu(19, False, True, original[90:]),
    ]
    joined = b"".join(H265PayloadDescriptor.parse(f)[1] for f in fragments)
    assert joined == b"\x00\x00\x01" + original


def test_ap_splits_into_start_coded_units():
    ap = bytes([48 << 1, 0x01])
    for nal in (SPS, TRAIL):
        ap += len(nal).to_bytes(2, "big") + nal
    _, data = H265PayloadDescriptor.parse(ap)
    assert data == b"\x00\x00\x01" + SPS + b"\x00\x00\x01" + TRAIL


@pytest.mark.parametrize(
    "bad",
    [
        b"",                                  # vazio
        b"\x02",                              # curto demais
        bytes([49 << 1, 0x01]),               # FU sem FU header
        bytes([48 << 1, 0x01, 0x00]),         # AP com length truncado
        bytes([48 << 1, 0x01, 0x00, 0x10]) + b"xx",  # AP anuncia mais que tem
        bytes([50 << 1, 0x01]) + b"zz",       # tipo PACI (50) nao suportado
    ],
)
def test_invalid_input_raises_value_error_only(bad):
    with pytest.raises(ValueError):
        H265PayloadDescriptor.parse(bad)


def test_adversarial_bytes_never_raise_anything_else():
    import random
    rng = random.Random(1234)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
        try:
            H265PayloadDescriptor.parse(blob)
        except ValueError:
            pass  # o unico contrato de erro


def test_depayload_helper():
    assert h265_depayload(TRAIL) == b"\x00\x00\x01" + TRAIL


def test_nal_type():
    assert nal_type(0x26) == 19
    assert nal_type(0x42) == 33


def test_opens_a_group():
    au_idr = b"\x00\x00\x01" + SPS + b"\x00\x00\x01" + IDR
    au_trail = b"\x00\x00\x01" + TRAIL
    assert opens_a_group(au_idr) is True
    assert opens_a_group(au_trail) is False
    assert opens_a_group(b"") is False
