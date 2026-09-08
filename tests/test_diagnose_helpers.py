import collections
import json
from pathlib import Path

from nooie_proxy.diagnose import count_nals, redact_answer

ANSWER = "00\r\n" + Path("tests/fixtures/compact_answer.json").read_text().strip()


def test_redacts_session_secrets():
    redacted = redact_answer(ANSWER)
    assert "NOT-A-REAL-ICE-PASSWORD" not in redacted
    payload = json.loads(redacted[4:])
    assert payload["com"]["p"] == "REDACTED"
    assert payload["com"]["u"] == "REDACTED"
    assert payload["com"]["ft"] == "REDACTED"
    # o resto sobrevive intacto (pt e o candidato lan sao o ponto do relatorio)
    assert payload["video"]["pt"] == 0
    assert "192.168.1.18" in payload["com"]["ic"]


def test_redact_passes_non_compact_input_through():
    assert redact_answer("v=0\r\nplain sdp") == "v=0\r\nplain sdp"
    assert redact_answer("00\r\n{broken") == "00\r\n{broken"


def test_count_nals_dual_parse():
    counters = {"h264": collections.Counter(), "h265": collections.Counter()}
    # au h265 real-shaped: sps(0x42 01) + idr(0x26 01)
    au = b"\x00\x00\x01\x42\x01\xaa" + b"\x00\x00\x01\x26\x01\xbb"
    count_nals(counters, au)
    assert counters["h265"][33] == 1 and counters["h265"][19] == 1
    # os mesmos bytes lidos como h264 (o modo de conferir um rotulo errado)
    assert counters["h264"][0x42 & 0x1F] == 1 and counters["h264"][0x26 & 0x1F] == 1
